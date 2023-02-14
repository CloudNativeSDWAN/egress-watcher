// Copyright (c) 2022, 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/controllers"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/google/go-github/github"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	defaultNamespace             = "egress-watcher"
	defaultContainerRegistryRepo = "ghcr.io/cloudnativesdwan/egress-watcher"
	githubOrgName                = "CloudNativeSDWAN"
	githubRepoName               = "egress-watcher"
	defaultName                  = "egress-watcher"
	defaultWaitingWindow         = 30 * time.Second
)

func getInstallCommand() *cobra.Command {
	interactive := false
	waitingWindow := defaultWaitingWindow
	opts := Options{
		ServiceEntryController: &controllers.ServiceEntryOptions{
			WatchAllServiceEntries: false,
		},
		NetworkPolicyController: &controllers.NetworkPolicyOptions{
			WatchAllNetworkPolicies: false,
		},

		Sdwan: &sdwan.Options{
			WaitingWindow: &waitingWindow,
			BaseURL:       "",
			Authentication: &sdwan.Authentication{
				Username: "",
				Password: "",
			},
			Insecure: false,
		},
	}

	cmd := &cobra.Command{
		Use:   "install [OPTIONS]",
		Short: `Install the egress watcher in Kubernetes. This is an experimental feature.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			home := homedir.HomeDir()
			if home == "" {
				return fmt.Errorf("cannot get home directory")
			}

			kubeconfig := filepath.Join(home, ".kube", "config")

			// use the current context in clientset
			config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				panic(err.Error())
			}

			// create the clientset
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return fmt.Errorf("cannot get clientset: %w", err)
			}

			if interactive {
				return installInteractivelyToK8s(clientset)
			} else {

				return install(clientset, "", opts)
			}

		},
		Example: "install --username myself --password password " +
			"--base-url https://my-vmanage.com",
	}

	// Flags
	// We use the same flag names as the run command to be consistent.
	cmd.Flags().BoolVarP(&interactive,
		"interactive", "i", false,
		"whether to install interactively.")
	cmd.Flags().BoolVarP(&opts.ServiceEntryController.WatchAllServiceEntries,
		"watch-all-service-entries", "w", false,
		"whether to watch all service entries by default.")
	cmd.Flags().BoolVarP(&opts.NetworkPolicyController.WatchAllNetworkPolicies,
		"watch-all-network-policies", "n", false,
		"whether to watch all service entries by default.")
	cmd.Flags().StringVarP(&opts.Sdwan.BaseURL, "sdwan.base-url", "a", "",
		"the base url where to send data.")
	cmd.Flags().StringVar(&opts.Sdwan.Authentication.Username,
		"sdwan.username", "", "username to authenticate as.")
	cmd.Flags().StringVar(&opts.Sdwan.Authentication.Password,
		"sdwan.password", "", "password for authenticating.")
	cmd.Flags().BoolVar(&opts.Sdwan.Insecure,
		"sdwan.insecure", false,
		"whether to connect to the SD-WAN ignoring self signed certificates.")
	cmd.Flags().IntVar(&opts.Verbosity,
		"verbosity", 1,
		"verbosity level, from 0 to 2.")
	cmd.Flags().BoolVar(&opts.PrettyLogs,
		"pretty-logs", false,
		"whether to log data in a slower but human readable format.")
	cmd.Flags().DurationVar(opts.Sdwan.WaitingWindow,
		"waiting-window", sdwan.DefaultWaitingWindow,
		"the duration of the waiting mode. Set this to 0 to disable it entirely.")

	return cmd
}

func install(clientset *kubernetes.Clientset, containerImage string, opts Options) error {
	inst, err := newInstaller(clientset, defaultNamespace, defaultName)
	if err != nil {
		return err
	}

	if containerImage == "" {
		// Get the latest tag image. We could just use "latest", but we don't
		// like doing that as we prefer to have a clear idea of which version
		// is installed.
		latestOfficialTag, err := func() (string, error) {
			ctx, canc := context.WithTimeout(context.Background(), 30*time.Second)
			defer canc()

			client := github.NewClient(nil)
			rel, _, err := client.Repositories.GetLatestRelease(ctx, githubOrgName, githubRepoName)
			if err != nil {
				return "", err
			}

			return *rel.TagName, nil
		}()
		if err != nil {
			return fmt.Errorf("cannot get latest release: %w", err)
		}

		containerImage = fmt.Sprintf("%s:%s", defaultContainerRegistryRepo, latestOfficialTag)
	}

	fmt.Println("using", containerImage)

	return inst.install(context.Background(), containerImage, opts)
}

func installInteractivelyToK8s(clientset *kubernetes.Clientset) error {
	askYesNo := func() bool {
		// Utility function to ask for yes or no with no as default.
		for {
			var user_input string
			fmt.Scanln(&user_input)

			switch strings.ToLower(user_input) {
			case "y":
				return true
			case "", "n":
				return false
			}

			fmt.Printf("invalid input, please try again: [y/n] (default: n): ")
		}
	}

	// Username
	var sdwan_username string
	for {
		fmt.Print("Please enter your SDWAN username: ")
		fmt.Scanln(&sdwan_username)
		if sdwan_username != "" {
			break
		}
		fmt.Println("username provided is invalid")
	}

	// Password
	var sdwan_password string
	for {
		fmt.Print("Please enter your sdwan password (input will be hidden): ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		sdwan_password = string(bytePassword)
		if sdwan_password != "" {
			break
		}
		fmt.Println("password provided is invalid")
	}
	fmt.Println()

	// Base URL
	var sdwan_base_url string
	for {
		fmt.Print("Please enter your SDWAN base URL, e.g. https://example.com: ")
		fmt.Scanln(&sdwan_base_url)

		if _, err := url.ParseRequestURI(sdwan_base_url); err == nil {
			break
		}
		fmt.Println("Provided URL is not valid")
	}

	// Waiting time
	waittime := fmt.Sprint(defaultWaitingWindow)
	sdwan_waittime := defaultWaitingWindow
	var err error
	for {
		fmt.Printf("Please enter the waiting window time, e.g. 1m (default %s): ", defaultWaitingWindow)
		fmt.Scanln(&waittime)
		sdwan_waittime, err = time.ParseDuration(waittime)
		if err == nil && sdwan_waittime >= 0 {
			break
		}
		fmt.Println("Provided duration is invalid")
	}

	// Self-signed certificates
	fmt.Print("Do you want to accept self-signed certificates? [y/n] (default: n): ")
	sdwan_insecure := askYesNo()

	// Verbosity
	sdwan_verbosity := defaultVerbosity
	for {
		var inputVerbosity string
		fmt.Printf("Please enter the verbosity level 0,1,2 (default: %d): ", defaultVerbosity)
		fmt.Scanln(&inputVerbosity)

		if strings.Trim(inputVerbosity, " ") == "" {
			inputVerbosity = "1"
		}

		sdwan_verbosity, err = strconv.Atoi(inputVerbosity)
		if err == nil {
			if sdwan_verbosity < 0 || sdwan_verbosity > 2 {
				fmt.Println("incorrect verbosity level provided, using default")
				sdwan_verbosity = defaultVerbosity
			}
			break
		}
		fmt.Println("Provided invalid verbosity value")
	}

	// Pretty logs
	fmt.Print("Do you need human-readable logs? [y/n] (default: n): ")
	sdwan_prettylogs := askYesNo()

	// Watch all service entries
	fmt.Print("Do you want to watch all ServiceEntry resources? [y/n] (default: n): ")
	watchAllServiceEntries := askYesNo()

	// Watch all network policies
	fmt.Print("Do you want to watch all NetworkPolicy resources? [y/n] (default: n): ")
	watchAllNetPols := askYesNo()

	// Docker Image
	dockerImage := ""
	fmt.Printf("Enter docker image (press enter for latest official release): ")
	var user_input string
	fmt.Scanln(&user_input)

	opt := Options{
		ServiceEntryController: &controllers.ServiceEntryOptions{
			WatchAllServiceEntries: watchAllServiceEntries,
		},
		NetworkPolicyController: &controllers.NetworkPolicyOptions{
			WatchAllNetworkPolicies: watchAllNetPols,
		},

		Sdwan: &sdwan.Options{
			WaitingWindow: &sdwan_waittime,
			BaseURL:       sdwan_base_url,
			Insecure:      sdwan_insecure,
			Authentication: &sdwan.Authentication{
				Username: sdwan_username,
				Password: sdwan_password,
			},
		},
		PrettyLogs: sdwan_prettylogs,
		Verbosity:  sdwan_verbosity,
	}

	fmt.Println()
	return install(clientset, dockerImage, opt)
}
