// Copyright (c) 2022 Cisco Systems, Inc. and its affiliates
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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/controllers"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	usernamespace        = "egress-watcher"
	usersettingsfilename = "settings.yaml"
	defaultImage         = "ghcr.io/cloudnativesdwan/egress-watcher:v0.3.0"
	defaultWaitingWindow = 30 * time.Second
)

var log zerolog.Logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()

func getInstallCommand() *cobra.Command {
	var (
		interactive bool
		user        string
		pass        string
		baseurl     string
	)

	cmd := &cobra.Command{
		Use:   "install [OPTIONS]",
		Short: `Install the egress watcher in Kubernetes.This is an experimental feature.`,
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

			a := 30 * time.Second
			opt := Options{
				ServiceEntryController: &controllers.ServiceEntryOptions{
					WatchAllServiceEntries: false,
				},

				Sdwan: &sdwan.Options{
					WaitingWindow: &a,
					BaseURL:       baseurl,
					Authentication: &sdwan.Authentication{
						Username: user,
						Password: pass,
					},
				},
			}
			if interactive {
				return installInteractivelyToK8s(clientset)
			} else {

				return install(clientset, defaultImage, opt)
			}

		},
		Example: "install -i",
	}

	// Flags
	cmd.Flags().BoolVarP(&interactive,
		"interactive", "i", false,
		"whether to install interactively.")
	cmd.Flags().StringVar(&user,
		"username", "",
		"the username for sdwan.")
	cmd.Flags().StringVar(&pass,
		"password", "",
		"the password for sdwan.")
	cmd.Flags().StringVar(&baseurl,
		"base-url", "",
		"the base url for sdwan.")

	return cmd
}

func install(clientset *kubernetes.Clientset, docker_image string, opt Options) error {

	type deleteComponentStep int

	const (
		clusterRoleStep deleteComponentStep = iota
		clusterRoleBindingStep
		namespaceStep
	)

	logLevels := [3]zerolog.Level{
		zerolog.DebugLevel,
		zerolog.InfoLevel,
		zerolog.ErrorLevel,
	}

	if opt.PrettyLogs {
		log = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	} else {
		log = zerolog.New(os.Stderr).With().Timestamp().Logger()
	}
	log = log.Level(logLevels[opt.Verbosity])
	log.Info().Msg("Starting...")

	log.Info().Msg("Attempting clusterrole creation")
	if err := createClusterRole(clientset, usernamespace, "egress-watcher-role"); err != nil {
		return err
	}
	log.Info().Msg("ClusterRole created successfully")

	log.Info().Msg("Attempting clusterrolebinding creation")
	if err := createClusterRoleBinding(clientset, usernamespace, "egress-watcher-role-binding"); err != nil {
		outputerr := cleanUP(clientset, int(clusterRoleStep))
		if outputerr != nil {
			log.Info().Msg("Could not delete a created resource")
		}
		return err
	}
	log.Info().Msg("ClusterRoleBinding created successfully")

	log.Info().Msg("Attempting namespace creation")
	if err := createNamespace(clientset, usernamespace); err != nil {
		outputerr := cleanUP(clientset, int(clusterRoleBindingStep))
		if outputerr != nil {
			log.Err(outputerr).Msg("Could not delete a created resource")
		}
		return err
	}
	log.Info().Msg("Namespace created successfully")

	log.Info().Msg("Attempting secret creation")
	if err := createSecret(clientset, usernamespace, "vmanage-credentials", opt); err != nil {
		outputerr := cleanUP(clientset, int(namespaceStep))
		if outputerr != nil {
			log.Info().Msg("Could not delete a created resources")
		}
		return err
	}
	log.Info().Msg("Secret created successfully")

	log.Info().Msg("Attempting configmap creation ")
	if err := createConfigMap(clientset, opt, usernamespace, "egress-watcher-settings"); err != nil {
		outputerr := cleanUP(clientset, int(namespaceStep))
		if outputerr != nil {
			log.Info().Msg("Could not delete a created resource")
		}
		return err
	}
	log.Info().Msg("ConfigMap created successfully")

	log.Info().Msg("Attempting serviceaccount creation")
	if err := createServiceAccount(clientset, usernamespace, "egress-watcher-service-account"); err != nil {
		outputerr := cleanUP(clientset, int(namespaceStep))
		if outputerr != nil {
			log.Info().Msg("Could not delete a created resource")
		}
		return err
	}
	log.Info().Msg("ServiceAccount created successfully")

	log.Info().Msg("Attempting Deployment creation")
	if err := createDeployment(clientset, "new-deployment", usernamespace, docker_image); err != nil {
		outputerr := cleanUP(clientset, int(namespaceStep))
		if outputerr != nil {
			log.Info().Msg("Could not delete a created resource")
		}
		return err
	}
	log.Info().Msg("Deployment created successfully")

	return nil
}

func installInteractivelyToK8s(clientset *kubernetes.Clientset) error {
	//take various inputs from user

	//Username
	var sdwan_username string
	for {
		fmt.Print("Please enter your SDWAN username: ")
		fmt.Scanln(&sdwan_username)
		if sdwan_username != "" {
			break
		}
		fmt.Println("username provided is invalid")
	}

	//Password
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

	//Baseurl
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

	//self signed certificate
	sdwan_insecure := false
selfSignedCertificate:
	for {
		fmt.Print("Do you want to accept self-signed certificates? [y/n] (default: n): ")

		var user_input string
		fmt.Scanln(&user_input)

		switch strings.ToLower(user_input) {
		case "y":
			sdwan_insecure = true
			break selfSignedCertificate
		case "", "n":
			break selfSignedCertificate

		}

	}

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

	// PrettyLogs
	sdwan_prettylogs := false
prettyLogsInput:
	for {
		fmt.Print("Do you need pretty logs? [y/n] (default: n): ")

		var user_input string
		fmt.Scanln(&user_input)

		switch strings.ToLower(user_input) {
		case "y":
			sdwan_prettylogs = true
			break prettyLogsInput
		case "", "n":
			break prettyLogsInput

		}
	}

	// Watch all services
	watchall_serviceentries := false
watchAllServicesInput:
	for {
		fmt.Print("Do you want to watch all ServiceEntry resources? [y/n] (default: n): ")

		var user_input string
		fmt.Scanln(&user_input)

		switch strings.ToLower(user_input) {
		case "y":
			watchall_serviceentries = true
			break watchAllServicesInput
		case "", "n":
			break watchAllServicesInput

		}
	}

	//docker image
	docker_image := defaultImage

	fmt.Printf("Enter docker image (default: %s): ", defaultImage)
	var user_input string
	fmt.Scanln(&user_input)
	if user_input != "" {
		docker_image = user_input
	}

	opt := Options{
		ServiceEntryController: &controllers.ServiceEntryOptions{
			WatchAllServiceEntries: watchall_serviceentries,
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

	return install(clientset, docker_image, opt)

}
