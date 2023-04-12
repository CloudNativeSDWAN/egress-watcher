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
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/controllers"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage"
	vmanagego "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/homedir"
)

type kubeConfigOptions struct {
	path string
	// TODO: on future maybe we could also support contexts.
}

type Options struct {
	ServiceEntryController  *controllers.ServiceEntryOptions  `yaml:"serviceEntry,omitempty"`
	NetworkPolicyController *controllers.NetworkPolicyOptions `yaml:"networkPolicy,omitempty"`
	Sdwan                   *sdwan.Options                    `yaml:"sdwan,omitempty"`
	Verbosity               int                               `yaml:"verbosity"`
	PrettyLogs              bool                              `yaml:"prettyLogs"`
}

func getRunCommand() *cobra.Command {
	insideCluster := false
	if _, err := rest.InClusterConfig(); err == nil {
		insideCluster = true
	}

	kopts := &kubeConfigOptions{}
	waitingWindow := sdwan.DefaultWaitingWindow
	flagOpts := &Options{
		ServiceEntryController:  &controllers.ServiceEntryOptions{},
		NetworkPolicyController: &controllers.NetworkPolicyOptions{},
		Sdwan: &sdwan.Options{
			Authentication: &sdwan.Authentication{},
			WaitingWindow:  &waitingWindow,
		},
	}
	fileOpts := &Options{
		ServiceEntryController:  &controllers.ServiceEntryOptions{},
		NetworkPolicyController: &controllers.NetworkPolicyOptions{},
		// We don't support having authentication in a file because that's
		// sensitive information.
		Sdwan: &sdwan.Options{
			Authentication: &sdwan.Authentication{},
			WaitingWindow:  &waitingWindow,
		},
	}
	var (
		fileSettingsPath string
		chosenSdWan      string
	)

	// TODO: remove fmt with zerolog in future versions.
	cmd := &cobra.Command{
		Use:   "run [ARGUMENT] [OPTIONS]",
		Short: "Run locally.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				fmt.Println(`no sdwan controller defined. Please include -h for a list of supported SD-WAN controllers.`)
				return fmt.Errorf("no sdwan controller provided")
			}

			if len(args) > 1 {
				fmt.Println(`WARNING: this command accepts only one argument: Only the first valid argument will be retained.`)
			}

			for _, arg := range args {
				if strings.EqualFold(arg, "vmanage") ||
					strings.EqualFold(arg, "with-vmanage") {
					chosenSdWan = "vmanage"
					return nil
				}
			}

			return fmt.Errorf(`no valid SD-WAN controllers provided as argument`)
		},
		Long: `Run locally and watch for ServiceEntry objects in
Kubernetes and send data to an SD-WAN controller for processing.

An SD-WAN controller must be provided as first argument after the run command.
The following controllers are supported:

* vManage
  You can run the program against vManage by using "vmanage" (or "with-vmanage") as
  first argument.`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if insideCluster && kopts.path != "" {
				return fmt.Errorf("using a different kubeconfig when running " +
					"inside the cluster is not suppported")
			}

			if fileSettingsPath != "" {
				f, err := getSettingsFromFile(fileSettingsPath)
				if err != nil {
					return err
				}
				fileOpts = f
			}

			if flagOpts.Sdwan.Authentication.Username == "" ||
				flagOpts.Sdwan.Authentication.Password == "" {
				return fmt.Errorf("no username or password provided")
			}
			fileOpts.Sdwan.Authentication = flagOpts.Sdwan.Authentication

			// -- SD-WAN options
			if fileOpts.Sdwan != nil {
				fv := fileOpts.Sdwan

				if fv.BaseURL == "" && flagOpts.Sdwan.BaseURL == "" {
					return fmt.Errorf("no base url provided")
				}

				if flagOpts.Sdwan.BaseURL != "" {
					fileOpts.Sdwan.BaseURL = flagOpts.Sdwan.BaseURL
				}

				if cmd.Flag("waiting-window").Changed {
					fileOpts.Sdwan.WaitingWindow = flagOpts.Sdwan.WaitingWindow
				}

				if cmd.Flag("sdwan.insecure").Changed {
					fileOpts.Sdwan.Insecure = flagOpts.Sdwan.Insecure
				}
			}

			if _, err := url.Parse(fileOpts.Sdwan.BaseURL); err != nil {
				return fmt.Errorf("invalid base url provided: %w", err)
			}

			if *fileOpts.Sdwan.WaitingWindow < 0 {
				return fmt.Errorf("invalid waiting window provided")
			}

			if cmd.Flag("watch-all-service-entries").Changed {
				fileOpts.ServiceEntryController.WatchAllServiceEntries = flagOpts.ServiceEntryController.WatchAllServiceEntries
			}

			if cmd.Flag("pretty-logs").Changed {
				fileOpts.PrettyLogs = flagOpts.PrettyLogs
			}

			if cmd.Flag("verbosity").Changed {
				fileOpts.Verbosity = flagOpts.Verbosity
			}

			if cmd.Flag("sdwan.enable").Changed {
				fileOpts.Sdwan.Enable = flagOpts.Sdwan.Enable
			}

			if cmd.Flag("watch-all-network-policies").Changed {
				fileOpts.NetworkPolicyController.WatchAllNetworkPolicies = flagOpts.NetworkPolicyController.WatchAllNetworkPolicies
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch chosenSdWan {
			case "vmanage":
				return runWithVmanage(kopts, fileOpts)
			default:
				return fmt.Errorf("no sdwan controller provided")
			}
		},
		Example: "run --kubeconfig /my/kubeconf/conf --watch-all-service-entries",
	}

	// Flags
	cmd.Flags().StringVar(&kopts.path, "kubeconfig", func() string {
		if home := homedir.HomeDir(); len(home) > 0 && !insideCluster {
			return path.Join(home, ".kube", "config")
		}

		return ""
	}(), "path to the kubeconfig file to use. "+
		"This is only used when running outside of the cluster.")
	cmd.Flags().BoolVarP(&flagOpts.ServiceEntryController.WatchAllServiceEntries,
		"watch-all-service-entries", "w", false,
		"whether to watch all service entries by default.")
	cmd.Flags().BoolVarP(&flagOpts.NetworkPolicyController.WatchAllNetworkPolicies,
		"watch-all-network-policies", "n", false,
		"whether to watch all service entries by default.")
	cmd.Flags().StringVarP(&flagOpts.Sdwan.BaseURL, "sdwan.base-url", "a", "",
		"the base url where to send data.")
	cmd.Flags().StringVar(&fileSettingsPath, "settings-file", "",
		"path to the file containing settings")
	cmd.Flags().StringVar(&flagOpts.Sdwan.Authentication.Username,
		"sdwan.username", "", "username to authenticate as.")
	cmd.Flags().StringVar(&flagOpts.Sdwan.Authentication.Password,
		"sdwan.password", "", "password for authenticating.")
	cmd.Flags().BoolVar(&flagOpts.Sdwan.Insecure,
		"sdwan.insecure", false,
		"whether to connect to the SD-WAN ignoring self signed certificates.")
	cmd.Flags().IntVar(&flagOpts.Verbosity,
		"verbosity", 1,
		"verbosity level, from 0 to 3.")
	cmd.Flags().BoolVar(&flagOpts.PrettyLogs,
		"pretty-logs", false,
		"whether to log data in a slower but human readable format.")
	cmd.Flags().DurationVar(flagOpts.Sdwan.WaitingWindow,
		"waiting-window", sdwan.DefaultWaitingWindow,
		"the duration of the waiting mode. Set this to 0 to disable it entirely.")
	cmd.Flags().BoolVarP(&flagOpts.Sdwan.Enable,
		"sdwan.enable", "e", false,
		"whether to also apply configuration/policies.")

	return cmd
}

func runWithVmanage(kopts *kubeConfigOptions, opts *Options) error {
	// -- Init logs
	log := initLogger(opts)
	log.Info().Msg("starting...")

	// -- Init vManage stuff
	opHandler, err := func() (*vmanage.OperationsHandler, error) {
		ctx, canc := context.WithTimeout(context.Background(), 10*time.Second)
		defer canc()

		vOpts := []vmanagego.ClientOption{}
		if opts.Sdwan.Insecure {
			vOpts = append(vOpts, vmanagego.WithSkipInsecure())
		}

		log.Info().Msg("getting client for vManage...")
		vclient, err := vmanagego.NewClient(ctx, opts.Sdwan.BaseURL,
			opts.Sdwan.Authentication.Username,
			opts.Sdwan.Authentication.Password,
			vOpts...)
		if err != nil {
			return nil, fmt.Errorf("cannot get vManage client: %w", err)
		}
		log.Info().Msg("successfully retrieved client for vManage")

		return vmanage.NewOperationsHandler(vclient, *opts.Sdwan, log)
	}()
	if err != nil {
		return fmt.Errorf("cannot start operations handler for "+
			"vManager: %w", err)
	}

	// -- Init controllers data
	opsChan := make(chan *sdwan.Operation, 100)
	mgr, err := initControllers(opsChan, kopts, opts, log)
	if err != nil {
		return err
	}

	// -- Init stop channels
	ctx, canc := context.WithCancel(context.Background())
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	// -- Do the actual work
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := opHandler.WatchForOperations(ctx, opsChan); err != nil {
			if !errors.Is(err, context.Canceled) {
				close(stopChan)
				log.Err(err).Msg("error while watching for operations")
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info().Str("worker", "Controllers Manager").
			Msg("starting controllers manager...")

		if err := mgr.Start(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Err(err).Msg("could not start manager")
				close(stopChan)
			}
		}
	}()

	log.Info().Msg("working....")

	// -- Graceful shutdown
	<-stopChan
	fmt.Println()
	log.Info().Msg("waiting for all workers to terminate...")

	canc()
	wg.Wait()
	log.Info().Msg("done. Good bye!")

	return nil
}
