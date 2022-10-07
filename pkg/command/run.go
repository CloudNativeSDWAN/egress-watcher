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
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/controllers"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/util/homedir"
)

const (
	defaultVerbosity int = 1
)

type kubeConfigOptions struct {
	path    string
	context string
}

type Options struct {
	ServiceEntryController *controllers.ServiceEntryOptions `yaml:"serviceEntry,omitempty"`
	Sdwan                  *sdwan.Options                   `yaml:"sdwan,omitempty"`
	Verbosity              int                              `yaml:"verbosity"`
	PrettyLogs             bool                             `yaml:"prettyLogs"`
}

func getRunCommand() *cobra.Command {
	kopts := &kubeConfigOptions{}
	waitingWindow := sdwan.DefaultWaitingWindow
	flagOpts := &Options{
		ServiceEntryController: &controllers.ServiceEntryOptions{},
		Sdwan: &sdwan.Options{
			Authentication: &sdwan.Authentication{},
			WaitingWindow:  &waitingWindow,
		},
	}
	opts := &Options{
		ServiceEntryController: &controllers.ServiceEntryOptions{},
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
				return fmt.Errorf("no sdwan controller provided.")
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
			if fileSettingsPath != "" {
				f, err := getSettingsFromFile(fileSettingsPath)
				if err != nil {
					return err
				}
				opts = f
			}

			if flagOpts.Sdwan.Authentication.Username == "" ||
				flagOpts.Sdwan.Authentication.Password == "" {
				return fmt.Errorf("no username or password provided")
			}
			opts.Sdwan.Authentication = flagOpts.Sdwan.Authentication

			// -- SD-WAN options
			if opts.Sdwan != nil {
				fv := opts.Sdwan

				if fv.BaseURL == "" && flagOpts.Sdwan.BaseURL == "" {
					return fmt.Errorf("no base url provided")
				}

				if flagOpts.Sdwan.BaseURL != "" {
					opts.Sdwan.BaseURL = flagOpts.Sdwan.BaseURL
				}

				if cmd.Flag("waiting-window").Changed {
					opts.Sdwan.WaitingWindow = flagOpts.Sdwan.WaitingWindow
				}

				if cmd.Flag("sdwan.insecure").Changed {
					opts.Sdwan.Insecure = flagOpts.Sdwan.Insecure
				}
			}

			if _, err := url.Parse(opts.Sdwan.BaseURL); err != nil {
				return fmt.Errorf("invalid base url provided: %w", err)
			}

			if *opts.Sdwan.WaitingWindow < 0 {
				return fmt.Errorf("invalid waiting window provided")
			}

			if cmd.Flag("watch-all-service-entries").Changed {
				opts.ServiceEntryController.WatchAllServiceEntries = flagOpts.ServiceEntryController.WatchAllServiceEntries
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch chosenSdWan {
			case "vmanage":
				return runWithVmanage(kopts, opts)
			default:
				return fmt.Errorf("no sdwan controller provided.")
			}
		},
		Example: "run --kubeconfig /my/kubeconf/.conf --watch-all-service-entries",
	}

	// Flags
	cmd.Flags().StringVar(&kopts.path, "kubeconfig", func() string {
		if home := homedir.HomeDir(); len(home) > 0 {
			return path.Join(home, ".kube", "config")
		}

		return ""
	}(), "path to the kubeconfig file to use.")
	cmd.Flags().StringVar(&kopts.context, "context", "", "the context to use.")
	cmd.Flags().BoolVarP(&flagOpts.ServiceEntryController.WatchAllServiceEntries,
		"watch-all-service-entries", "w", false,
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

	return cmd
}

func runWithVmanage(kopts *kubeConfigOptions, opts *Options) error {
	var log zerolog.Logger
	{
		logLevels := [3]zerolog.Level{
			zerolog.DebugLevel,
			zerolog.InfoLevel,
			zerolog.ErrorLevel,
		}

		if opts.Verbosity < 0 || opts.Verbosity > 3 {
			fmt.Println("invalid verbosity level provided, using default")
			opts.Verbosity = defaultVerbosity
		}

		if opts.PrettyLogs {
			log = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
		} else {
			log = zerolog.New(os.Stderr).With().Timestamp().Logger()
		}

		log = log.Level(logLevels[opts.Verbosity])
		log.Info().Msg("starting...")
	}

	mgr, err := controllers.NewManager()
	if err != nil {
		return fmt.Errorf("could not get manager: %w", err)
	}

	ctx, canc := context.WithCancel(context.Background())
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
	exitChan := make(chan struct{})

	go func() {
		var err error
		defer func() {
			if err != nil {
				close(stopChan)
			}

			close(exitChan)
		}()

		log.Info().Msg("getting client...")

		vctx, vcanc := context.WithTimeout(ctx, 30*time.Second)
		vclient, err := vmanage.NewClient(vctx, opts.Sdwan)
		vcanc()
		if err != nil {
			log.Err(err).Msg("could not get client")
			// TODO: probably use an error channel on future to make this fail.
			return
		}

		opsChan := make(chan *sdwan.Operation, 100)
		defer close(opsChan)

		_, err = controllers.NewServiceEntryController(mgr, opts.ServiceEntryController, opsChan, log)
		if err != nil {
			log.Err(err).Msg("could not get controller")
			return
		}

		exitWatch := make(chan struct{})
		go func() {
			defer close(exitWatch)

			if err = vclient.WatchForOperations(ctx, opsChan, *opts.Sdwan.WaitingWindow, log); err != nil {
				log.Err(err).Msg("error while watch for operations")
				return
			}
		}()

		log.Info().Msg("starting controller...")
		if mgrErr := mgr.Start(ctx); mgrErr != nil {
			log.Err(mgrErr).Msg("could not start manager")
		}

		<-exitWatch
	}()

	log.Info().Msg("working....")

	<-stopChan
	fmt.Println()
	log.Info().Msg("exit requested")

	canc()
	<-exitChan
	log.Info().Msg("good bye!")

	return nil
}

func getSettingsFromFile(settingsPath string) (*Options, error) {
	file, err := os.Open(settingsPath)
	switch {
	case err == nil:
		stat, err := file.Stat()
		if err != nil {
			return nil, fmt.Errorf("could not check file path: %w", err)
		}

		if stat.IsDir() {
			return nil, fmt.Errorf("provided file path is a directory")
		}
	case os.IsNotExist(err):
		return nil, fmt.Errorf("provided file path does not exist")
	default:
		return nil, fmt.Errorf("could not open file path: %w", err)
	}

	defer file.Close()

	var settings Options
	if err := yaml.NewDecoder(file).Decode(&settings); err != nil {
		return nil, fmt.Errorf("could not unmarshal settings file: %w", err)
	}

	return &settings, nil
}
