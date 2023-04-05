// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
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
	"os"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/controllers"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	defaultVerbosity int = 1
)

func initLogger(opts *Options) (log zerolog.Logger) {
	logLevels := [3]zerolog.Level{
		zerolog.DebugLevel,
		zerolog.InfoLevel,
		zerolog.ErrorLevel,
	}

	if opts.Verbosity < 0 || opts.Verbosity > 3 {
		fmt.Println("invalid verbosity level provided, using default...")
		opts.Verbosity = defaultVerbosity
	}

	if opts.PrettyLogs {
		log = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	} else {
		log = zerolog.New(os.Stderr).With().Timestamp().Logger()
	}

	log = log.Level(logLevels[opts.Verbosity])
	return log
}

func initControllers(opsChan chan *sdwan.Operation, kopts *kubeConfigOptions, opts *Options, log zerolog.Logger) (manager.Manager, error) {
	mgr, err := controllers.NewManager(kopts.path)
	if err != nil {
		return nil, fmt.Errorf("could not get manager: %w", err)
	}

	_, err = controllers.NewServiceEntryController(mgr, opts.ServiceEntryController, opsChan, log)
	if err != nil {
		return nil, fmt.Errorf("could not initiate service entry "+
			"controller: %w", err)
	}

	_, err = controllers.NewNetworkPolicyController(mgr, opts.NetworkPolicyController, opsChan, log)
	if err != nil {
		return nil, fmt.Errorf("could not initiate network policy "+
			"controller: %w", err)
	}

	return mgr, nil
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
