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
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func getInstallCommand() *cobra.Command {
	var (
		interactive bool
		user        string
		pass        string
		baseurl     string
	)

	cmd := &cobra.Command{
		Use: "install [OPTIONS]",
		Short: `Install the egress watcher in Kubernetes.

This is an experimental feature.`,
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
				installInteractivelyToK8s(clientset)
			} else {
				install(clientset, user, pass, baseurl)
			}

			return nil

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

func install(clientset *kubernetes.Clientset, user, pass, url string) error {
	usernamespace := "egress-watcher"
	usersettingsfilename := "settings.yaml"
	defaultImage := "ghcr.io/cloudnativesdwan/egress-watcher:v0.3.0"

	createNamespace(clientset, usernamespace)
	createSecret(clientset, usernamespace, "vmanage-credentials", user, pass)
	createConfigMap(clientset, usernamespace, "egress-watcher-settings", usersettingsfilename, url, user, pass)
	createServiceAccount(clientset, usernamespace, "egress-watcher-service-account")
	createClusterRole(clientset, usernamespace, "egress-watcher-role")
	createClusterRoleBinding(clientset, usernamespace, "egress-watcher-role-binding")
	createDeployment(clientset, "new-deployment", usernamespace, defaultImage)

	return nil
}

func installInteractivelyToK8s(clientset *kubernetes.Clientset) error {
	//Take inputs from user
	fmt.Println("Hi user , please enter your sdwan username :")
	var sdwan_username string
	fmt.Scanln(&sdwan_username)

	// enter password
	fmt.Println("Please enter your sdwan password :")
	var sdwan_password string
	fmt.Scanln(&sdwan_password)

	//enter base_url
	fmt.Println("Please enter your sdwan base_url :")
	var sdwan_base_url string
	fmt.Scanln(&sdwan_base_url)

	usernamespace := "egress-watcher"
	usersettingsfilename := "settings.yaml"
	defaultImage := "ghcr.io/cloudnativesdwan/egress-watcher:v0.3.0"

	createNamespace(clientset, usernamespace)
	createSecret(clientset, usernamespace, "vmanage-credentials", sdwan_username, sdwan_password)
	createConfigMap(clientset, usernamespace, "egress-watcher-settings", usersettingsfilename, sdwan_base_url, sdwan_username, sdwan_password)
	createServiceAccount(clientset, usernamespace, "egress-watcher-service-account")
	createClusterRole(clientset, usernamespace, "egress-watcher-role")
	createClusterRoleBinding(clientset, usernamespace, "egress-watcher-role-binding")
	createDeployment(clientset, "new-deployment", usernamespace, defaultImage)

	return nil
}
