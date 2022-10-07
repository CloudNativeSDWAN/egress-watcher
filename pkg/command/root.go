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
	"github.com/spf13/cobra"
)

func GetRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "egress-watcher run|deploy|set [OPTIONS]",
		Short: "Watch for ServiceEntry objects.",
		Long: `Watch for ServiceEntry objects in Kubernetes and send data to
an SD-WAN controller for processing.`,
		Example: "egress-watcher run --kubeconfig /my/kubeconf/.conf --watch-all-service-entries",
	}

	// Commands
	cmd.AddCommand(getRunCommand())

	return cmd
}
