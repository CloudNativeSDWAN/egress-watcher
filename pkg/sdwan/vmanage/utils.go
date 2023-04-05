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

package vmanage

import (
	"fmt"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/customapp"
)

func checkOperation(op *sdwan.Operation) error {
	var (
		hosts int
		ips   int
	)

	if len(op.Data) == 0 {
		return fmt.Errorf("no valid data")
	}

	for _, data := range op.Data {
		hosts += len(data.Hosts)
		ips += len(data.IPs)

		if hosts > 0 && ips > 0 {
			return fmt.Errorf("mix of IPs and hosts found")
		}

		switch data.Protocol {
		case sdwan.ProtocolHTTP,
			sdwan.ProtocolHTTPS, sdwan.ProtocolTCP, sdwan.ProtocolUDP:
			// Accepted, we just discard the return
			continue
		default:
			return fmt.Errorf("unsupported protocol: %s", data.Protocol)
		}
	}

	return nil
}

func buildCustomAppCreateUpdateOptions(op *sdwan.Operation) customapp.CreateUpdateOptions {
	opts := customapp.CreateUpdateOptions{
		Name: op.ApplicationName,
	}

	// -- Are there hosts?
	serverNames := []string{}
	for _, data := range op.Data {
		if len(data.Hosts) > 0 {
			serverNames = append(serverNames, data.Hosts...)
		}
	}

	if len(serverNames) > 0 {
		opts.ServerNames = serverNames
		return opts
	}

	// -- Are there IPs and ports?
	attrs := customapp.L3L4Attributes{}

	for _, protoPorts := range op.Data {
		parsedPorts := func() []int32 {
			ports := []int32{}

			for _, port := range protoPorts.Ports {
				ports = append(ports, int32(port))
			}

			return ports
		}()

		ipsAndPorts := customapp.IPsAndPorts{
			IPs: protoPorts.IPs,
			Ports: &customapp.Ports{
				Values: parsedPorts,
			},
		}

		if protoPorts.Protocol == sdwan.ProtocolTCP {
			attrs.TCP = append(attrs.TCP, ipsAndPorts)
		}

		if protoPorts.Protocol == sdwan.ProtocolUDP {
			attrs.UDP = append(attrs.UDP, ipsAndPorts)
		}
	}
	opts.L3L4Attributes = attrs

	return opts
}
