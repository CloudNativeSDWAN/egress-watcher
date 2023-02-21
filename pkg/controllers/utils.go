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

package controllers

import (
	"strings"

	netv1b1 "istio.io/api/networking/v1beta1"
	vb1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// replaceDots replaces all the dots in a name with underscores.
//
// This is just a shorthand function used to return a suitable application
// or application list name from a server name.
func replaceDots(hostName string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(hostName, ".", "_"),
		"*", "_")
}

func shouldWatchLabel(labels map[string]string, watchAllByDefault bool) bool {
	switch labels[watchLabel] {
	case watchEnabledLabel:
		return true
	case watchDisabledLabel:
		return false
	default:
		return watchAllByDefault
	}
}

func getHostsFromServiceEntry(se *vb1.ServiceEntry) (hosts []string) {
	for _, host := range se.Spec.Hosts {
		if len(validation.IsDNS1123Subdomain(host)) == 0 {
			hosts = append(hosts, host)
		}
	}

	return hosts
}

func getProtocolAndPortFromServiceEntry(ports []*netv1b1.Port) (string, uint32) {
	var (
		protocol string
		port     uint32
	)

	for _, sePort := range ports {
		switch strings.ToLower(sePort.Protocol) {
		case "https":
			// HTTPS has the priority
			return "https", sePort.Number
		case "http":
			// HTTP has second priority: is stored but not returned because
			// we want to see if maybe we also have https in other iterations.
			protocol, port = "http", sePort.Number
		case "mongo":
			// mongo is not supported
			continue
		default:
			if protocol == "" {
				// Everything else has lowest priority, so it will be added
				// only if http is not there.
				protocol, port = "https", sePort.Number
			}
		}

	}

	return protocol, port
}
