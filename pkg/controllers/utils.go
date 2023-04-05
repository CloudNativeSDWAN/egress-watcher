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
	"net"
	"strings"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	netv1b1 "istio.io/api/networking/v1beta1"
	vb1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
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

func getProtocolAndPortFromServiceEntry(ports []*netv1b1.ServicePort) (string, uint32) {
	var (
		protocol string
		port     uint32
	)

	for _, sePort := range ports {
		switch proto := strings.ToLower(sePort.Protocol); proto {
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
				protocol, port = proto, sePort.Number
			}
		}

	}

	return protocol, port
}

type checkServiceEntryResult struct {
	passed   bool
	reason   string
	protocol string
	port     uint32
	hosts    []string
}

func checkServiceEntry(se *vb1.ServiceEntry, opts *ServiceEntryOptions) (result checkServiceEntryResult) {
	result = checkServiceEntryResult{}

	if !shouldWatchLabel(se.Labels, opts.WatchAllServiceEntries) {
		result.reason = "no watch label found"
		return
	}

	if se.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL {
		result.reason = "not a MESH_EXTERNAL"
		return
	}

	if se.Spec.Resolution != netv1b1.ServiceEntry_DNS {
		result.reason = "not a DNS"
		return
	}

	parsedHosts := getHostsFromServiceEntry(se)
	if len(parsedHosts) == 0 {
		result.reason = "no valid hosts found"
		return
	}

	result.passed = true
	result.hosts = parsedHosts
	result.protocol, result.port = getProtocolAndPortFromServiceEntry(se.Spec.Ports)
	return
}

type ipsAndPorts struct {
	ips []string
	tcp []uint32
	udp []uint32
}

// Credits to @tomilashy for the original work on this function.
func getIpsAndPortsFromNetworkPolicy(n *netv1.NetworkPolicy) []*sdwan.L3L4Data {
	ipPorts := []ipsAndPorts{}
	for _, rule := range n.Spec.Egress {
		ips := []string{}
		tcpPorts := []uint32{}
		udpPorts := []uint32{}

		// Get the ports and protocols
		for _, port := range rule.Ports {
			portNumber := func() uint32 {
				if port.Port != nil {
					return uint32(port.Port.IntVal)
				}

				return 0
			}()
			if portNumber == 0 {
				continue
			}

			switch *port.Protocol {
			case v1.ProtocolTCP:
				tcpPorts = append(tcpPorts, portNumber)
			case v1.ProtocolUDP:
				udpPorts = append(udpPorts, portNumber)
			}
		}

		// Get the ips
		for _, to := range rule.To {
			if to.IPBlock != nil {
				ipv4Addr, _, _ := net.ParseCIDR(to.IPBlock.CIDR)
				if len(validation.IsValidIP(ipv4Addr.String())) == 0 {
					ips = append(ips, ipv4Addr.String())
				}
			}
		}

		if len(ips) > 0 && (len(tcpPorts) > 0 || len(udpPorts) > 0) {
			ipPorts = append(ipPorts, ipsAndPorts{
				ips: ips,
				tcp: tcpPorts,
				udp: udpPorts,
			})
		}
	}

	data := []*sdwan.L3L4Data{}
	for _, ipPort := range ipPorts {

		if len(ipPort.tcp) > 0 {
			data = append(data, &sdwan.L3L4Data{
				IPs:      ipPort.ips,
				Protocol: sdwan.ProtocolTCP,
				Ports:    ipPort.tcp,
			})
		}

		if len(ipPort.udp) > 0 {
			data = append(data, &sdwan.L3L4Data{
				IPs:      ipPort.ips,
				Protocol: sdwan.ProtocolUDP,
				Ports:    ipPort.udp,
			})
		}
	}

	return data
}
