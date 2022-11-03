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

package customapp

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	ca "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/customapp"
)

type InternalCustomApplication struct {
	AppID               string         `json:"appId,omitempty"`
	AppName             string         `json:"appName"`
	ServerNames         []string       `json:"serverNames"`
	LastUpdated         string         `json:"lastUpdated,omitempty"`
	Owner               string         `json:"owner,omitempty"`
	L3L4Attributes      []InternalL3L4 `json:"L3L4,omitempty"`
	SDAVCStatus         string         `json:"sdavcStatus,omitempty"`
	ReferenceCount      int            `json:"referenceCount"`
	References          []Reference    `json:"references,omitempty"`
	ActivatedID         []string       `json:"activatedId,omitempty"`
	IsActivatedByVsmart bool           `json:"isActivatedByVsmart"`
}

type InternalL3L4 struct {
	IPs        []string `json:"ipAddresses,omitempty"`
	Ports      string   `json:"ports,omitempty"`
	L4Protocol string   `json:"l4Protocol,omitempty"`
}

type Reference struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func (c *InternalCustomApplication) ToCustomApplication() *ca.CustomApplication {
	return &ca.CustomApplication{
		ID:   c.AppID,
		Name: c.AppName,
		ServerNames: func() []string {
			servers := []string{}
			for _, server := range c.ServerNames {
				servers = append(servers, strings.Trim(server, " "))
			}
			return servers
		}(),
		LastUpdated: func() time.Time {
			// TODO: what if nothing is here? Does this even happen, actually?
			timestamp, _ := strconv.ParseInt(c.LastUpdated, 10, 64)
			return time.UnixMilli(int64(timestamp))
		}(),
		Owner:          c.Owner,
		SDAVCStatus:    c.SDAVCStatus,
		ReferenceCount: c.ReferenceCount,
		References: func() []ca.Reference {
			refs := []ca.Reference{}
			for _, ref := range c.References {
				refs = append(refs, ca.Reference{
					ID:   ref.ID,
					Type: ref.Type,
				})
			}
			return refs
		}(),
		L3L4Attributes:  parseL3L4(c.L3L4Attributes),
		VsmartPolicyIDs: c.ActivatedID,
	}
}

func parseL3L4(l3l4 []InternalL3L4) *ca.L3L4Attributes {
	vals := map[ca.Layer4Protocol][]ca.IPsAndPorts{}

	// Group everything under the same protocol.
	for _, val := range l3l4 {
		ports := ca.Ports{
			Values: []int32{},
			Ranges: [][2]int32{},
		}
		if val.Ports != "" {
			ports = parsePortsFromString(val.Ports)
		}

		parsedVal := ca.IPsAndPorts{
			IPs:   val.IPs,
			Ports: &ports,
		}

		var protos []ca.Layer4Protocol
		switch val.L4Protocol {
		case "TCP":
			protos = []ca.Layer4Protocol{ca.TCP}
		case "UDP":
			protos = []ca.Layer4Protocol{ca.UDP}
		case "TCP-UDP":
			protos = []ca.Layer4Protocol{ca.TCP, ca.UDP}
		}

		for _, proto := range protos {
			if _, exists := vals[proto]; !exists {
				vals[proto] = []ca.IPsAndPorts{}
			}

			vals[proto] = append(vals[proto], parsedVal)
		}
	}

	parsedAttributes := &ca.L3L4Attributes{}
	for l4, val := range vals {
		if l4 == ca.TCP {
			parsedAttributes.TCP = append(parsedAttributes.TCP, val...)
		} else {
			parsedAttributes.UDP = append(parsedAttributes.UDP, val...)
		}
	}

	return parsedAttributes
}

func parsePortsFromString(ports string) ca.Ports {
	parsedPorts := ca.Ports{
		Values: []int32{},
		Ranges: [][2]int32{},
	}

	vals := strings.Split(ports, " ")
	for _, val := range vals {

		if !strings.Contains(val, "-") {
			// If this is not a range
			port, _ := strconv.ParseInt(val, 10, 32)
			parsedPorts.Values = append(parsedPorts.Values, int32(port))
		} else {
			ranges := strings.Split(val, "-")
			start, _ := strconv.ParseInt(ranges[0], 10, 32)
			end, _ := strconv.ParseInt(ranges[1], 10, 32)
			parsedPorts.Ranges = append(parsedPorts.Ranges, [2]int32{int32(start), int32(end)})
		}
	}

	return parsedPorts
}

func NewInternalCustomApplication(c *ca.CustomApplication) *InternalCustomApplication {
	return &InternalCustomApplication{
		AppID:       c.ID,
		AppName:     c.Name,
		ServerNames: c.ServerNames,
		L3L4Attributes: func() []InternalL3L4 {
			if c.L3L4Attributes == nil {
				return []InternalL3L4{}
			}

			return toInternalL3L4(c.L3L4Attributes)
		}(),
		LastUpdated: func() string {
			var defaultTime time.Time
			if c.LastUpdated == defaultTime {
				return ""
			}

			return strconv.Itoa(int(c.LastUpdated.UnixMilli()))
		}(),
		Owner:          c.Owner,
		SDAVCStatus:    c.SDAVCStatus,
		ReferenceCount: c.ReferenceCount,
		References: func() []Reference {
			refs := []Reference{}
			for _, ref := range refs {
				refs = append(refs, Reference{ID: ref.ID, Type: ref.Type})
			}
			return refs
		}(),
		ActivatedID:         c.VsmartPolicyIDs,
		IsActivatedByVsmart: len(c.VsmartPolicyIDs) > 0,
	}
}

func toInternalL3L4(attr *ca.L3L4Attributes) []InternalL3L4 {
	l3l4 := []InternalL3L4{}

	renderL3L4 := func(ipsPorts ca.IPsAndPorts, l4 ca.Layer4Protocol) InternalL3L4 {
		return InternalL3L4{
			L4Protocol: string(l4),
			Ports: func() string {
				ports := []string{}
				for _, port := range ipsPorts.Ports.Values {
					ports = append(ports, strconv.Itoa(int(port)))
				}
				for _, portRange := range ipsPorts.Ports.Ranges {
					ports = append(ports, fmt.Sprintf("%d-%d", portRange[0], portRange[1]))
				}
				return strings.Join(ports, " ")
			}(),
			IPs: func() []string {
				ips := []string{}
				for _, ip := range ipsPorts.IPs {
					// Sometimes vManage appends/prepends spaces in the IP.
					// Don't know why but it does.
					// TODO: other validations and sanitizations.
					ips = append(ips, strings.Trim(ip, " "))
				}
				return ips
			}(),
		}
	}

	for _, tcp := range attr.TCP {
		l3l4 = append(l3l4, renderL3L4(tcp, "TCP"))
	}
	for _, udp := range attr.UDP {
		l3l4 = append(l3l4, renderL3L4(udp, "UDP"))
	}

	return l3l4
}
