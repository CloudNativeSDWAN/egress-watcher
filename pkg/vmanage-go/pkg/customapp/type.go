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
	"time"
)

type CustomApplication struct {
	ID              string
	Name            string
	ServerNames     []string
	L3L4Attributes  L3L4Attributes
	LastUpdated     time.Time
	Owner           string
	SDAVCStatus     string
	ReferenceCount  int
	References      []Reference
	VsmartPolicyIDs []string
}

func (c *CustomApplication) GetCreateUpdateOptions() CreateUpdateOptions {
	return CreateUpdateOptions{
		Name:        c.Name,
		ServerNames: c.ServerNames,
		L3L4Attributes: func() L3L4Attributes {
			attrs := L3L4Attributes{}

			if len(c.L3L4Attributes.TCP) > 0 {
				attrs.TCP = c.L3L4Attributes.TCP
			}

			if len(c.L3L4Attributes.UDP) > 0 {
				attrs.UDP = c.L3L4Attributes.UDP
			}

			return attrs
		}(),
	}
}

type L3L4Attributes struct {
	UDP []IPsAndPorts
	TCP []IPsAndPorts
}

type IPsAndPorts struct {
	IPs   []string
	Ports *Ports
}

type Ports struct {
	Values []int32
	Ranges [][2]int32
}

type Reference struct {
	ID       string `json:"id"`
	Property string `json:"property"`
	Type     string `json:"type,omitempty"`
}

type Layer4Protocol string

const (
	TCP       Layer4Protocol = "TCP"
	UDP       Layer4Protocol = "UDP"
	TCPAndUDP Layer4Protocol = "TCP-UDP"
)

type CreateUpdateOptions struct {
	Name           string
	ServerNames    []string
	L3L4Attributes L3L4Attributes
}
