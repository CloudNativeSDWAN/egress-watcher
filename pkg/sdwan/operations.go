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

package sdwan

type OperationType string

const (
	OperationRemove         OperationType = "remove"
	OperationCreateOrUpdate OperationType = "create-or-update"
	OperationUpdate         OperationType = "update"

	// This one will soon be deprecated.
	OperationAdd OperationType = "add"
)

type Protocol string

// NON-EXHAUSTIVE
const (
	ProtocolTCP   Protocol = "tcp"
	ProtocolUDP   Protocol = "udp"
	ProtocolHTTPS Protocol = "https"
	ProtocolHTTP  Protocol = "http"
)

type L3L4Data struct {
	// One of IPs and Hosts should be there, not together.
	IPs      []string
	Hosts    []string
	Ports    []uint32
	Protocol Protocol
}

type Operation struct {
	Type            OperationType
	ApplicationName string
	// DEPRECATED: use L3L4 instead
	Servers []string

	Data []*L3L4Data
}
