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

package cloudx

type DeviceType string

const (
	GatewayDevice              DeviceType = "gateway"
	DirectInternetAccessDevice DeviceType = "dia"
)

type Device struct {
	SiteID string   `json:"site-id"`
	VEdges []*VEdge `json:"vedgeList"`
}

type VEdge struct {
	SystemIP      string `json:"system-ip"`
	LocalSystemIP string `json:"local-system-ip"`
	HostName      string `json:"host-name"`

	// ... Other fields we don't use. They may be implemented in future
	// if we need them.
}
