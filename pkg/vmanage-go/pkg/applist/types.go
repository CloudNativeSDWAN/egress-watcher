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

package applist

import "time"

type ApplicationList struct {
	ID           string
	Name         string
	Type         string
	Description  string
	Applications []Application
	LastUpdated  time.Time
	Owner        string
	ReadOnly     bool
	Version      string
	// NOTE: In the api this is called endpoint, but in the GUI it is called
	// probe. We're going to adapt this.
	Probe Probe
	// ListType can be either "standard" if already existing or "custom" if
	// created by the user.
	ListType       ListType
	ReferenceCount int
	// References is a list of policies, such as AppRoute, that refer to this
	// this policy application list. Or the contrary maybe.
	// NOTE: many times vmanage includes empty values, so this must be parsed
	// by the user anyways! Because we have ReferenceCount which we do not know
	// how it behaves!
	References []Reference
	// VsmartPoliciesIDs is a list of vSmart policies IDs that activate
	// this policy application list. If empty, it means that this application
	// list is not activated by any vSmart policy.
	VsmartPolicyIDs []string
	InfoTag         string
}

type Application struct {
	// Name of the application inside this application list.
	Name string
	// ID of the custom application. If this is not a custom application,
	// then this is empty.
	ID string
}

type Probe struct {
	Type  ProbeType
	Value string
}

type ProbeType string

const (
	FQDNProbe ProbeType = "fqdn"
	URLProbe  ProbeType = "url"
	IPProbe   ProbeType = "ip"
)

type Reference struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type ListType string

const (
	Standard ListType = "standard"
	Custom   ListType = "custom"
)

type CreateOptions struct {
	Name         string
	Description  string
	Applications []Application
	Probe        Probe
}
