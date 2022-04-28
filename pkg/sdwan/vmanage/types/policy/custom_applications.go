// Copyright © 2022 Cisco
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// All rights reserved.

package policy

type CustomApplication struct {
	ID          string   `json:"appId"`
	Name        string   `json:"appName"`
	ServerNames []string `json:"serverNames"`
	L3L4        []string `json:"L3L4,omitempty"`
}

type ApplicationList struct {
	ID                 string              `json:"listId,omitempty"`
	Name               string              `json:"name"`
	Type               string              `json:"type"`
	Description        string              `json:"description"`
	ApplicationEntries []*ApplicationEntry `json:"entries"`
	Endpoint           *Endpoint           `json:"endpoint"`
	IsCustomApp        bool                `json:"isCustomApp"`
	ReferenceCount     int                 `json:"referenceCount"`
	// References is a list of policies, such as AppRoute, that refer to this
	// this policy application list. Or the contrary probably.
	References []*Reference `json:"references"`
	// ActivatedIDs is a list of vSmart template policies that activates
	// this policy application list.
	ActivatedIDs      []string `json:"activatedId"`
	ActivatedByVSmart bool     `json:"isActivatedByVsmart"`
}

type ApplicationEntry struct {
	Name      string `json:"app"`
	Reference string `json:"appRef"`
}

type Endpoint struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Reference struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}
