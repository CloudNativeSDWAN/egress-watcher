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

package approute

type Policy struct {
	DefinitionID      string       `json:"definitionId"`
	Name              string       `json:"name"`
	Type              string       `json:"type"`
	Description       string       `json:"description"`
	Sequences         []*Sequence  `json:"sequences"`
	LastUpdated       int64        `json:"lastUpdated"`
	Owner             string       `json:"owner"`
	InfoTag           string       `json:"infoTag"`
	Mode              string       `json:"mode"`
	Optimized         string       `json:"optimized"`
	ReferenceCount    int          `json:"referenceCount"`
	References        []*Reference `json:"references"`
	ActivatedIDs      []string     `json:"activatedId"`
	ActivatedByVSmart bool         `json:"isActivatedByVsmart"`

	// ID is exactly the same as DefinitionID but the Bulk endpoint calls it
	// just `id` instead of `definitionId`.
	ID *string `json:"id,omitempty"`
	// IsCreate is used for the Bulk endpoint.
	IsCreate *bool `json:"isCreate,omitempty"`
}

type Sequence struct {
	ID      int       `json:"sequenceId"`
	Name    string    `json:"sequenceName"`
	Type    string    `json:"sequenceType"`
	IPType  string    `json:"sequenceIpType"`
	Match   *Match    `json:"match"`
	Actions []*Action `json:"actions"`
}

type Match struct {
	Entries []*Entry `json:"entries"`
}

type Entry struct {
	Field     string `json:"field"`
	Reference string `json:"ref"`
}

type Action struct {
	Type      string `json:"type"`
	Parameter string `json:"parameter"`
}

type Reference struct {
	ID       string `json:"id"`
	Property string `json:"property"`
}
