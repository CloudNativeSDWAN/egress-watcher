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

package vsmart

type Policy struct {
	ID             string `json:"policyId"`
	Type           string `json:"policyType"`
	Name           string `json:"policyName"`
	Description    string `json:"policyDescription"`
	Version        string `json:"policyVersion"`
	DefinitionJSON string `json:"policyDefinition"`
	Definition     *PolicyDefinition
	IsActivated    bool   `json:"isPolicyActivated"`
	RID            int    `json:"@rid"`
	CreatedOn      int64  `json:"createdOn"`
	CreatedBy      string `json:"createdBy"`
	LastUpdatedOn  int64  `json:"lastUpdatedOn"`
	LastUpdatedBy  string `json:"lastUpdatedBy"`
}

type PolicyDefinition struct {
	Type                 string                `json:"policyType,omitempty"`
	Name                 string                `json:"policyName,omitempty"`
	Description          string                `json:"policyDescription,omitempty"`
	IsActivated          bool                  `json:"isPolicyActivated"`
	Assemblies           []*Assembly           `json:"assembly"`
	RegionRoleAssemblies []*RegionRoleAssembly `json:"regionRoleAssembly"`
}

type Assembly struct {
	DefinitionId string   `json:"definitionId"`
	Type         string   `json:"type"`
	Entries      []*Entry `json:"entries"`
}

type RegionRoleAssembly struct{}

type Entry struct {
	Sites []string `json:"siteLists"`
	VPNs  []string `json:"vpnLists"`
}
