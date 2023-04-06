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

package vsmart

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/vsmart"
)

type InternalPolicy struct {
	PolicyID          string `json:"policyId"`
	PolicyName        string `json:"policyName"`
	PolicyDescription string `json:"policyDescription"`
	PolicyVersion     string `json:"policyVersion"`
	PolicyType        string `json:"policyType"`
	CreatedOn         int64  `json:"createdOn"`
	CreatedBy         string `json:"createdBy"`
	LastUpdatedBy     string `json:"lastUpdatedBy"`
	LastUpdatedOn     int64  `json:"lastUpdatedOn"`
	IsPolicyActivated bool   `json:"isPolicyActivated"`
	RID               int    `json:"@rid"`
	PolicyDefinition  string `json:"policyDefinition"`
}

type InternalDefinition struct {
	Assembly []InternalPolicyAssembly `json:"assembly"`
}

type InternalPolicyAssembly struct {
	DefinitionID string          `json:"definitionId"`
	Type         string          `json:"type"`
	Entries      []InternalEntry `json:"entries"`
}

type InternalEntry struct {
	SiteLists []string `json:"siteLists"`
	VpnLists  []string `json:"vpnLists"`
}

func (p *InternalPolicy) ToPolicy() *vsmart.Policy {
	var def InternalDefinition

	json.NewDecoder(strings.NewReader(p.PolicyDefinition)).Decode(&def)

	return &vsmart.Policy{
		ID:            p.PolicyID,
		Name:          p.PolicyName,
		Type:          p.PolicyType,
		Description:   p.PolicyDescription,
		Version:       p.PolicyVersion,
		CreatedOn:     time.UnixMilli(p.CreatedOn),
		CreatedBy:     p.CreatedBy,
		LastUpdatedOn: time.UnixMilli(p.LastUpdatedOn),
		LastUpdatedBy: p.LastUpdatedBy,
		IsActivated:   p.IsPolicyActivated,
		RID:           p.RID,
		Assemblies: func() []vsmart.Assembly {
			asm := []vsmart.Assembly{}
			for _, as := range def.Assembly {
				asm = append(asm, vsmart.Assembly{
					DefinitionID: as.DefinitionID,
					Type:         as.Type,
					Entries: func() []vsmart.Entry {
						entries := []vsmart.Entry{}
						for _, en := range as.Entries {
							entries = append(entries, vsmart.Entry{
								Sites: en.SiteLists,
								VPNs:  en.VpnLists,
							})
						}
						return entries
					}(),
				})
			}
			return asm
		}(),
	}
}

type UpdatePolicyRequestBody struct {
	PolicyDescription string             `json:"policyDescription"`
	PolicyType        string             `json:"policyType"`
	PolicyName        string             `json:"policyName"`
	Definition        InternalDefinition `json:"policyDefinition"`
	IsPolicyActivated bool               `json:"isPolicyActivated"`
}

func NewUpdatePolicyRequestBody(pol *vsmart.Policy) *UpdatePolicyRequestBody {
	return &UpdatePolicyRequestBody{
		PolicyDescription: pol.Description,
		PolicyType:        pol.Type,
		PolicyName:        pol.Name,
		IsPolicyActivated: pol.IsActivated,
		Definition: InternalDefinition{
			Assembly: func() []InternalPolicyAssembly {
				asm := []InternalPolicyAssembly{}
				for _, as := range pol.Assemblies {
					asm = append(asm, InternalPolicyAssembly{
						DefinitionID: as.DefinitionID,
						Type:         as.Type,
						Entries: func() []InternalEntry {
							entries := []InternalEntry{}
							for _, entry := range as.Entries {
								entries = append(entries, InternalEntry{
									SiteLists: entry.Sites,
									VpnLists:  entry.VPNs,
								})
							}
							return entries
						}(),
					})
				}
				return asm
			}(),
		},
	}
}

type ActivatePolicyRequestBody struct {
	IsEdited  bool   `json:"isEdited"`
	ProcessID string `json:"processId"`
}
