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

import (
	"strings"
	"time"

	al "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/applist"
)

type InternalApplicationList struct {
	ListID            string              `json:"listId,omitempty"`
	Name              string              `json:"name"`
	Type              string              `json:"type"`
	Description       string              `json:"description,omitempty"`
	Entries           []InternalEntry     `json:"entries,omitempty"`
	LastUpdated       *int64              `json:"lastUpdated,omitempty"`
	Owner             string              `json:"owner,omitempty"`
	ReadOnly          bool                `json:"readOnly"`
	Version           string              `json:"version,omitempty"`
	Endpoint          InternalEndpoint    `json:"endpoint"`
	IsCustomApp       bool                `json:"isCustomApp"`
	InfoTag           string              `json:"infoTag"`
	ReferenceCount    int                 `json:"referenceCount"`
	References        []InternalReference `json:"references"`
	ActivatedID       []string            `json:"activatedId"`
	ActivatedByVSmart bool                `json:"isActivatedByVsmart"`
}

type InternalEntry struct {
	App    string `json:"app"`
	AppRef string `json:"appRef"`
}

type InternalEndpoint struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type InternalReference struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func (l *InternalApplicationList) ToApplicationList() *al.ApplicationList {
	return &al.ApplicationList{
		ID:          l.ListID,
		Name:        l.Name,
		Type:        l.Type,
		Description: l.Description,
		Applications: func() []al.Application {
			apps := []al.Application{}
			for _, e := range l.Entries {
				apps = append(apps, al.Application{
					Name: e.App,
					ID:   e.AppRef,
				})
			}
			return apps
		}(),
		// TODO: what if this is 0? Does this even happen, actually?
		LastUpdated: func() time.Time {
			lu := l.LastUpdated
			if lu != nil {
				return time.UnixMilli(int64(*lu))
			}

			// TODO: Is this correct? (look above)
			return time.Now()
		}(),
		Owner:    l.Owner,
		ReadOnly: l.ReadOnly,
		Version:  l.Version,
		Probe: al.Probe{
			Type:  al.ProbeType(l.Endpoint.Type),
			Value: strings.TrimSpace(l.Endpoint.Value),
		},
		ListType: func() al.ListType {
			if l.IsCustomApp {
				return al.Custom
			}

			return al.Standard
		}(),
		ReferenceCount: l.ReferenceCount,
		References: func() []al.Reference {
			refs := []al.Reference{}
			for _, ref := range l.References {
				refs = append(refs, al.Reference{
					ID:   ref.ID,
					Type: ref.Type,
				})
			}
			return refs
		}(),
		VsmartPolicyIDs: l.ActivatedID,
	}
}

func NewInternalApplicationList(l *al.ApplicationList) *InternalApplicationList {
	return &InternalApplicationList{
		ListID:      l.ID,
		Name:        l.Name,
		Type:        l.Type,
		Description: l.Description,
		Entries: func() []InternalEntry {
			es := []InternalEntry{}
			for _, app := range l.Applications {
				es = append(es, InternalEntry{
					App:    app.Name,
					AppRef: app.ID,
				})
			}
			return es
		}(),
		LastUpdated: func() *int64 {
			var defTime time.Time
			if l.LastUpdated == defTime {
				return nil
			}

			lu := l.LastUpdated.UnixMilli()
			return &lu
		}(),
		Owner:    l.Owner,
		ReadOnly: l.ReadOnly,
		Version:  l.Version,
		Endpoint: InternalEndpoint{
			// This must (and is) validated from public package
			Type:  string(l.Probe.Type),
			Value: l.Probe.Value,
		},
		IsCustomApp:    l.ListType == al.Custom,
		InfoTag:        l.InfoTag,
		ReferenceCount: l.ReferenceCount,
		References: func() []InternalReference {
			refs := []InternalReference{}
			for _, ref := range l.References {
				refs = append(refs, InternalReference{ID: ref.ID, Type: ref.Type})
			}
			return refs
		}(),
		ActivatedID:       l.VsmartPolicyIDs,
		ActivatedByVSmart: len(l.VsmartPolicyIDs) > 0,
	}
}
