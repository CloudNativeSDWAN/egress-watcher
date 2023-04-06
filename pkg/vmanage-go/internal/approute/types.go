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

import (
	"time"

	ar "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/approute"
)

type InternalPolicy struct {
	Name                string      `json:"name"`
	DefinitionID        string      `json:"definitionId,omitempty"`
	Type                string      `json:"type"`
	Description         string      `json:"description"`
	Owner               string      `json:"owner"`
	LastUpdated         *int64      `json:"lastUpdated"`
	InfoTag             string      `json:"infoTag"`
	Mode                string      `json:"mode"`
	Optimized           string      `json:"optimized"`
	ReferenceCount      int         `json:"referenceCount"`
	References          []Reference `json:"references,omitempty"`
	Sequences           []Sequence  `json:"sequences,omitempty"`
	IsActivatedByVsmart bool        `json:"isActivatedByVsmart"`
	ActivatedID         []string    `json:"activatedId"`
}

type Reference struct {
	ID       string `json:"id"`
	Property string `json:"property"`
	Type     string `json:"type,omitempty"`
}

type Sequence struct {
	SequenceID     int      `json:"sequenceId"`
	SequenceName   string   `json:"sequenceName"`
	SequenceType   string   `json:"sequenceType"`
	SequenceIPType string   `json:"sequenceIpType"`
	Match          Match    `json:"match"`
	Actions        []Action `json:"actions"`
}

type Match struct {
	Entries []Entry `json:"entries"`
}

type Entry struct {
	Field string `json:"field"`
	ID    string `json:"ref"`
}

type Action struct {
	Type      string `json:"type"`
	Parameter string `json:"parameter,omitempty"`
}

func (i *InternalPolicy) ToAppRoutePolicy() *ar.Policy {
	return &ar.Policy{
		ID:          i.DefinitionID,
		Name:        i.Name,
		Type:        i.Type,
		Description: i.Description,
		Sequences: func() []ar.Sequence {
			seqs := []ar.Sequence{}
			for _, seq := range i.Sequences {
				seqs = append(seqs, ar.Sequence{
					ID:     seq.SequenceID,
					Name:   seq.SequenceName,
					Type:   seq.SequenceType,
					IPType: seq.SequenceIPType,
					Match: ar.Match{
						Entries: func() []ar.Entry {
							es := []ar.Entry{}
							for _, entry := range seq.Match.Entries {
								es = append(es, ar.Entry{Field: entry.Field, ID: entry.ID})
							}
							return es
						}(),
					},
					Actions: func() []ar.Action {
						acts := []ar.Action{}
						for _, action := range seq.Actions {
							acts = append(acts, ar.Action{Type: action.Type, Parameter: action.Parameter})
						}
						return acts
					}(),
				})
			}
			return seqs
		}(),
		// TODO: what if this is 0? Does this even happen, actually?
		LastUpdated: func() time.Time {
			lu := i.LastUpdated
			if lu != nil {
				return time.UnixMilli(int64(*lu))
			}

			// TODO: Is this correct? (look above)
			return time.Now()
		}(),
		Owner:          i.Owner,
		InfoTag:        i.InfoTag,
		Mode:           i.Mode,
		Optimized:      i.Optimized == "true",
		ReferenceCount: i.ReferenceCount,
		References: func() []ar.Reference {
			refs := []ar.Reference{}
			for _, ref := range i.References {
				refs = append(refs, ar.Reference{
					ID:       ref.ID,
					Property: ref.Property,
					Type:     ref.Type,
				})
			}
			return refs
		}(),
		ActivatedByVSmartPolicies: i.ActivatedID,
	}
}

type BulkPolicy struct {
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Description string     `json:"description"`
	Sequences   []Sequence `json:"sequences"`
	ID          string     `json:"id"`
	IsCreate    bool       `json:"isCreate"`
}

func NewBulkPoliciesFromOptions(opts ar.BulkOptions) []BulkPolicy {
	pols := []BulkPolicy{}
	for _, pol := range opts.Update {
		p := BulkPolicy{
			Name:        pol.Name,
			Type:        pol.Type,
			Description: pol.Description,
			Sequences:   NewSequences(pol.Sequences),
			ID:          pol.ID,
		}
		pols = append(pols, p)
	}
	for _, pol := range opts.Create {
		p := BulkPolicy{
			Name:        pol.Name,
			Type:        pol.Type,
			Description: pol.Description,
			Sequences:   NewSequences(pol.Sequences),
			ID:          pol.ID,
			IsCreate:    true,
		}
		pols = append(pols, p)
	}

	return pols
}

type BulkRequestBody struct {
	Definitions []BulkPolicy `json:"definitions"`
	ProcessID   string       `json:"processId"`
}

func NewSequences(sequences []ar.Sequence) []Sequence {
	seqs := []Sequence{}
	for _, seq := range sequences {
		seqs = append(seqs, Sequence{
			SequenceID:     seq.ID,
			SequenceName:   seq.Name,
			SequenceType:   seq.Type,
			SequenceIPType: seq.IPType,
			Match: Match{
				Entries: func() []Entry {
					entries := []Entry{}
					for _, entry := range seq.Match.Entries {
						entries = append(entries, Entry{Field: entry.Field, ID: entry.ID})
					}
					return entries
				}(),
			},
			Actions: func() []Action {
				actions := []Action{}
				for _, action := range actions {
					actions = append(actions, Action{Type: action.Type, Parameter: action.Parameter})
				}
				return actions
			}(),
		})
	}
	return seqs
}
