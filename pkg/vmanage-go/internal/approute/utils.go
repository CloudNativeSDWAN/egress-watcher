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

import ar "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/approute"

func RemoveAppListsFromSequences(sequences []ar.Sequence, toRemove [][2]string) []ar.Sequence {
	sequencesToKeep := []ar.Sequence{}
	remove := map[string]bool{}
	for _, rem := range toRemove {
		remove[rem[0]] = true
	}

	for _, seq := range sequences {
		found := func() bool {
			for _, entry := range seq.Match.Entries {
				if _, exists := remove[entry.ID]; exists {
					return true
				}
			}

			return false
		}()

		if !found {
			sequencesToKeep = append(sequencesToKeep, seq)

			// Re-write sequences
			sequencesToKeep[len(sequencesToKeep)-1].ID = ((len(sequencesToKeep) - 1) * 10) + 1
		}
	}

	return sequencesToKeep
}

func AddAppListsToSequences(sequences []ar.Sequence, toAdd [][2]string) []ar.Sequence {
	const (
		saasAppList          = "saasAppList"
		appRouteSequenceName = "App Route"
		appRouteSequenceType = "appRoute"
		cloudSaasType        = "cloudSaas"
		countType            = "count"
		ipv4Type             = "ipv4"
	)

	sequencesToKeep := append([]ar.Sequence{}, sequences...)
	for _, add := range toAdd {
		found := func() bool {
			for _, sequence := range sequences {
				for _, entry := range sequence.Match.Entries {
					if entry.Field == saasAppList && entry.ID == add[0] {
						return true
					}
				}
			}

			return false
		}()

		if !found {
			// If you're here, it means that it does not exist.
			newSequenceID := 1
			if len(sequencesToKeep) > 0 {
				newSequenceID = sequencesToKeep[len(sequencesToKeep)-1].ID + 10
			}

			sequencesToKeep = append(sequencesToKeep, ar.Sequence{
				ID:     newSequenceID,
				Name:   appRouteSequenceName,
				Type:   appRouteSequenceType,
				IPType: ipv4Type,
				Match: ar.Match{
					Entries: []ar.Entry{
						{Field: saasAppList, ID: add[0]},
					},
				},
				Actions: []ar.Action{
					{Type: cloudSaasType},
					{Type: countType, Parameter: add[1] + "_ctr"},
				},
			})
		}
	}

	return sequencesToKeep
}
