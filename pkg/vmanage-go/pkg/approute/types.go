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

import "time"

type Policy struct {
	ID                        string
	Name                      string
	Type                      string
	Description               string
	Sequences                 []Sequence
	LastUpdated               time.Time
	Owner                     string
	InfoTag                   string
	Mode                      string
	Optimized                 bool
	ReferenceCount            int
	References                []Reference
	ActivatedByVSmartPolicies []string
}

type Sequence struct {
	ID      int
	Name    string
	Type    string
	IPType  string
	Match   Match
	Actions []Action
}

type Match struct {
	Entries []Entry
}

type Entry struct {
	Field string
	ID    string
}

type Action struct {
	Type      string
	Parameter string
}

type Reference struct {
	ID       string
	Property string
	Type     string
}

type BulkOptions struct {
	Create []*Policy
	Update []*Policy
}

type AddRemoveAppListOptions struct {
	// Add is a list of names of application lists to add to this AppRoute
	// Policy.
	Add []string
	// Remove is a list of names of application lists to remove from this
	// AppRoute Policy.
	Remove []string
}
