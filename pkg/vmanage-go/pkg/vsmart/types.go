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

import "time"

type Policy struct {
	ID            string
	Name          string
	Description   string
	Version       string
	Type          string
	CreatedOn     time.Time
	CreatedBy     string
	LastUpdatedBy string
	LastUpdatedOn time.Time
	IsActivated   bool
	RID           int
	Assemblies    []Assembly
}

type Assembly struct {
	DefinitionID string
	Type         string
	Entries      []Entry
}

type Entry struct {
	Sites []string
	VPNs  []string
}
