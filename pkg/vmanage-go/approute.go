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

package vmanagego

import (
	"context"
	"encoding/json"
	"fmt"

	iar "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/approute"
	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	ar "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/approute"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

type appRouteOps struct {
	*r.Requester
}

func (c *Client) AppRoute() *appRouteOps {
	return newAppRouteOpsFromRequester(c.requester)
}

func newAppRouteOpsFromRequester(req *r.Requester) *appRouteOps {
	const (
		pathApprouteBasePath string = "dataservice/template/policy/definition/approute"
	)

	return &appRouteOps{
		Requester: req.CloneWithNewBasePath(pathApprouteBasePath),
	}
}

func (a *appRouteOps) List(ctx context.Context) ([]*ar.Policy, error) {
	resp, err := a.Do(ctx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	pols := []*ar.Policy{}
	{
		var _pols []*iar.InternalPolicy
		if err := json.NewDecoder(resp.Body).Decode(&_pols); err != nil {
			return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
		}

		for _, _pol := range _pols {
			pol, err := a.Get(ctx, _pol.DefinitionID)
			if err != nil {
				return nil, fmt.Errorf("error while getting approute with ID %s: %w", _pol.DefinitionID, err)
			}

			pols = append(pols, pol)
		}
	}

	return pols, nil
}

func (a *appRouteOps) Get(ctx context.Context, id string) (*ar.Policy, error) {
	if id == "" {
		return nil, verrors.ErrorNoDefinitionIDProvided
	}

	resp, err := a.Do(ctx, r.WithPath(id))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pol iar.InternalPolicy
	if err := json.NewDecoder(resp.Body).Decode(&pol); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return pol.ToAppRoutePolicy(), nil
}

func (a *appRouteOps) BulkUpdateCreate(ctx context.Context, opts ar.BulkOptions) (*string, error) {
	if len(opts.Create) == 0 && len(opts.Update) == 0 {
		return nil, verrors.ErrorNoPoliciesProvided
	}

	pols := iar.NewBulkPoliciesFromOptions(opts)
	reqBody, err := json.Marshal(&iar.BulkRequestBody{
		Definitions: pols,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorMarshallingData, err)
	}

	resp, err := a.Put(ctx,
		r.WithBodyBytes(reqBody),
		r.WithPath("bulk"),
		r.WithResponseField("processId"))
	if err != nil {
		return nil, err
	}

	var processID string
	if err := json.NewDecoder(resp.Body).Decode(&processID); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return &processID, nil
}

func (a *appRouteOps) UpdateApplicationListsOnPolicy(ctx context.Context, policyID string, opts ar.AddRemoveAppListOptions) (*string, error) {
	if policyID == "" {
		return nil, verrors.ErrorNoIDProvided
	}

	// Get the app route policy...
	approute, err := a.Get(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("error while getting approute policy prior to editing: %w", err)
	}

	// ... then, the app lists...
	appLists, err := newAppListsOpsFromRequester(a.Requester).List(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while searching for application lists prior to editing: %w", err)
	}

	// ... and then edit sequences by adding or removing
	appListsToRemove := [][2]string{}
	appListsToAdd := [][2]string{}
	for _, applist := range appLists {
		for _, rem := range opts.Remove {
			if rem == applist.ID {
				appListsToRemove = append(appListsToRemove, [2]string{applist.ID, applist.Name})
			}
		}
		for _, add := range opts.Add {
			if add == applist.ID {
				appListsToAdd = append(appListsToAdd, [2]string{applist.ID, applist.Name})
			}
		}
	}

	if len(appListsToRemove) > 0 {
		approute.Sequences = iar.RemoveAppListsFromSequences(approute.Sequences, appListsToRemove)
	}
	if len(appListsToAdd) > 0 {
		approute.Sequences = iar.AddAppListsToSequences(approute.Sequences, appListsToAdd)
	}

	return a.BulkUpdateCreate(ctx, ar.BulkOptions{
		Update: []*ar.Policy{approute},
	})
}
