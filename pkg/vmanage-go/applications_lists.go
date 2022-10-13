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

package vmanagego

import (
	"context"
	"encoding/json"
	"fmt"

	ial "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/applist"
	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	al "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/applist"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

type appsListsOps struct {
	*r.Requester
}

func (c *Client) ApplicationLists() *appsListsOps {
	return newAppListsOpsFromRequester(c.requester)
}

func newAppListsOpsFromRequester(req *r.Requester) *appsListsOps {
	const (
		pathAppsListBasePath string = "dataservice/template/policy/list/app"
	)

	return &appsListsOps{
		Requester: req.CloneWithNewBasePath(pathAppsListBasePath),
	}
}

func (a *appsListsOps) List(ctx context.Context) ([]*al.ApplicationList, error) {
	resp, err := a.Do(ctx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	lists := []*al.ApplicationList{}
	{
		var _lists []*ial.InternalApplicationList
		if err := json.NewDecoder(resp.Body).Decode(&_lists); err != nil {
			return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
		}

		for _, _list := range _lists {
			lists = append(lists, _list.ToApplicationList())
		}
	}

	return lists, nil
}

func (a *appsListsOps) Get(ctx context.Context, id string) (*al.ApplicationList, error) {
	if id == "" {
		return nil, verrors.ErrorNoIDProvided
	}

	resp, err := a.Do(ctx, r.WithPath(id))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var appsList *ial.InternalApplicationList
	if err := json.NewDecoder(resp.Body).Decode(&appsList); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return appsList.ToApplicationList(), nil
}

func (a *appsListsOps) GetByName(ctx context.Context, name string) (*al.ApplicationList, error) {
	if name == "" {
		return nil, verrors.ErrorNoNameProvided
	}

	lists, err := a.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get list of application lists: %w", err)
	}

	for _, list := range lists {
		if list.Name == name {
			return list, nil
		}
	}

	return nil, verrors.ErrorNotFound
}

func (a *appsListsOps) Create(ctx context.Context, opts al.CreateOptions) (*string, error) {
	// -- First, some validations
	if opts.Name == "" {
		return nil, verrors.ErrorNoNameProvided
	}
	if len(opts.Applications) == 0 {
		return nil, verrors.ErrorNoApplicationsProvided
	}
	if opts.Probe.Type != al.FQDNProbe &&
		opts.Probe.Type != al.IPProbe &&
		opts.Probe.Type != al.URLProbe {
		return nil, verrors.ErrorInvalidProbeType
	}
	if opts.Probe.Value == "" {
		// TODO: do a tougher validation (valid ip, valid url)?
		return nil, verrors.ErrorInvalidProbeValue
	}

	// -- Now, do your thing
	list := &al.ApplicationList{
		Name:         opts.Name,
		Description:  opts.Description,
		Type:         "app",
		Applications: opts.Applications,
		Probe:        opts.Probe,
		ListType:     al.Custom,
	}

	bodyReq, err := json.Marshal(ial.NewInternalApplicationList(list))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorMarshallingData, err)
	}

	resp, err := a.Post(ctx,
		r.WithBodyBytes(bodyReq),
		r.WithResponseField("listId"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var listId string
	if err := json.NewDecoder(resp.Body).Decode(&listId); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return &listId, nil
}

func (a *appsListsOps) Delete(ctx context.Context, id string) error {
	if id == "" {
		return verrors.ErrorNoIDProvided
	}

	resp, err := a.Do(ctx, r.WithPath(id), r.WithDELETE())
	if err != nil {
		return err
	}

	resp.Body.Close()
	return nil
}
