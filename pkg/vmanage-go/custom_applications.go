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

	ica "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/customapp"
	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	ca "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/customapp"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

type customApplicationsOps struct {
	*r.Requester
}

func (c *Client) CustomApplications() *customApplicationsOps {
	return newCustomAppOpsFromRequester(c.requester)
}

func newCustomAppOpsFromRequester(req *r.Requester) *customApplicationsOps {
	const (
		pathCustomAppBasePath string = "dataservice/template/policy/customapp"
	)

	return &customApplicationsOps{
		Requester: req.CloneWithNewBasePath(pathCustomAppBasePath),
	}
}

func (c *customApplicationsOps) List(ctx context.Context) ([]*ca.CustomApplication, error) {
	resp, err := c.Do(ctx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	apps := []*ca.CustomApplication{}
	{
		var _apps []*ica.InternalCustomApplication
		if err := json.NewDecoder(resp.Body).Decode(&_apps); err != nil {
			return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
		}

		for _, _app := range _apps {
			app, err := c.GetByID(ctx, _app.AppID)
			if err != nil {
				return nil, fmt.Errorf("error while trying to get custom application with id %s: %w", _app.AppID, err)
			}

			apps = append(apps, app)
		}
	}

	return apps, nil
}

func (c *customApplicationsOps) GetByID(ctx context.Context, id string) (*ca.CustomApplication, error) {
	if id == "" {
		return nil, verrors.ErrorNoIDProvided
	}

	resp, err := c.Do(ctx, r.WithPath(id))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var app ica.InternalCustomApplication
	if err := json.NewDecoder(resp.Body).Decode(&app); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return app.ToCustomApplication(), nil
}

func (c *customApplicationsOps) GetByName(ctx context.Context, name string) (*ca.CustomApplication, error) {
	if name == "" {
		return nil, verrors.ErrorNoNameProvided
	}

	list, err := c.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting list prior to search: %w", err)
	}

	for _, app := range list {
		if app.Name == name {
			return app, nil
		}
	}

	return nil, verrors.ErrorNotFound
}

func (c *customApplicationsOps) Create(ctx context.Context, opts ca.CreateOptions) (*string, error) {
	if opts.Name == "" {
		return nil, verrors.ErrorNoNameProvided
	}
	if len(opts.ServerNames) == 0 {
		return nil, verrors.ErrorNoServerNamesProvided
	}

	reqBody, err := json.Marshal(ica.NewInternalCustomApplication(&ca.CustomApplication{
		Name:           opts.Name,
		ServerNames:    opts.ServerNames,
		L3L4Attributes: &opts.L3L4Attributes,
	}))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorMarshallingData, err)
	}

	resp, err := c.Post(ctx, r.WithBodyBytes(reqBody), r.WithResponseField("appId"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var appId string
	if err := json.NewDecoder(resp.Body).Decode(&appId); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return &appId, nil
}

func (c *customApplicationsOps) Delete(ctx context.Context, id string) error {
	if id == "" {
		return verrors.ErrorNoIDProvided
	}

	resp, err := c.Do(ctx, r.WithDELETE(), r.WithPath(id))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	resp.Body.Close()
	return nil
}
