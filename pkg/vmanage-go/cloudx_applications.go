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

	icx "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/cloudx"
	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	cx "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/cloudx"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

type cloudxOps struct {
	*r.Requester
}

func (c *Client) CloudExpress() *cloudxOps {
	return &cloudxOps{c.requester}
}

type cloudxAppsOps struct {
	*r.Requester
}

func (c *cloudxOps) Applications() *cloudxAppsOps {
	return newCloudxAppsOpsFromRequester(c.Requester)
}

func newCloudxAppsOpsFromRequester(req *r.Requester) *cloudxAppsOps {
	const (
		pathCloudxBaseURL string = "dataservice/template/cloudx"
	)

	return &cloudxAppsOps{
		Requester: req.CloneWithNewBasePath(pathCloudxBaseURL),
	}
}

// Only lists enabled applications!
func (a *cloudxAppsOps) List(ctx context.Context) ([]*cx.Application, error) {
	apps := map[string]*icx.InternalApplication{}

	// Get all available apps first
	{
		resp, err := a.Do(ctx, r.WithPath("availableapps"))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var _apps []*icx.InternalApplication
		if err := json.NewDecoder(resp.Body).Decode(&_apps); err != nil {
			return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
		}

		for _, _app := range _apps {
			apps[_app.AppType] = _app
		}
	}

	// Get features list
	{
		resp, err := a.Do(ctx)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var _apps []*icx.InternalApplication
		if err := json.NewDecoder(resp.Body).Decode(&_apps); err != nil {
			return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
		}

		for _, _app := range _apps {
			// Add sites data
			apps[_app.AppType].TotalSites = _app.TotalSites
			apps[_app.AppType].GoodSites = _app.GoodSites
			apps[_app.AppType].BadSites = _app.BadSites
			apps[_app.AppType].AverageSites = _app.AverageSites
		}
	}

	// From "manage/apps"
	{
		// We're doing this from another function because we're going to reuse
		// this for other operations
		_apps, err := a.listFromManage(ctx)
		if err != nil {
			return nil, err
		}

		for _, _app := range _apps {
			apps[_app.AppType].AppVPNList = _app.AppVPNList
			apps[_app.AppType].PolicyEnabled = _app.PolicyEnabled
		}
	}

	// Return it as list
	cloudxApps := []*cx.Application{}
	for _, app := range apps {
		cloudxApps = append(cloudxApps, app.ToApplication())
	}

	return cloudxApps, nil
}

func (a *cloudxAppsOps) listFromManage(ctx context.Context) ([]*icx.InternalApplication, error) {
	resp, err := a.Do(ctx, r.WithPath("manage/apps"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var _apps []*icx.InternalApplication
	if err := json.NewDecoder(resp.Body).Decode(&_apps); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return _apps, nil
}

func (a *cloudxAppsOps) UpdateApps(ctx context.Context, apps []*cx.Application) (bool, error) {
	if len(apps) == 0 {
		return false, verrors.ErrorNoApplicationsProvided
	}

	jsonReq, err := json.Marshal(icx.NewUpdateApplicationRequestBody(apps))
	if err != nil {
		return false, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	resp, err := a.Put(ctx,
		r.WithPath("manage/apps"),
		r.WithBodyBytes(jsonReq),
		r.WithResponseField("pushRequired"),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var pushRequired bool
	if err := json.NewDecoder(resp.Body).Decode(&pushRequired); err != nil {
		return false, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return pushRequired, nil
}

func (a *cloudxAppsOps) Toggle(ctx context.Context, opts cx.ToggleOptions) (bool, error) {
	if len(opts.Disable) == 0 && len(opts.Enable) == 0 {
		return false, verrors.ErrorNoApplicationsProvided
	}

	apps, err := a.List(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot get list of apps prior to toggling: %w", err)
	}

	appsToDisable := map[string]bool{}
	appsToEnable := map[string]bool{}
	for _, dis := range opts.Disable {
		appsToDisable[dis] = true
	}
	for _, en := range opts.Enable {
		appsToEnable[en] = true
	}

	appsToKeep := []*cx.Application{}
	for _, app := range apps {
		if _, toEnable := appsToEnable[app.Name]; toEnable {
			// If this must be enabled, then just simply add it.
			app.PolicyEnabled = true
			appsToKeep = append(appsToKeep, app)
			continue
		}

		_, toDisable := appsToDisable[app.Name]
		if app.SiteCounts != nil && app.SiteCounts.Total > 0 && !toDisable {
			// If this is already enabled and must not be disable...
			appsToKeep = append(appsToKeep, app)
		}
	}

	return a.UpdateApps(ctx, appsToKeep)
}
