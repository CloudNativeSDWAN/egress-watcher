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

package vmanage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/cloudx"
)

const (
	listCloudxAppsPath string = "template/cloudx/manage/apps"
	attachedGwPath     string = "template/cloudx/attachedgateway"
	diaPath            string = "template/cloudx/attacheddia"
	attachCloudxPath   string = "template/device/config/attachcloudx"
)

type DeviceType string

const (
	GatewayDevice              DeviceType = "gateway"
	DirectInternetAccessDevice DeviceType = "dia"
)

type cloudxOps struct {
	vclient *Client
}

func (c *Client) CloudX() *cloudxOps {
	return &cloudxOps{vclient: c}
}

func (c *cloudxOps) ListApplications(ctx context.Context) ([]*cloudx.Application, error) {
	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	u := url.URL{Path: listCloudxAppsPath}
	_, body, err := c.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	var apps []*cloudx.Application
	{
		data, err := getRawMessageFromResponseBody(body, "data")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &apps); err != nil {
			return nil, fmt.Errorf("could not unmarshal response: %w", err)
		}
	}

	return apps, nil
}

func (c *cloudxOps) UpdateApplications(ctx context.Context, apps []*cloudx.Application) (bool, error) {
	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	jsonReq, err := json.Marshal(map[string][]*cloudx.Application{
		"appList": apps,
	})
	if err != nil {
		return false, fmt.Errorf("could not marshal request body: %w", err)
	}

	u := url.URL{Path: listCloudxAppsPath}
	_, bodyResp, err := c.vclient.do(ctx, http.MethodPut, u, bytes.NewReader(jsonReq))
	if err != nil {
		return false, err
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	pushRequired := false
	{
		var r map[string]bool
		if err := json.Unmarshal(bodyResp, &r); err != nil {
			return false, fmt.Errorf("could not marshal response body: %w", err)
		}

		pushRequired = r["pushRequired"]
	}

	return pushRequired, nil
}

func (c *cloudxOps) ListAttachedGateways(ctx context.Context) ([]*cloudx.Device, error) {
	return c.ListDevices(ctx, GatewayDevice)
}

func (c *cloudxOps) ListAttachedGatewaysSiteIDs(ctx context.Context) ([]int, error) {
	devices, err := c.ListDevices(ctx, GatewayDevice)
	if err != nil {
		return nil, fmt.Errorf("could not get list of devices: %w", err)
	}

	ids := []int{}
	for _, device := range devices {
		if id, err := strconv.Atoi(device.SiteID); err == nil {
			ids = append(ids, id)
		}
	}

	return ids, nil
}

func (c *cloudxOps) ListAttachedDIAs(ctx context.Context) ([]*cloudx.Device, error) {
	return c.ListDevices(ctx, DirectInternetAccessDevice)
}

func (c *cloudxOps) ListAttachedDIAsSiteIDs(ctx context.Context) ([]int, error) {
	devices, err := c.ListDevices(ctx, DirectInternetAccessDevice)
	if err != nil {
		return nil, fmt.Errorf("could not get list of devices: %w", err)
	}

	ids := []int{}
	for _, device := range devices {
		if id, err := strconv.Atoi(device.SiteID); err == nil {
			ids = append(ids, id)
		}
	}

	return ids, nil
}

func (c *cloudxOps) ListDevices(ctx context.Context, devType DeviceType) ([]*cloudx.Device, error) {
	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	u := url.URL{}

	switch devType {
	case GatewayDevice:
		u.Path = attachedGwPath
	case DirectInternetAccessDevice:
		u.Path = diaPath
	default:
		return nil, fmt.Errorf("invalid device type (%s)", string(devType))
	}

	_, body, err := c.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	var devices []*cloudx.Device
	{
		data, err := getRawMessageFromResponseBody(body, "data")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &devices); err != nil {
			return nil, fmt.Errorf("could not unmarshal response: %w", err)
		}
	}

	return devices, nil
}

func (c *cloudxOps) AttachConfiguration(ctx context.Context, siteIDs []int) (string, error) {
	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	if len(siteIDs) == 0 {
		return "", fmt.Errorf("no ids provided")
	}

	u := url.URL{Path: attachCloudxPath}
	var reqBody []byte
	{
		marshalled, err := json.Marshal(map[string]interface{}{
			"siteList": siteIDs,
			"isEdited": true,
		})
		if err != nil {
			return "", fmt.Errorf("error while marshaling request: %w", err)
		}

		reqBody = marshalled
	}

	_, bodyResp, err := c.vclient.do(ctx, http.MethodPut, u, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	//	Parse the response
	// --------------------------------

	return unmarshalIDFromResponseBody(bodyResp, "id")
}

// DisableApplicationsByName tries to disable the applications provided with
// the names parameter.
//
// This will first get a list of the currently enabled applications, so make
// sure you provided a good and long context.
func (c *cloudxOps) DisableApplicationsByName(ctx context.Context, names []string) (bool, error) {
	if len(names) == 0 {
		return false, fmt.Errorf("no name provided")
	}

	toDisable := map[string]bool{}
	for _, name := range names {
		toDisable[name] = true
	}

	// --------------------------------
	// First, get the list of enabled applications
	// --------------------------------

	appsToKeep := []*cloudx.Application{}
	{
		apps, err := c.ListApplications(ctx)
		if err != nil {
			return false, fmt.Errorf("could not get list of applications: %w", err)
		}

		for _, app := range apps {
			if _, exists := toDisable[app.AppType]; !exists {
				appsToKeep = append(appsToKeep, app)
			}
		}
	}

	return c.UpdateApplications(ctx, appsToKeep)
}

// EnableApplicationsByName tries to enable the applications provided with the
// apps parameter.
//
// This will first get a list of the currently enabled
// applications, so make sure you provided a good and long context.
func (c *cloudxOps) EnableApplicationsByName(ctx context.Context, names []string) (bool, error) {
	if len(names) == 0 {
		return false, fmt.Errorf("no names provided")
	}

	customApps := make([]*cloudx.Application, len(names))
	for i := 0; i < len(names); i++ {
		customApps[i] = &cloudx.Application{
			AppType:       names[i],
			LongName:      names[i],
			IsCustomApp:   true,
			PolicyEnabled: true,
		}
	}

	// --------------------------------
	// First, get the list of enabled applications
	// --------------------------------

	appsToEnable, err := c.ListApplications(ctx)
	if err != nil {
		return false, fmt.Errorf("could not get list of applications: %w", err)
	}

	for _, customApp := range customApps {
		alreadyThere := false
		for _, app := range appsToEnable {
			if app.AppType == customApp.AppType {
				alreadyThere = true
				break
			}
		}

		if !alreadyThere {
			appsToEnable = append(appsToEnable, customApp)
		}
	}

	return c.UpdateApplications(ctx, appsToEnable)
}

func (c *cloudxOps) ToggleApplicationsByName(ctx context.Context, add []string, remove []string) (bool, error) {
	if len(add) == 0 && len(remove) == 0 {
		return false, fmt.Errorf("no application names provided")
	}

	// The ones to remove
	toDisable := map[string]bool{}
	for _, name := range remove {
		toDisable[name] = true
	}

	// The ones to add
	toAdd := make([]*cloudx.Application, len(add))
	for i := 0; i < len(add); i++ {
		toAdd[i] = &cloudx.Application{
			AppType:       add[i],
			LongName:      add[i],
			IsCustomApp:   true,
			PolicyEnabled: true,
		}
	}

	// --------------------------------
	// First, get the list of enabled applications
	// --------------------------------

	currentApps, err := c.ListApplications(ctx)
	if err != nil {
		return false, fmt.Errorf("could not get list of applications: %w", err)
	}

	// Remove some
	toUpdate := []*cloudx.Application{}
	{
		for _, app := range currentApps {
			if _, exists := toDisable[app.AppType]; !exists {
				toUpdate = append(toUpdate, app)
			}
		}
	}

	// Add some
	for _, customApp := range toAdd {
		alreadyThere := false
		for _, app := range toUpdate {
			if app.AppType == customApp.AppType {
				alreadyThere = true
				break
			}
		}

		if !alreadyThere {
			toUpdate = append(toUpdate, customApp)
		}
	}

	return c.UpdateApplications(ctx, toUpdate)
}

// ApplyConfigurationToAllDevices is a convenient function that first lists
// all site IDs and then attaches the configuration to Cloud Express.
//
// Returns an error if any error happens along the way.
func (c *cloudxOps) ApplyConfigurationToAllDevices(ctx context.Context) (string, error) {
	ids := []int{}

	{
		gwIDs, err := c.ListAttachedGatewaysSiteIDs(ctx)
		if err != nil {
			return "", fmt.Errorf("cannot get list of attached gateways: %w", err)
		}

		ids = append(ids, gwIDs...)
	}

	{
		diaIDs, err := c.ListAttachedDIAsSiteIDs(ctx)
		if err != nil {
			return "", fmt.Errorf("cannot get list of attached dias: %w", err)
		}

		ids = append(ids, diaIDs...)
	}

	return c.AttachConfiguration(ctx, ids)
}
