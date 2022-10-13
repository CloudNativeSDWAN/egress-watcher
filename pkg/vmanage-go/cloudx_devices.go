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
	"strconv"

	icx "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/cloudx"
	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	cx "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/cloudx"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

type cloudxDevicesOps struct {
	*r.Requester
}

func (c *cloudxOps) Devices() *cloudxDevicesOps {
	return newCloudxDevicesOpsFromRequester(c.Requester)
}

func newCloudxDevicesOpsFromRequester(req *r.Requester) *cloudxDevicesOps {
	const (
		pathCloudxBaseURL string = "dataservice/template/cloudx"
	)

	return &cloudxDevicesOps{
		Requester: req.CloneWithNewBasePath(pathCloudxBaseURL),
	}
}

func (x *cloudxDevicesOps) listDevicesWithPath(ctx context.Context, p string) ([]*cx.Device, error) {
	devs := []*cx.Device{}

	resp, err := x.Do(ctx, r.WithPath(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var _devices []*icx.InternalDevice
	if err := json.NewDecoder(resp.Body).Decode(&_devices); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	for _, _device := range _devices {
		devs = append(devs, &cx.Device{SiteID: _device.SiteID})
	}

	return devs, nil
}

func (x *cloudxDevicesOps) ListGateways(ctx context.Context) ([]*cx.Device, error) {
	return x.listDevicesWithPath(ctx, "gatewaylist")
}

func (x *cloudxDevicesOps) ListAttachedGateways(ctx context.Context) ([]*cx.Device, error) {
	return x.listDevicesWithPath(ctx, "attachedgateway")
}

func (x *cloudxDevicesOps) ListDIAs(ctx context.Context) ([]*cx.Device, error) {
	return x.listDevicesWithPath(ctx, "dialist")
}

func (x *cloudxDevicesOps) ListAttachedDIAs(ctx context.Context) ([]*cx.Device, error) {
	return x.listDevicesWithPath(ctx, "attacheddia")
}

func (x *cloudxDevicesOps) AttachConfiguration(ctx context.Context, devices []*cx.Device) (*string, error) {
	siteIDs := []string{}

	for _, dev := range devices {
		siteIDs = append(siteIDs, dev.SiteID)
	}

	return x.AttachConfigurationToSiteIDs(ctx, siteIDs)
}

func (x *cloudxDevicesOps) AttachConfigurationToSiteIDs(ctx context.Context, siteIDs []string) (*string, error) {
	const (
		attachPath string = "dataservice/template/device/config"
	)

	ids := []int{}
	for _, id := range siteIDs {
		// vManage wants these as integer, instead of string. Yet provides
		// them as string during response. So we just have to cast them
		// back.
		_id, err := strconv.Atoi(id)
		if err != nil {
			return nil, fmt.Errorf("cannot start request: error while marshalling id %s: %w", id, err)
		}
		ids = append(ids, int(_id))
	}

	reqBody, err := json.Marshal(icx.NewAttachConfigurationRequestBody(ids))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorMarshallingData, err)
	}

	// We are using this temporary vclient because the url is different, but
	// still belongs to cloud express operations.
	attachCli := x.Requester.CloneWithNewBasePath(attachPath)
	resp, err := attachCli.Put(ctx,
		r.WithPath("attachcloudx"),
		r.WithBodyBytes(reqBody),
		r.WithResponseField("id"),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var operationID string
	if err := json.NewDecoder(resp.Body).Decode(&operationID); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return &operationID, nil
}

// // TODO: say that this will return an operation ID that will have to be
// // monitored
func (x *cloudxDevicesOps) ApplyConfigurationToAllDevices(ctx context.Context) (*string, error) {
	devs := []*cx.Device{}

	attDia, err := x.ListAttachedDIAs(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get list of attached DIAs: %w", err)
	}
	devs = append(devs, attDia...)

	attGws, err := x.ListAttachedGateways(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get list of attached gateways: %w", err)
	}
	devs = append(devs, attGws...)

	return x.AttachConfiguration(ctx, devs)
}
