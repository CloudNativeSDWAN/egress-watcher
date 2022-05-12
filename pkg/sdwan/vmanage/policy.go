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
	"path"
	"strings"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/policy"
)

const (
	FQDN string = `fqdn`

	customAppPath      string = "template/policy/customapp"
	appsListPolicyPath string = "template/policy/list/app"
	listCustomAppsPath string = "template/policy/customapp"
)

type policyOps struct {
	vclient *Client
}

func (c *Client) PolicyApplicationsList() *policyOps {
	return &policyOps{vclient: c}
}

func (p *policyOps) CreateCustomApplication(ctx context.Context, customApp *policy.CustomApplication) (string, error) {
	// -----------------------------------
	// Validations
	// -----------------------------------

	if customApp == nil {
		return "", fmt.Errorf("no custom application provided")
	}

	if customApp.Name == "" {
		return "", fmt.Errorf("no name provided")
	}

	if len(customApp.ServerNames) == 0 {
		return "", fmt.Errorf("no server names provided")
	}

	// -----------------------------------
	// Prepare and make the request
	// -----------------------------------

	u := url.URL{Path: customAppPath}
	reqBody, err := json.Marshal(customApp)
	if err != nil {
		return "", fmt.Errorf("could not marshal request body: %w", err)
	}

	_, bodyResp, err := p.vclient.do(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("could not perform request: %w", err)
	}

	return unmarshalIDFromResponseBody(bodyResp, "appId")
}

func (p *policyOps) AddApplication(ctx context.Context, app *policy.ApplicationList) (string, error) {
	// --------------------------------
	// Application validation
	// --------------------------------

	if app == nil {
		return "", fmt.Errorf("no custom application provided")
	}

	if app.Name == "" {
		return "", fmt.Errorf("no name provided")
	}

	if len(app.ApplicationEntries) == 0 {
		return "", fmt.Errorf("no entries provided")
	}

	for i, entry := range app.ApplicationEntries {
		if entry.Name == "" {
			return "", fmt.Errorf(`entry at position %d has an empty "app" field`, i)
		}
		if entry.Reference == "" {
			return "", fmt.Errorf(`entry at position %d has an empty "appRef" field`, i)
		}
	}

	if app.Endpoint == nil {
		return "", fmt.Errorf("no endpoint provided")
	}

	app.Endpoint.Type = strings.ToLower(app.Endpoint.Type)
	if app.Endpoint.Type != FQDN {
		return "", fmt.Errorf("unsupported or empty endpoint type")
	}
	if app.Endpoint.Value == "" {
		return "", fmt.Errorf("empty endpoint value provided")
	}

	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	u := url.URL{Path: appsListPolicyPath}
	reqBody, err := json.Marshal(app)
	if err != nil {
		return "", fmt.Errorf("could not marshal request body: %w", err)
	}

	_, bodyResp, err := p.vclient.do(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	return unmarshalIDFromResponseBody(bodyResp, "listId")
}

func (p *policyOps) CreatePolicyApplicationList(ctx context.Context, customApp *policy.CustomApplication) (string, error) {
	// --------------------------------
	// Application validation
	// --------------------------------

	if customApp == nil {
		return "", fmt.Errorf("no custom application provided")
	}

	if customApp.Name == "" {
		return "", fmt.Errorf("no name provided")
	}

	if customApp.ID == "" {
		return "", fmt.Errorf("no custom application ID provided")
	}

	if len(customApp.ServerNames) == 0 {
		return "", fmt.Errorf("no server names provided")
	}

	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	u := url.URL{Path: appsListPolicyPath}
	reqBody, err := json.Marshal(policy.ApplicationList{
		Name:        customApp.Name,
		Description: fmt.Sprintf("Created by egress watcher."),
		Type:        "app",
		ApplicationEntries: []*policy.ApplicationEntry{
			{
				Name:      customApp.Name,
				Reference: customApp.ID,
			},
		},
		Endpoint: &policy.Endpoint{
			Type:  FQDN,
			Value: customApp.ServerNames[0],
		},
		IsCustomApp: true,
	})
	if err != nil {
		return "", fmt.Errorf("could not marshal request body: %w", err)
	}

	_, bodyResp, err := p.vclient.do(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	return unmarshalIDFromResponseBody(bodyResp, "listId")
}

func (p *policyOps) DeleteApplication(ctx context.Context, listID string) error {
	if listID == "" {
		return fmt.Errorf("no list ID provided")
	}

	u := url.URL{Path: path.Join(appsListPolicyPath, listID)}
	_, _, err := p.vclient.do(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("could not perform request: %w", err)
	}

	return nil
}

func (p *policyOps) DeleteCustomApplication(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("no custom application ID provided")
	}

	u := url.URL{Path: path.Join(customAppPath, id)}
	_, _, err := p.vclient.do(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("could not perform request: %w", err)
	}

	return nil
}

func (p *policyOps) GetApplicationListByName(ctx context.Context, name string) (*policy.ApplicationList, error) {
	if name == "" {
		return nil, fmt.Errorf("no application name provided")
	}

	u := url.URL{Path: appsListPolicyPath}
	_, bodyResp, err := p.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	var appLists []*policy.ApplicationList
	{
		data, err := getRawMessageFromResponseBody(bodyResp, "data")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &appLists); err != nil {
			return nil, fmt.Errorf("could not unmarshal response body: %w", err)
		}
	}

	// --------------------------------
	// Search for it
	// --------------------------------

	for _, al := range appLists {
		if al.Name == name {
			return al, nil
		}
	}

	return nil, fmt.Errorf("not found")
}

func (p *policyOps) ListCustomApplications(ctx context.Context) ([]*policy.CustomApplication, error) {
	u := url.URL{Path: listCustomAppsPath}
	_, bodyResp, err := p.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	var appLists []*policy.CustomApplication
	{
		data, err := getRawMessageFromResponseBody(bodyResp, "data")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &appLists); err != nil {
			return nil, fmt.Errorf("could not unmarshal response body: %w", err)
		}
	}

	return appLists, nil
}
