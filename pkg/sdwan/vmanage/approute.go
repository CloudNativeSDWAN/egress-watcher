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

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/approute"
)

const (
	polDefinitionPath string = "template/policy/definition/approute"
	appRouteBulkPath  string = "template/policy/definition/approute/bulk"
)

type appRouteOps struct {
	vclient *Client
}

func (c *Client) AppRoute() *appRouteOps {
	return &appRouteOps{vclient: c}
}

func (a *appRouteOps) GetPolicy(ctx context.Context, definitionID string) (*approute.Policy, error) {
	if definitionID == "" {
		return nil, fmt.Errorf("no definition ID provided")
	}

	u := url.URL{Path: path.Join(polDefinitionPath, definitionID)}

	_, body, err := a.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	var policy approute.Policy
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("could not unmarshal response: %w", err)
	}

	return &policy, nil
}

func (a *appRouteOps) BulkUpdate(ctx context.Context, policies []*approute.Policy) (string, error) {
	// --------------------------------
	// Prepare the request
	// --------------------------------

	if len(policies) == 0 {
		return "", fmt.Errorf("no policies provided")
	}

	isCreate := false
	defs := make([]approute.Policy, len(policies))
	for i := 0; i < len(policies); i++ {
		defs[i] = *policies[i]
		defs[i].ID = &defs[i].DefinitionID
		defs[i].IsCreate = &isCreate
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"definitions": defs,
		"processId":   "",
	})
	if err != nil {
		return "", fmt.Errorf("could not marshal request body: %w", err)
	}

	u := url.URL{Path: appRouteBulkPath}
	_, bodyResp, err := a.vclient.do(ctx, http.MethodPut, u, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Prepare the request
	// --------------------------------

	return unmarshalIDFromResponseBody(bodyResp, "processId")
}

func (a *appRouteOps) ListPolicies(ctx context.Context) ([]*approute.Policy, error) {
	u := url.URL{Path: polDefinitionPath}

	_, bodyResp, err := a.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	var policies []*approute.Policy
	{
		data, err := getRawMessageFromResponseBody(bodyResp, "data")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &policies); err != nil {
			return nil, fmt.Errorf("could not unmarshal response body: %w", err)
		}
	}

	return policies, nil
}
