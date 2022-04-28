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

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/vsmart"
)

const (
	vSmartPolicyDefPath    string = "template/policy/vsmart/definition"
	vSmartPolicyPath       string = "template/policy/vsmart"
	vSmartCentraPolicyPath string = "template/policy/vsmart/central"
	activatePolicyPath     string = "template/policy/vsmart/activate/central"
)

type vSmartOps struct {
	vclient *Client
}

func (c *Client) VSmart() *vSmartOps {
	return &vSmartOps{vclient: c}
}

func (s *vSmartOps) ListPolicies(ctx context.Context) ([]*vsmart.Policy, error) {
	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	u := url.URL{Path: vSmartPolicyPath}
	_, bodyResp, err := s.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	var apps []*vsmart.Policy
	{
		data, err := getRawMessageFromResponseBody(bodyResp, "data")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &apps); err != nil {
			return nil, fmt.Errorf("could not unmarshal response: %w", err)
		}
	}

	// -- Fill the policy
	for i := 0; i < len(apps); i++ {
		apps[i].Definition = &vsmart.PolicyDefinition{}

		if err := json.Unmarshal([]byte(apps[i].DefinitionJSON), apps[i].Definition); err != nil {
			return nil, fmt.Errorf("could not unmarshal definition of policy %d: %w", i, err)
		}

		apps[i].Definition.Type = apps[i].Type
		apps[i].Definition.Name = apps[i].Name
		apps[i].Definition.Description = apps[i].Description
		apps[i].Definition.IsActivated = apps[i].IsActivated
	}

	return apps, nil
}

func (s *vSmartOps) UpdateCentralPolicyByID(ctx context.Context, id string, policy *vsmart.Policy) error {
	if id == "" {
		return fmt.Errorf("no id provided")
	}
	if policy == nil {
		return fmt.Errorf("no policy provided")
	}
	if policy.Definition == nil {
		return fmt.Errorf("no policy definition provided")
	}

	u := url.URL{Path: path.Join(vSmartCentraPolicyPath, id)}
	bodyReq, err := json.Marshal(map[string]interface{}{
		"policyDescription": policy.Description,
		"policyType":        policy.Type,
		"policyName":        policy.Name,
		"policyDefinition":  policy.Definition,
		"isPolicyActivated": true,
	})
	if err != nil {
		return fmt.Errorf("could not marshal request body: %w", err)
	}

	_, _, err = s.vclient.do(ctx, http.MethodPut, u, bytes.NewReader(bodyReq))
	if err != nil {
		return fmt.Errorf("could not perform request: %w", err)
	}

	return err
}

func (s *vSmartOps) ActivatePolicyByID(ctx context.Context, policyID, processID string) (string, error) {
	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	if policyID == "" {
		return "", fmt.Errorf("no policy ID provided")
	}
	if processID == "" {
		return "", fmt.Errorf("no process ID provided")
	}

	u := url.URL{
		Path: path.Join(activatePolicyPath, policyID),
		RawQuery: func() string {
			vals := url.Values{}
			vals.Add("confirm", "true")
			return vals.Encode()
		}(),
	}

	bodyReq, err := json.Marshal(map[string]interface{}{
		"isEdited":  true,
		"processId": processID,
	})
	if err != nil {
		return "", fmt.Errorf("could not marshal request body: %w", err)
	}

	_, bodyResp, err := s.vclient.do(ctx, http.MethodPost, u, bytes.NewReader(bodyReq))
	if err != nil {
		return "", fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	return unmarshalIDFromResponseBody(bodyResp, "id")
}
