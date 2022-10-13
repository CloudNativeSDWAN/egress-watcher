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
	"path"

	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	iv "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/vsmart"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/vsmart"
)

type vsmartOps struct {
	*r.Requester
}

func (c *Client) VSmartPolicies() *vsmartOps {
	return newVsmartOpsFromRequester(c.requester)
}

func newVsmartOpsFromRequester(req *r.Requester) *vsmartOps {
	const (
		pathVsmartBaseURL string = "dataservice/template/policy/vsmart"
	)

	return &vsmartOps{
		Requester: req.CloneWithNewBasePath(pathVsmartBaseURL),
	}
}

func (v *vsmartOps) List(ctx context.Context) ([]*vsmart.Policy, error) {
	resp, err := v.Do(ctx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respPols []*iv.InternalPolicy
	if err := json.NewDecoder(resp.Body).Decode(&respPols); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	vpols := []*vsmart.Policy{}
	for _, pol := range respPols {
		vpols = append(vpols, pol.ToPolicy())
	}

	return vpols, nil
}

func (v *vsmartOps) Get(ctx context.Context, id string) (*vsmart.Policy, error) {
	if id == "" {
		return nil, verrors.ErrorNoIDProvided
	}

	pols, err := v.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot search vSmart policy with id %s: %w", id, err)
	}

	for _, pol := range pols {
		if pol.ID == id {
			return pol, nil
		}
	}

	return nil, verrors.ErrorNotFound
}

func (s *vsmartOps) UpdateCentralPolicy(ctx context.Context, policy vsmart.Policy) error {
	if policy.ID == "" {
		return verrors.ErrorNoIDProvided
	}

	bodyReq, err := json.Marshal(iv.NewUpdatePolicyRequestBody(&policy))
	if err != nil {
		return fmt.Errorf("%w: %s", verrors.ErrorMarshallingData, err)
	}

	resp, err := s.Do(ctx,
		r.WithPUT(),
		r.WithPath(path.Join("central", policy.ID)),
		r.WithBodyBytes(bodyReq),
	)
	if err != nil {
		return err
	}

	resp.Body.Close()
	return nil
}

func (s *vsmartOps) ActivatePolicy(ctx context.Context, policyID, processID string) (*string, error) {
	if policyID == "" {
		return nil, verrors.ErrorNoIDProvided
	}
	if processID == "" {
		return nil, fmt.Errorf("no process ID provided")
	}

	bodyReq, err := json.Marshal(iv.ActivatePolicyRequestBody{
		IsEdited:  true,
		ProcessID: processID,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorMarshallingData, err)
	}

	resp, err := s.Do(ctx,
		r.WithPOST(),
		r.WithPath(path.Join("activate", "central", policyID)),
		r.WithBodyBytes(bodyReq),
		r.WithQueryParameter("confirm", "true"),
		r.WithResponseField("id"),
	)
	if err != nil {
		return nil, err
	}

	var operationID string
	if err := json.NewDecoder(resp.Body).Decode(&operationID); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return &operationID, nil
}
