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
	"time"

	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/status"
)

type statusOps struct {
	*r.Requester
}

func (c *Client) Status() *statusOps {
	return newStatusOpsFromRequester(c.requester)
}

func newStatusOpsFromRequester(req *r.Requester) *statusOps {
	const (
		pathDeviceActionStatusBaseURL string = "dataservice/device/action/status"
	)

	return &statusOps{
		Requester: req.CloneWithNewBasePath(pathDeviceActionStatusBaseURL),
	}
}

func (s *statusOps) GetDeviceStatusSummary(ctx context.Context, actionID string) (*status.Summary, error) {
	if actionID == "" {
		return nil, verrors.ErrorNoIDProvided
	}

	resp, err := s.Do(ctx, r.WithPath(actionID), r.WithResponseField("summary"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var summary status.Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return nil, fmt.Errorf("%w: %s", verrors.ErrorUnmarshallingBody, err)
	}

	return &summary, nil
}

func (s *statusOps) WaitForOperationToFinish(ctx context.Context, opts status.WaitOptions) (*status.Summary, error) {
	if opts.Duration == 0 {
		opts.Duration = 2 * time.Second
	}

	ticker := time.NewTicker(opts.Duration)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("error while checking operation status: %w", ctx.Err())
		case <-ticker.C:
			summary, err := s.GetDeviceStatusSummary(ctx, opts.OperationID)
			if err != nil {
				return nil, fmt.Errorf("error while checking operation status: %w", ctx.Err())
			}

			if summary.Finished() {
				return summary, nil
			}
		}
	}
}
