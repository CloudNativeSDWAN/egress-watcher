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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/status"
)

const (
	deviceStatusPath    string        = "device/action/status"
	defaultStatusTicker time.Duration = 5 * time.Second
)

type statusOps struct {
	vclient *Client
}

func (c *Client) Status() *statusOps {
	return &statusOps{vclient: c}
}

func (s *statusOps) GetDeviceStatusSummary(ctx context.Context, actionID string) (*status.Summary, error) {
	if actionID == "" {
		return nil, fmt.Errorf("no action ID provided")
	}

	// --------------------------------
	// Prepare and make the request
	// --------------------------------

	u := url.URL{Path: path.Join(deviceStatusPath, actionID)}
	_, bodyResp, err := s.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}

	// --------------------------------
	// Parse the response
	// --------------------------------

	var summary status.Summary
	{
		data, err := getRawMessageFromResponseBody(bodyResp, "summary")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &summary); err != nil {
			return nil, fmt.Errorf("could not unmarshal response: %w", err)
		}
	}

	return &summary, nil
}

// WaitUntilOperationCompletes regularly gets summary status of an opeartion
// defined by the operation ID.
//
// It returns when an error was found, the operation went into "done" status
// or the context has expired.
func (s *statusOps) WaitUntilOperationCompletes(ctx context.Context, operationID string) error {
	if operationID == "" {
		return fmt.Errorf("no status id provided")
	}

	tick := time.NewTicker(defaultStatusTicker)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			summary, err := s.GetDeviceStatusSummary(ctx, operationID)
			if err != nil {
				tick.Stop()
				return fmt.Errorf("could not get summary: %w", err)
			}

			switch summary.Status {
			case "done":
				return nil
			case "in_progress":
				continue
			default:
				return fmt.Errorf("unknown status: %s", summary.Status)
			}
		}
	}
}
