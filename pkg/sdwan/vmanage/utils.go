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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
)

const (
	xsrfTokenKey string = "X-XSRF-TOKEN"
)

var (
	ErrorEmptyToken   error = errors.New("no xsrf token")
	ErrorEmptySession error = errors.New("no session ID")
	// TODO: session expired error, unathenticated erorr
)

func unmarshalIDFromResponseBody(resp []byte, key string) (string, error) {
	var r map[string]string
	if err := json.Unmarshal(resp, &r); err != nil {
		return "", fmt.Errorf("could not unmarshal response body: %w", err)
	}

	val, exists := r[key]
	if !exists {
		return "", fmt.Errorf(`"%s" field not found on response`, key)
	}

	return val, nil
}

func getRawMessageFromResponseBody(resp []byte, key string) (json.RawMessage, error) {
	var objResp map[string]json.RawMessage
	if err := json.Unmarshal(resp, &objResp); err != nil {
		return nil, fmt.Errorf("could not unmarshal response: %w", err)
	}

	dataResp, exists := objResp[key]
	if !exists {
		return nil, fmt.Errorf(`"%s" field is not present in the response`, key)
	}

	return dataResp, nil
}

func (c *Client) do(ctx context.Context, method string, url url.URL, body io.Reader) (int, []byte, error) {
	if c.auth.SessionID == "" {
		return 0, nil, ErrorEmptySession
	}

	if method != http.MethodGet && c.auth.XSRFToken == "" {
		return 0, nil, ErrorEmptyToken
	}
	// /re-authenticate

	url.Scheme = c.addr.Scheme
	url.Host = c.addr.Host
	url.Path = path.Join(c.addr.Path, url.Path)

	// ----------------------------------
	// Create and perform the request
	// ----------------------------------

	req, err := http.NewRequestWithContext(ctx, method, url.String(), body)
	if err != nil {
		return 0, nil, fmt.Errorf("error while performing request: %w", err)
	}
	req.Header.Add(xsrfTokenKey, c.auth.XSRFToken)

	resp, err := c.client.Do(req)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}

		return code, nil, fmt.Errorf("error returned: %w", err)
	}

	// ----------------------------------
	// Parse the response
	// ----------------------------------

	defer resp.Body.Close()
	bodyResp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("could not read the response body: %w", err)
	}

	// Is there an error?
	// TODO: It looks like vManage only returns 200 when success. But this may
	// change in future, and this check too as a consequence.
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, bodyResp, nil
	}

	var errResp sdwan.Error
	{
		var errbody map[string]json.RawMessage
		if err := json.Unmarshal(bodyResp, &errbody); err != nil {
			return resp.StatusCode, nil, fmt.Errorf("cannot unmarshal error response: %w", err)
		}

		errBytes, exists := errbody["error"]
		if !exists {
			return resp.StatusCode, nil, fmt.Errorf("unknown error response received")
		}

		if err := json.Unmarshal(errBytes, &errResp); err != nil {
			return resp.StatusCode, nil, fmt.Errorf("cannot unmarshal error response: %w", err)
		}
	}

	return resp.StatusCode, nil, &errResp
}
