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

package requester

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

type Requester struct {
	baseURL       url.URL
	httpClient    *http.Client
	tokens        *tokens
	authenticator *authenticator
}

type tokens struct {
	SessionID string
	XsrfToken string
}

type Authentication struct {
	Username string
	Password string
}

func NewRequester(baseURL *url.URL, httpClient *http.Client, auth *Authentication) *Requester {
	return &Requester{
		baseURL:    *baseURL,
		tokens:     &tokens{},
		httpClient: httpClient,
		authenticator: &authenticator{
			username: auth.Username,
			password: auth.Password,
		},
	}
}

func (r *Requester) Authenticate(ctx context.Context) error {
	// Using the authenticate function from the authenticator so we can do this
	// in a thread-safe way.
	return r.authenticator.authenticate(ctx, r)
}

func (r *Requester) Do(ctx context.Context, opts ...WithRequestOption) (*http.Response, error) {
	const (
		defaultRespField string = "data"
		xsrfTokenKey     string = "X-XSRF-TOKEN"
	)

	// ----------------------------------
	// Prepare options
	// ----------------------------------

	reqOptions := &RequestOptions{
		method:      http.MethodGet,
		body:        http.NoBody,
		headers:     http.Header{},
		respField:   "data",
		maxAttempts: defaultMaxAttempts,
	}

	for _, opt := range opts {
		opt(reqOptions)
	}

	if reqOptions.reAuth {
		if err := r.Authenticate(ctx); err != nil {
			return nil, fmt.Errorf("error while trying to renew session: %w", err)
		}
	}

	if _, exists := reqOptions.headers["Content-Type"]; !exists {
		reqOptions.headers.Add("Content-Type", "application/json")
	}

	if r.tokens.XsrfToken != "" {
		reqOptions.headers.Add(xsrfTokenKey, r.tokens.XsrfToken)
	}

	// Make the URL
	u := r.baseURL
	u.Path = path.Join(r.baseURL.Path, reqOptions.path)
	if len(reqOptions.queryParams) > 0 {
		u.RawQuery = reqOptions.queryParams.Encode()
	}

	// ----------------------------------
	// Create and make the request
	// ----------------------------------

	req, err := http.NewRequestWithContext(ctx, reqOptions.method, u.String(), reqOptions.body)
	if err != nil {
		return nil, fmt.Errorf("error while creating request: %w", err)
	}
	req.Header = reqOptions.headers

	// Finally, do the actual request.
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while performing request: %w", err)
	}

	// ----------------------------------
	// Parse the response
	// ----------------------------------

	bodyResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, fmt.Errorf("%w: %s", verrors.ErrorParsingBody, err)
	}

	// If we received HTML, let's try to detect what that is, maybe it is a
	// form asking us to re-authenticate?
	// So let's parse it and make the request again, but this time renew the
	// session before doing that, **but only** if we haven't already just done
	// that.
	if resp.Header.Get("content-type") != "application/json" &&
		!reqOptions.reAuth {

		bodyReader := bytes.NewReader(bodyResp)

		if expired, _ := isSessionExpired(bodyReader); expired {
			// The session has expired. Let's try to do this again, but
			// this time we retreive a new session and xsrf token, before
			// that.
			opts = append(opts, withReauth())
			return r.Do(ctx, opts...)
		}

		if unavailable, _ := isVmanageUnavailable(bodyReader); unavailable {
			if reqOptions.currAttempt == reqOptions.maxAttempts {
				resp.Body = io.NopCloser(bodyReader)
				return resp, verrors.ErrorTooManyFailedAttempts
			}

			// vManage looks unavailable, let's retry later.
			if err := coolDown(ctx); err != nil {
				return resp, err
			}

			opts = append(opts, withIncreaseAttempt())
			return r.Do(ctx, opts...)
		}
	}

	// We close and reset the body because we are going to parse and strip it
	// from all data that is not relevant, such as the html-related one.
	// We're going to re-populate it later with just the useful one.
	resp.Body.Close()
	resp.Body = nil

	rawMessage := map[string]json.RawMessage{}
	if unmarshErr := json.Unmarshal(bodyResp, &rawMessage); unmarshErr == nil {
		if data, exists := rawMessage[reqOptions.respField]; exists {
			resp.Body = io.NopCloser(bytes.NewReader(data))
		}

		if errBody, exists := rawMessage["error"]; exists {

			// This is by no means a good way to do this, but unfortunately
			// there is no documentation about error codes. So this is all we
			// have.
			if strings.Contains(strings.ToLower(string(errBody)), "failed to find") {
				return resp, verrors.ErrorNotFound
			}

			var verr verrors.VmanageError
			if parseErr := json.Unmarshal(errBody, &verr); parseErr == nil {
				err = &verr
			} else {
				resp.Body = io.NopCloser(bytes.NewReader(errBody))
				err = errors.New(string(errBody))
			}
		}
	}

	if resp.Body == nil {
		// This body does not have neither an error nor a data field and
		// this means that we don't know what kind of body this is.
		// We're going to leave the caller to parse this then.
		resp.Body = io.NopCloser(bytes.NewReader(bodyResp))
	}

	return resp, err
}

// Get is just a shortcut for Do(ctx, WithGET())
func (r *Requester) Get(ctx context.Context, opts ...WithRequestOption) (*http.Response, error) {
	opts = append(opts, WithGET())
	return r.Do(ctx, opts...)
}

// Post is just a shortcut for Do(ctx, WithPOST())
func (r *Requester) Post(ctx context.Context, opts ...WithRequestOption) (*http.Response, error) {
	opts = append(opts, WithPOST())
	return r.Do(ctx, opts...)
}

// Put is just a shortcut for Do(ctx, WithPUT())
func (r *Requester) Put(ctx context.Context, opts ...WithRequestOption) (*http.Response, error) {
	opts = append(opts, WithPUT())
	return r.Do(ctx, opts...)
}

// Delete is just a shortcut for Do(ctx, WithDELETE())
func (r *Requester) Delete(ctx context.Context, opts ...WithRequestOption) (*http.Response, error) {
	opts = append(opts, WithDELETE())
	return r.Do(ctx, opts...)
}

func (r *Requester) CloneWithNewBasePath(newPath string) *Requester {
	newRequester := *r
	newRequester.baseURL.Path = newPath

	return &newRequester
}
