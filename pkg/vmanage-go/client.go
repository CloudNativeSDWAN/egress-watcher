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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

type Client struct {
	requester *r.Requester
}

type ClientOptions struct {
	SkipInsecure bool
}

type ClientOption func(*ClientOptions)

func WithSkipInsecure() ClientOption {
	return func(opts *ClientOptions) {
		opts.SkipInsecure = true
	}
}

func NewClient(ctx context.Context, baseURL, username, password string, opts ...ClientOption) (*Client, error) {
	// ------------------------------------
	// Inits and setups
	// ------------------------------------

	options := &ClientOptions{}
	for _, opt := range opts {
		opt(options)
	}

	vurl, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("base URL doesn't look valid: %w", err)
	}

	// ------------------------------------
	// Some validations
	// ------------------------------------

	// TODO: if credentials expire?
	if username == "" {
		return nil, fmt.Errorf("no username provided")
	}

	if password == "" {
		return nil, fmt.Errorf("no password provided")
	}

	// ------------------------------------
	// Create the client first
	// ------------------------------------

	cookiesJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("could not get cookie jar: %w", err)
	}

	client := &http.Client{
		Jar: cookiesJar,
	}

	if options.SkipInsecure {
		client.Transport = getInsecureSkipVerifyConfig()
	}

	// Temporary requester, just to get tokens
	_req := r.NewRequester(vurl, client, r.Tokens{})

	// ------------------------------------
	//	Test login...
	// ------------------------------------

	// Session ID
	authCtx, authCanc := context.WithTimeout(ctx, 30*time.Second)
	defer authCanc()

	sessID, err := getSessionID(authCtx, _req, username, password)
	if err != nil {
		return nil, fmt.Errorf("could not get session ID: %w", err)
	}

	// XSRF Token
	xsrfToken, err := getXSRFToken(authCtx, _req)
	if err != nil {
		return nil, fmt.Errorf("could not get xsrf token: %w", err)
	}

	req := r.NewRequester(vurl, client, r.Tokens{
		SessionID: *sessID,
		XsrfToken: *xsrfToken,
	})

	return &Client{requester: req}, nil
}

func getSessionID(ctx context.Context, req *r.Requester, username, password string) (*string, error) {
	const (
		cookieSessionIDKey string = "JSESSIONID"
		pathGetSessionID   string = "j_security_check"
		authBody           string = "j_username=%s&j_password=%s"
	)
	body := strings.NewReader(fmt.Sprintf(authBody, username, password))

	resp, err := req.Do(context.Background(),
		r.WithPOST(),
		r.WithBodyReader(body),
		r.WithPath(pathGetSessionID),
		r.WithHeader("Content-Type", "application/x-www-form-urlencoded"),
	)
	if err != nil {
		return nil, err
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieSessionIDKey {
			return &cookie.Value, nil
		}
	}
	return nil, verrors.ErrorCookieSessionIDNotFound
}

func getXSRFToken(ctx context.Context, req *r.Requester) (*string, error) {
	const (
		xsrfTokenKey     string = "XSRF-TOKEN"
		pathGetXsrfToken string = "dataservice/client/token"
	)

	resp, err := req.Do(context.Background(), r.WithPath(pathGetXsrfToken))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	token := ""
	{
		_token, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", verrors.ErrorParsingBody, err)
		}

		token = string(_token)
	}

	return &token, nil
}

func getInsecureSkipVerifyConfig() (customTransport *http.Transport) {
	customTransport = http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return
}
