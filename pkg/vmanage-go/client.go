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
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	r "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/internal/requester"
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

	req := r.NewRequester(vurl, client, &r.Authentication{
		Username: username,
		Password: password,
	})

	// ------------------------------------
	//	Test login...
	// ------------------------------------

	authCtx, authCanc := context.WithTimeout(ctx, 30*time.Second)
	defer authCanc()

	if err := req.Authenticate(authCtx); err != nil {
		return nil, fmt.Errorf("cannot authenticate to vManage: %w", err)
	}

	return &Client{requester: req}, nil
}

func getInsecureSkipVerifyConfig() (customTransport *http.Transport) {
	customTransport = http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return
}
