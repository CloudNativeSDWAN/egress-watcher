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
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
)

type Client struct {
	client http.Client
	auth   sdwan.Authentication
	addr   *url.URL
}

// NewClient returns a new vManage client with the provided options.
func NewClient(ctx context.Context, opts *sdwan.Options) (*Client, error) {
	vclient := &Client{}

	if opts == nil {
		return nil, fmt.Errorf("no options provided")
	}

	vurl, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("base URL doesn't look valid: %w", err)
	}
	vclient.addr = vurl

	// ------------------------------------
	// Some validations
	// ------------------------------------

	// TODO: on future we can also check session and token
	if opts.Authentication == nil {
		return nil, fmt.Errorf("no authentication method provided")
	}

	if opts.Authentication.Username == "" || opts.Authentication.Password == "" {
		return nil, fmt.Errorf("no username or password provided")
	}

	// ------------------------------------
	// Create the client first
	// ------------------------------------

	cookiesJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("could not get cookie jar: %w", err)
	}

	client := http.Client{
		Jar: cookiesJar,
	}

	if opts.Insecure {
		client.Transport = getInsecureSkipVerifyConfig()
	}

	vclient.client = client

	// ------------------------------------
	//	Get session ID and XSRF Token
	// ------------------------------------

	auth := opts.Authentication

	// Session ID
	{
		sessCtx, sessCanc := context.WithTimeout(ctx, 30*time.Second)
		sessionID, err := getSessionID(sessCtx, &client, vurl, auth.Username, auth.Password)
		sessCanc()
		if err != nil {
			return nil, fmt.Errorf("could not get session ID: %w", err)
		}

		auth.SessionID = sessionID
	}

	// XSRF Token
	{
		tokenCtx, tokenCanc := context.WithTimeout(ctx, 30*time.Second)
		token, err := getXSRFToken(tokenCtx, &client, vurl)
		tokenCanc()
		if err != nil {
			return nil, fmt.Errorf("could not get XSRF token: %w", err)
		}

		auth.XSRFToken = token
	}
	vclient.auth = *auth

	return vclient, nil
}

func getInsecureSkipVerifyConfig() (customTransport *http.Transport) {
	customTransport = http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return
}
