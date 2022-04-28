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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authPath        string = "j_security_check"
	authBody        string = "j_username=%s&j_password=%s"
	cookieSessionID string = "JSESSIONID"
	authTokenPath   string = "/dataservice/client/token"

	sessionTimeoutPath string = "settings/clientSessionTimeout"
)

type auth struct {
	vclient *Client
}

func (c *Client) Auth() *auth {
	return &auth{vclient: c}
}

func getSessionID(ctx context.Context, client *http.Client, addr *url.URL, user, pass string) (string, error) {
	auth := *addr
	auth.Path = authPath

	body := strings.NewReader(fmt.Sprintf(authBody, user, pass))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, auth.String(), body)
	if err != nil {
		return "", fmt.Errorf("error while creating request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error while performing request: %w", err)
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieSessionID {
			return cookie.Value, nil
		}
	}

	return "", fmt.Errorf("no JESSIONID cookie found")
}

func getXSRFToken(ctx context.Context, client *http.Client, addr *url.URL) (string, error) {
	auth := *addr
	auth.Path = authTokenPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, auth.String(), nil)
	if err != nil {
		return "", fmt.Errorf("error while creating request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error while performing request: %w", err)
	}
	defer resp.Body.Close()

	xsrfToken, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read response body: %w", err)
	}

	return string(xsrfToken), nil
}

func (a *auth) AreTokensStillValid(ctx context.Context) (bool, error) {
	u := url.URL{Path: sessionTimeoutPath}

	status, _, err := a.vclient.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, fmt.Errorf("could not perform request: %w", err)
	}

	return status == http.StatusOK, nil
}

func (a *auth) RenewTokens(ctx context.Context) error {
	v := a.vclient

	// Session ID
	{
		sessionID, err := getSessionID(ctx, &v.client, v.addr, v.auth.Username, v.auth.Password)
		if err != nil {
			return fmt.Errorf("could not get session ID: %w", err)
		}

		v.auth.SessionID = sessionID
	}

	// XSRF Token
	{
		tokenCtx, tokenCanc := context.WithTimeout(ctx, 30*time.Second)
		token, err := getXSRFToken(tokenCtx, &v.client, v.addr)
		tokenCanc()
		if err != nil {
			return fmt.Errorf("could not get XSRF token: %w", err)
		}
		v.auth.XSRFToken = token
	}

	return nil
}
