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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
)

const (
	authThreshold = 20 * time.Minute
)

type authenticator struct {
	username string
	password string

	sync.Mutex
	lastAuth time.Time
}

func (a *authenticator) authenticate(ctx context.Context, r *Requester) error {
	a.Lock()
	defer a.Unlock()

	if time.Since(a.lastAuth) <= authThreshold {
		return nil
	}

	defer func() {
		a.lastAuth = time.Now()
	}()

	sessionID, err := getSessionID(ctx, r.httpClient, r.baseURL, a.username, a.password)
	if err != nil {
		return fmt.Errorf("error while trying to get session ID: %w", err)
	}

	xsrfToken, err := getXSRFToken(ctx, r.httpClient, r.baseURL)
	if err != nil {
		return fmt.Errorf("error while trying to get xsrf token: %w", err)
	}

	r.tokens.XsrfToken = *xsrfToken
	r.tokens.SessionID = *sessionID

	return nil
}

func getSessionID(ctx context.Context, httpClient *http.Client, baseURL url.URL, username, password string) (*string, error) {
	// Previously this function was re-using the requester, but now it is
	// a separated function, so that the "Do" function of the requester
	// can be more generalized and we can remove some checks that were
	// made specifically for this.

	const (
		pathGetSessionID   string = "j_security_check"
		cookieSessionIDKey string = "JSESSIONID"
		authBody           string = "j_username=%s&j_password=%s"
	)
	body := strings.NewReader(fmt.Sprintf(authBody, username, password))

	baseURL.Path = pathGetSessionID
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("error while creating authentication request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while performing authentication request: %w", err)
	}
	resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieSessionIDKey {
			return &cookie.Value, nil
		}
	}
	return nil, verrors.ErrorCookieSessionIDNotFound
}

func getXSRFToken(ctx context.Context, httpClient *http.Client, baseURL url.URL) (*string, error) {
	// Previously this function was re-using the requester, but now it is
	// a separated function, so that the "Do" function of the requester
	// can be more generalized and we can remove some checks that were
	// made specifically for this.

	const (
		pathGetXsrfToken string = "dataservice/client/token"
	)

	baseURL.Path = pathGetXsrfToken
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("error while creating xsrf token request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while performing authentication request: %w", err)
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
