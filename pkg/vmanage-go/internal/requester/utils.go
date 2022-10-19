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
	"strings"

	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
	"github.com/PuerkitoBio/goquery"
)

const (
	pathGetSessionID string = "j_security_check"
	pathGetXsrfToken string = "dataservice/client/token"
)

func getSessionID(ctx context.Context, req *Requester, username, password string) (*string, error) {
	const (
		cookieSessionIDKey string = "JSESSIONID"
		authBody           string = "j_username=%s&j_password=%s"
	)
	body := strings.NewReader(fmt.Sprintf(authBody, username, password))

	resp, err := req.Post(context.Background(),
		WithBodyReader(body),
		WithPath(pathGetSessionID),
		WithHeader("Content-Type", "application/x-www-form-urlencoded"),
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

func getXSRFToken(ctx context.Context, req *Requester) (*string, error) {
	resp, err := req.Do(context.Background(), WithPath(pathGetXsrfToken))
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

func isSessionExpired(reader io.Reader) (bool, error) {
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return false, fmt.Errorf("cannot open HTML document: %w", err)
	}

	return doc.FindMatcher(goquery.Single("body")).
		ChildrenMatcher(goquery.Single("div.loginContainer")).Length() == 1, nil
}
