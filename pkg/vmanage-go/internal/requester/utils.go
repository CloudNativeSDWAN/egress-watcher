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
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	coolDownDuration   time.Duration = 5 * time.Second
	defaultMaxAttempts int           = 5
)

func isSessionExpired(reader io.Reader) (bool, error) {
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return false, fmt.Errorf("cannot open HTML document: %w", err)
	}

	return doc.FindMatcher(goquery.Single("body")).
		ChildrenMatcher(goquery.Single("div.loginContainer")).Length() == 1, nil
}

func isVmanageUnavailable(reader io.Reader) (bool, error) {
	const unavText = "vManage Server is not ready or temporarily unavailable"

	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return false, fmt.Errorf("cannot open HTML document: %w", err)
	}

	// NOTE! As of now, the *only* way to see if vManage is unavailable is to
	// look for an image which contains a particular text.
	// We have no other way  ¯\_(ツ)_/¯
	data := doc.FindMatcher(goquery.Single("div.loginInnerContainer")).
		ChildrenMatcher(goquery.Single("img"))

	if data.Length() == 0 {
		return false, nil
	}

	alt, _ := data.Attr("alt")
	return alt == unavText, nil
}

func coolDown(ctx context.Context) error {
	timer := time.NewTimer(coolDownDuration)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
