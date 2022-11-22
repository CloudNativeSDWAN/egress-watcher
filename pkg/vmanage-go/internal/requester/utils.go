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
	"fmt"
	"io"

	"github.com/PuerkitoBio/goquery"
)

func isSessionExpired(reader io.Reader) (bool, error) {
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return false, fmt.Errorf("cannot open HTML document: %w", err)
	}

	return doc.FindMatcher(goquery.Single("body")).
		ChildrenMatcher(goquery.Single("div.loginContainer")).Length() == 1, nil
}
