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
	"io"
	"net/http"
	"net/url"
	"path"
)

type RequestOptions struct {
	method      string
	path        string
	body        io.Reader
	headers     http.Header
	respField   string
	queryParams url.Values
	reAuth      bool
	maxAttempts int
	currAttempt int
}

type WithRequestOption func(r *RequestOptions)

func WithGET() WithRequestOption {
	return func(r *RequestOptions) {
		r.method = http.MethodGet
	}
}

func WithPUT() WithRequestOption {
	return func(r *RequestOptions) {
		r.method = http.MethodPut
	}
}

func WithPOST() WithRequestOption {
	return func(r *RequestOptions) {
		r.method = http.MethodPost
	}
}

func WithDELETE() WithRequestOption {
	return func(r *RequestOptions) {
		r.method = http.MethodDelete
	}
}

func WithBodyBytes(body []byte) WithRequestOption {
	return func(r *RequestOptions) {
		r.body = bytes.NewReader(body)
	}
}

func WithBodyReader(body io.Reader) WithRequestOption {
	return func(r *RequestOptions) {
		r.body = body
	}
}

func WithPath(urlPath string) WithRequestOption {
	return func(r *RequestOptions) {
		r.path = path.Join(urlPath)
	}
}

func WithHeader(key string, values ...string) WithRequestOption {
	return func(r *RequestOptions) {
		if len(r.headers) == 0 {
			r.headers = http.Header{}
		}

		for _, value := range values {
			r.headers.Add(key, value)
		}
	}
}

func WithResponseField(field string) WithRequestOption {
	return func(r *RequestOptions) {
		r.respField = field
	}
}

func WithQueryParameter(key string, values ...string) WithRequestOption {
	return func(r *RequestOptions) {
		if len(r.queryParams) == 0 {
			r.queryParams = url.Values{}
		}

		for _, value := range values {
			r.queryParams.Add(key, value)
		}
	}
}

func withReauth() WithRequestOption {
	return func(r *RequestOptions) {
		r.reAuth = true
	}
}

func WithNoRetry() WithRequestOption {
	return func(r *RequestOptions) {
		r.maxAttempts = 0
	}
}

func withIncreaseAttempt() WithRequestOption {
	return func(r *RequestOptions) {
		r.currAttempt++
	}
}
