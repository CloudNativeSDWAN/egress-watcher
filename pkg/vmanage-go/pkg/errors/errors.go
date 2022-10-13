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

package errors

import (
	"fmt"
)

var (
	ErrorParsingBody                    error = fmt.Errorf("could not read the response body")
	ErrorUnmarshallingBody              error = fmt.Errorf("could not unmarshal the response body")
	ErrorCookieSessionIDNotFound        error = fmt.Errorf("session ID cookie not found")
	ErrorNoDefinitionIDProvided         error = fmt.Errorf("no definition ID provided")
	ErrorNoPoliciesProvided             error = fmt.Errorf("no policies provided")
	ErrorMarshallingData                error = fmt.Errorf("could not marshal data")
	ErrorNoIDProvided                   error = fmt.Errorf("no ID provided")
	ErrorNoNameProvided                 error = fmt.Errorf("no name provided")
	ErrorNoServerNamesProvided          error = fmt.Errorf("no server names provided")
	ErrorNotFound                       error = fmt.Errorf("resource not found")
	ErrorInvalidDeviceType              error = fmt.Errorf("invalid device type")
	ErrorApplicationListAlreadyIncluded error = fmt.Errorf("application list is already included in give approute policy")
	ErrorNoApplicationsProvided         error = fmt.Errorf("no applications provided")
	ErrorInvalidProbeType               error = fmt.Errorf("invalid probe type provided")
	ErrorInvalidProbeValue              error = fmt.Errorf("invalid probe value provided")
)

type VmanageError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Details string `json:"details"`
	Code    string `json:"code"`
}

func (v *VmanageError) Error() string {
	return fmt.Sprintf("code: %s, message: %s, details: %s", v.Code, v.Message, v.Details)
}
