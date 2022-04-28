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

package sdwan

import "fmt"

type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Details string `json:"details"`
	Code    string `json:"code"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("Code: %s, Message: %s, Details: %s", e.Code, e.Message, e.Details)
}
