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

// Package internal contains code and types that are mostly used to marshal
// and unmarshal data sent to/received by vManage. This is done because that
// data is not always consistent, and depending on the endpoint query vManage
// may return something completely different, i.e. with different fields, names
// or types.
//
// So, this package serves as middle/temporary types where data is first
// converted from vManage, and later converted into a public, more polished
// format, i.e. the ones you can find in the "pkg" folder.
//
// Some types may be merged with the pkg folder in future, but this will depend
// on how many endpoint we will be covering at that point.
package internal
