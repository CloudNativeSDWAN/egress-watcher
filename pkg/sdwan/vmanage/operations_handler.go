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

package vmanage

import (
	"context"
	"fmt"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	vmanagego "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go"
	"github.com/rs/zerolog"
)

// OperationsHandler receives operations from the controller in a general
// format and "translates" with data that is specific to vManage only, and
// calls the appropriate API endpoints to reflect that data to vManage.
type OperationsHandler struct {
	client        *vmanagego.Client
	waitingWindow time.Duration
	log           zerolog.Logger
}

// NewOperationsHandler returns a new instance of the operations handler.
//
// It returns an error in case the client passed is nil or the waiting window
// contains an invalid value -- usually a value <= 0.
func NewOperationsHandler(client *vmanagego.Client, waitingWindow time.Duration, log zerolog.Logger) (*OperationsHandler, error) {
	if client == nil {
		return nil, fmt.Errorf("vManage client passed is nil")
	}

	if waitingWindow <= 0 {
		return nil, fmt.Errorf("invalid waiting window timer provided")
	}

	return &OperationsHandler{
		client:        client,
		waitingWindow: waitingWindow,
		log:           log.With().Str("worker", "Operations Handler").Logger(),
	}, nil
}

// WatchForOperations starts watching on the provided channel for operations
// to perform. It returns an error in case the channel is nil or the context
// is cancelled.
//
// Make sure to run this in another goroutine.
func (o *OperationsHandler) WatchForOperations(mainCtx context.Context, opsChan chan *sdwan.Operation) error {
	if opsChan == nil {
		return fmt.Errorf("nil channel passed")
	}

	// TODO
	return nil
}
