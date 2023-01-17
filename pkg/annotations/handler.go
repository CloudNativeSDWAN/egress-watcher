// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
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

package annotations

import (
	"context"

	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	insertedAnnotation string = "egress-watcher.cnwan.io/sdwan-populated"
	enabledAnnotation  string = "egress-watcher.cnwan.io/sdwan-enabled"
)

type handler struct {
	client.Client
	log zerolog.Logger
}

type OperationType string

const (
	// OperationEnabled means that the object has been enabled, i.e. the SDWAN
	// applied configuration and policies to optimize traffic for this
	// application.
	OperationEnabled OperationType = "enabled"
	// OperationInserted means that the object has been inserted into SDWAN's
	// database.
	OperationInserted OperationType = "inserted"
	// OperationDisabled is the opposite OperationEnabled, but the application
	// still is present in SDWAN's database.
	OperationDisabled OperationType = "disabled"
	// OperationRemoved means that the application/object was removed from
	// SDWAN's database.
	OperationRemoved OperationType = "removed"
)

// TODO: might use the definition from each of these packages instead of
// defining them as strings here.
type ObjectType string

const (
	ServiceEntry  ObjectType = "serviceentry"
	NetworkPolicy ObjectType = "networkpolicy"
)

// Operation contains data about the operation just performed by SDWAN that
// must be reflected as annotation on the object.
type Operation struct {
	// The object to annotate.
	Object Object
	// The type of the operation that was performed.
	Type OperationType
}

// Object that originated this event.
type Object struct {
	// Name of the object.
	Name types.NamespacedName
	// Type of object.
	Type ObjectType
}

func WatchForUpdates(ctx context.Context, client client.Client, opsChan chan *Operation, log zerolog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case op := <-opsChan:
			// TODO
			_ = op
		}
	}
}
