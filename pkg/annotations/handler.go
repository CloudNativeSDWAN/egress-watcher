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
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"istio.io/client-go/pkg/apis/networking/v1beta1"
	v1 "k8s.io/api/networking/v1"
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

func WatchForUpdates(ctx context.Context, k8sclient client.Client, opsChan chan *Operation, log zerolog.Logger) error {
	h := &handler{k8sclient, log.With().Str("worker", "Annotations Handler").Logger()}

	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case op := <-opsChan:
			obj, err := h.getObject(ctx, op.Object.Name, op.Object.Type)
			if client.IgnoreNotFound(err) != nil {
				h.log.Err(err).Str("name", op.Object.Name.String()).Msg("cannot get object to annotate: skipping...")
				continue
			}

			// TODO: use the object to annotate it
			_ = obj
		}
	}
}

func (a *handler) getObject(mainCtx context.Context, name types.NamespacedName, objType ObjectType) (client.Object, error) {
	ctx, canc := context.WithTimeout(mainCtx, 30*time.Second)
	defer canc()

	switch objType {
	case ServiceEntry:
		var svcEntry v1beta1.ServiceEntry
		if err := a.Get(ctx, name, &svcEntry); err != nil {
			return nil, fmt.Errorf("cannot get object '%s': %w", name, err)
		}

		return &svcEntry, nil
	case NetworkPolicy:
		var netpol v1.NetworkPolicy
		if err := a.Get(ctx, name, &netpol); err != nil {
			return nil, fmt.Errorf("cannot get object '%s': %w", name, err)
		}

		return &netpol, nil
	default:
		return nil, fmt.Errorf("'%s' is not a valid object type", objType)
	}
}
