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

package controllers

import (
	"context"
	"fmt"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	v1alpha1 "github.com/openservicemesh/osm/pkg/apis/policy/v1alpha1"
	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/util/validation"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	osmCtrlName string = "openservicemesh-event-handler"
)

type osmEventHandler struct {
	opsChan chan *sdwan.Operation
	log     zerolog.Logger
}

func NewOSMcontroller(mgr manager.Manager, opsChan chan *sdwan.Operation, log zerolog.Logger) (controller.Controller, error) {
	if opsChan == nil {
		return nil, fmt.Errorf("no operations channel provided")
	}

	osmHandler := &osmEventHandler{opsChan, log}

	c, err := controller.New(osmCtrlName, mgr, controller.Options{
		Reconciler: reconcile.Func(func(c context.Context, r reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})

	if err != nil {
		return nil, err
	}

	err = c.Watch(&source.Kind{Type: &v1alpha1.Egress{}}, osmHandler)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Update handles update events.
func (n *osmEventHandler) Update(ue event.UpdateEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Update").Logger()
	defer wq.Done(ue.ObjectNew)

	l.Info().Msg("updating...")
}

// Delete handles delete events.
func (n *osmEventHandler) Delete(de event.DeleteEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Delete").Logger()
	defer wq.Done(de.Object)

	l.Info().Msg("deleting...")
}

// Create handles create events.
func (o *osmEventHandler) Create(ce event.CreateEvent, wq workqueue.RateLimitingInterface) {
	l := o.log.With().Str("event-handler", "Create").Logger()
	defer wq.Done(ce.Object)

	osm, ok := ce.Object.(*v1alpha1.Egress)
	if !ok {
		l.Error().Msg("could not unmarshal openservicemesh!")
		return
	}

	parsedHosts := getOsmHosts(osm)

	if len(parsedHosts) == 0 {
		l.Debug().Msg("no valid IPs detected: skipping...")
		return
	}

	if len(parsedHosts) > 8 {
		l.Warn().Msg("Hosts should not be more than 8. Only the first 8 would be selected")
		parsedHosts = parsedHosts[0:8]
	}

	l = l.With().Strs("Hosts", parsedHosts).Logger()

	o.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationAdd,
		ApplicationName: osm.Name,
		Servers:         parsedHosts,
	}
}

// Generic handles generic events.
func (n *osmEventHandler) Generic(ge event.GenericEvent, wq workqueue.RateLimitingInterface) {
	// We don't really know what to do with generic events.
	// We will just ignore this.
	wq.Done(ge.Object)
}

func getOsmHosts(o *v1alpha1.Egress) (hosts []string) {
	for _, host := range o.Spec.Hosts {
		if len(validation.IsDNS1123Subdomain(host)) == 0 {
			hosts = append(hosts, host)
		}
	}

	return hosts
}
