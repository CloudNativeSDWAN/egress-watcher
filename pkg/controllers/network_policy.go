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
//
// Credits to @tomilashy for the original version of this controller.

package controllers

import (
	"context"
	"fmt"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/rs/zerolog"
	netv1 "k8s.io/api/networking/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	netPolsCtrlName string = "network-policy-event-handler"
	// TODO: this error is now temporarily disabled, as it may be irrelevant
	// now that we distinguish ports and protocols as well.
	// errTooManyIPs   string = "exceeded number of supported IPs (8)"
)

type NetworkPolicyOptions struct {
	WatchAllNetworkPolicies bool `yaml:"watchAllNetworkPolicies"`
}

type netPolsEventHandler struct {
	options *NetworkPolicyOptions
	opsChan chan *sdwan.Operation
	log     zerolog.Logger
}

func NewNetworkPolicyController(mgr manager.Manager, options *NetworkPolicyOptions, opsChan chan *sdwan.Operation, log zerolog.Logger) (controller.Controller, error) {
	if opsChan == nil {
		return nil, fmt.Errorf("no operations channel provided")
	}

	npHandler := &netPolsEventHandler{options, opsChan, log}

	c, err := controller.New(netPolsCtrlName, mgr, controller.Options{
		Reconciler: reconcile.Func(func(c context.Context, r reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})

	if err != nil {
		return nil, err
	}

	err = c.Watch(&source.Kind{Type: &netv1.NetworkPolicy{}}, npHandler)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Update handles update events.
func (n *netPolsEventHandler) Update(ue event.UpdateEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Update").Logger()
	defer wq.Done(ue.ObjectNew)

	curr, currok := ue.ObjectNew.(*netv1.NetworkPolicy)
	old, oldok := ue.ObjectOld.(*netv1.NetworkPolicy)
	if !currok || !oldok {
		return
	}

	oldData := getIpsAndPortsFromNetworkPolicy(old)
	currData := getIpsAndPortsFromNetworkPolicy(curr)

	oldWatch := shouldWatchLabel(curr.Labels, n.options.WatchAllNetworkPolicies)
	currWatch := shouldWatchLabel(old.Labels, n.options.WatchAllNetworkPolicies)

	if !oldWatch && !currWatch {
		return
	}

	if len(oldData) == 0 && len(currData) == 0 {
		return
	}

	if (oldWatch && !currWatch) || (len(oldData) > 0 && len(currData) == 0) {
		l.Info().Msg("sending delete...")
		n.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationRemove,
			ApplicationName: old.Name,
			Data:            oldData,
		}

		return
	}

	l.Info().Msg("sending update...")
	n.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationCreateOrUpdate,
		ApplicationName: curr.Name,
		Data:            currData,
	}
}

// Delete handles delete events.
func (n *netPolsEventHandler) Delete(de event.DeleteEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Delete").Logger()
	defer wq.Done(de.Object)

	netpol, ok := de.Object.(*netv1.NetworkPolicy)
	if !ok {
		l.Error().Msg("could not unmarshal network policy!")
		return
	}

	if !shouldWatchLabel(netpol.Labels, n.options.WatchAllNetworkPolicies) {
		return
	}

	data := getIpsAndPortsFromNetworkPolicy(netpol)
	if len(data) == 0 {
		l.Debug().Msg("no valid data detected: skipping...")
		return
	}

	n.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationRemove,
		ApplicationName: netpol.Name,
		Data:            data,
	}
}

// Create handles create events.
func (n *netPolsEventHandler) Create(ce event.CreateEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Create").Logger()
	defer wq.Done(ce.Object)

	netpol, ok := ce.Object.(*netv1.NetworkPolicy)
	if !ok {
		l.Error().Msg("could not unmarshal network policy!")
		return
	}

	if !shouldWatchLabel(netpol.Labels, n.options.WatchAllNetworkPolicies) {
		return
	}

	data := getIpsAndPortsFromNetworkPolicy(netpol)
	if len(data) == 0 {
		l.Debug().Msg("no valid data detected: skipping...")
		return
	}

	n.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationCreateOrUpdate,
		ApplicationName: netpol.Name,
		Data:            data,
	}
}

// Generic handles generic events.
func (n *netPolsEventHandler) Generic(ge event.GenericEvent, wq workqueue.RateLimitingInterface) {
	// We don't really know what to do with generic events.
	// We will just ignore this.
	wq.Done(ge.Object)
}
