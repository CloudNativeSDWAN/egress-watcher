// Copyright (c) 2022, 2023 Cisco Systems, Inc. and its affiliates
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
	"github.com/rs/zerolog"
	vb1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	servEntryCtrlName  string = "service-entry-event-handler"
	watchLabel         string = "egress-watch"
	watchEnabledLabel  string = "enabled"
	watchDisabledLabel string = "disabled"
)

type ServiceEntryOptions struct {
	WatchAllServiceEntries bool `yaml:"watchAllServiceEntries"`
}

type serviceEntryEventHandler struct {
	options *ServiceEntryOptions
	opsChan chan *sdwan.Operation
	log     zerolog.Logger
}

func NewServiceEntryController(mgr manager.Manager, options *ServiceEntryOptions, opsChan chan *sdwan.Operation, log zerolog.Logger) (controller.Controller, error) {
	if opsChan == nil {
		return nil, fmt.Errorf("no operations channel provided")
	}

	srHandler := &serviceEntryEventHandler{options, opsChan, log}

	c, err := controller.New(servEntryCtrlName, mgr, controller.Options{
		Reconciler: reconcile.Func(func(c context.Context, r reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})

	if err != nil {
		return nil, err
	}

	err = c.Watch(&source.Kind{Type: &vb1.ServiceEntry{}}, srHandler)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Update handles update events.
func (s *serviceEntryEventHandler) Update(ue event.UpdateEvent, wq workqueue.RateLimitingInterface) {
	l := s.log.With().Str("event-handler", "Update").Logger()
	defer wq.Done(ue.ObjectNew)

	curr, currok := ue.ObjectNew.(*vb1.ServiceEntry)
	old, oldok := ue.ObjectOld.(*vb1.ServiceEntry)
	if !currok || !oldok {
		return
	}

	checkCurr := checkServiceEntry(curr, s.options)
	checkOld := checkServiceEntry(old, s.options)

	switch {
	case !checkOld.passed && !checkCurr.passed:
		return
	case checkOld.passed && !checkCurr.passed:
		l.Info().Str("reason", checkCurr.reason).Msg("sending delete...")
		s.handleEvent(checkOld, sdwan.OperationRemove)
	case !checkOld.passed && checkCurr.passed:
		l.Info().Msg("sending create...")
		s.handleEvent(checkOld, sdwan.OperationCreateOrUpdate)
	}

	// -----------------------------------------------
	// Send an update
	// -----------------------------------------------

	l.Info().
		Strs("new-hosts", checkCurr.hosts).
		Strs("old-hosts", checkOld.hosts).
		Msg("sending updates...")

	s.handleEvent(checkCurr, sdwan.OperationCreateOrUpdate)

	// Delete the ones that are not there anymore...
	toRemove := checkServiceEntryResult{}
	for _, oldHost := range checkOld.hosts {
		found := false
		for _, currHost := range checkCurr.hosts {
			if oldHost == currHost {
				found = true
				break
			}
		}

		if !found {
			toRemove.hosts = append(toRemove.hosts, oldHost)
		}
	}

	if len(toRemove.hosts) > 0 {
		toRemove.port = checkOld.port
		toRemove.protocol = checkOld.protocol
		s.handleEvent(toRemove, sdwan.OperationRemove)
	}
}

// Delete handles delete events.
func (s *serviceEntryEventHandler) Delete(de event.DeleteEvent, wq workqueue.RateLimitingInterface) {
	l := s.log.With().Str("event-handler", "Delete").Logger()
	defer wq.Done(de.Object)

	se, ok := de.Object.(*vb1.ServiceEntry)
	if !ok {
		return
	}

	check := checkServiceEntry(se, s.options)
	if !check.passed {
		l.Debug().Str("reason", check.reason).Msg("skipping service entry...")
		return
	}

	s.handleEvent(check, sdwan.OperationRemove)
}

// Create handles create events.
func (s *serviceEntryEventHandler) Create(ce event.CreateEvent, wq workqueue.RateLimitingInterface) {
	l := s.log.With().Str("event-handler", "Create").Logger()
	defer wq.Done(ce.Object)

	se, ok := ce.Object.(*vb1.ServiceEntry)
	if !ok {
		return
	}

	check := checkServiceEntry(se, s.options)
	if !check.passed {
		l.Debug().Str("reason", check.reason).Msg("skipping service entry...")
		return
	}

	s.handleEvent(check, sdwan.OperationCreateOrUpdate)
}

func (s *serviceEntryEventHandler) handleEvent(res checkServiceEntryResult, eventType sdwan.OperationType) {
	for _, host := range res.hosts {
		name := replaceDots(host)
		s.opsChan <- &sdwan.Operation{
			Type:            eventType,
			ApplicationName: name,
			Data: []*sdwan.L3L4Data{
				{
					Hosts:    []string{host},
					Protocol: sdwan.Protocol(res.protocol),
					Ports:    []uint32{res.port},
				},
			},
		}
	}
}

// Generic handles generic events.
func (s *serviceEntryEventHandler) Generic(ge event.GenericEvent, wq workqueue.RateLimitingInterface) {
	// We don't really know what to do with generic events.
	// We will just ignore this.
	wq.Done(ge.Object)
}
