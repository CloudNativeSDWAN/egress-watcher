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
	"strings"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/rs/zerolog"
	netv1b1 "istio.io/api/networking/v1beta1"
	vb1 "istio.io/client-go/pkg/apis/networking/v1beta1"
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

	currParsedHosts := getHosts(curr)
	oldParsedHosts := getHosts(old)

	currHosts := map[string]bool{}
	for _, currHost := range currParsedHosts {
		currHosts[currHost] = true
	}
	currProto, currPort := getServiceEntryPortocolAndPort(curr.Spec.Ports)

	oldHosts := map[string]bool{}
	for _, oldHost := range oldParsedHosts {
		oldHosts[oldHost] = true
	}
	oldProto, oldPort := getServiceEntryPortocolAndPort(old.Spec.Ports)

	shouldWatchNow := shouldWatchLabel(curr.Labels, s.options.WatchAllServiceEntries)
	shouldWatchBefore := shouldWatchLabel(old.Labels, s.options.WatchAllServiceEntries)

	// -----------------------------------------------
	// Determine if this event should be skipped
	// -----------------------------------------------

	switch {
	case !shouldWatchBefore && !shouldWatchNow:
		// Wasn't being watched and still isn't
	case old.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL &&
		curr.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL:
		// Wasn't MESH_EXTERNAL and still isn't
	case old.Spec.Resolution != netv1b1.ServiceEntry_DNS &&
		curr.Spec.Resolution != netv1b1.ServiceEntry_DNS:
		// Wasn't DNS and still isn't
	case len(oldHosts) == 0 && len(currHosts) == 0:
		// Had no valid hosts and still hasn't
		return
	}

	// -----------------------------------------------
	// Determine if we should remove this
	// -----------------------------------------------

	mustBeRemoved := func() (remove bool, reason string) {
		switch {
		case !shouldWatchNow:
			remove, reason = true, "no watch enabled"
		case curr.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL:
			remove, reason = true, "MESH_INTERNAL detected"
		case curr.Spec.Resolution != netv1b1.ServiceEntry_DNS:
			remove, reason = true, "non-DNS resolution detected"
		case len(currHosts) == 0:
			remove, reason = true, "no valid hosts found"
		}

		return
	}

	if remove, reason := mustBeRemoved(); remove {
		l.Info().Str("reason", reason).Msg("sending delete...")
		for host := range oldHosts {
			s.opsChan <- &sdwan.Operation{
				Type:            sdwan.OperationRemove,
				ApplicationName: curr.Name,
				Server:          host,
			}
		}
		return
	}

	// -----------------------------------------------
	// Send an update
	// -----------------------------------------------

	l.Info().
		Strs("new-hosts", currParsedHosts).
		Strs("old-hosts", oldParsedHosts).
		Msg("sending updates...")

	// Delete the ones that are not there anymore...
	for host := range oldHosts {
		if _, exists := currHosts[host]; !exists {
			s.opsChan <- &sdwan.Operation{
				Type:            sdwan.OperationRemove,
				ApplicationName: curr.Name,
				Server:          host,
			}
		}
	}

	// ... and add the new ones
	for host := range currHosts {
		if _, exists := oldHosts[host]; !exists || (currProto != oldProto || currPort != oldPort) {
			s.opsChan <- &sdwan.Operation{
				Type:            sdwan.OperationCreateOrUpdate,
				ApplicationName: curr.Name,
				Server:          host,
				Protocol:        currProto,
				Port:            currPort,
			}
		}
	}
}

// Delete handles delete events.
func (s *serviceEntryEventHandler) Delete(de event.DeleteEvent, wq workqueue.RateLimitingInterface) {
	defer wq.Done(de.Object)

	se, ok := de.Object.(*vb1.ServiceEntry)
	if !ok {
		return
	}

	if !shouldWatchLabel(se.Labels, s.options.WatchAllServiceEntries) {
		// Wasn't being watched anyways
		return
	}

	if se.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL ||
		se.Spec.Resolution != netv1b1.ServiceEntry_DNS {
		// Wasn't being watched anyways
		return
	}

	parsedHosts := getHosts(se)
	if len(parsedHosts) == 0 {
		// Didn't have any valid hosts anyways.
		return
	}

	for _, host := range parsedHosts {
		s.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationRemove,
			ApplicationName: se.Name,
			Server:          host,
		}
	}
}

// Create handles create events.
func (s *serviceEntryEventHandler) Create(ce event.CreateEvent, wq workqueue.RateLimitingInterface) {
	l := s.log.With().Str("event-handler", "Create").Logger()
	defer wq.Done(ce.Object)

	se, ok := ce.Object.(*vb1.ServiceEntry)
	if !ok {
		return
	}

	if !shouldWatchLabel(se.Labels, s.options.WatchAllServiceEntries) {
		return
	}

	parsedHosts := getHosts(se)
	if len(parsedHosts) == 0 {
		l.Debug().Msg("no valid hosts detected: skipping...")
		return
	}

	l = l.With().Strs("hosts", parsedHosts).Logger()
	l.Info().Msg("reconciling service entry...")

	if se.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL {
		l.Info().Msg("service entry location is not MESH_EXTERNAL: skipping...")
		return
	}

	if se.Spec.Resolution != netv1b1.ServiceEntry_DNS {
		l.Info().Msg("service entry resolution is not DNS: skipping...")
		return
	}

	protocol, port := getServiceEntryPortocolAndPort(se.Spec.Ports)
	for _, host := range parsedHosts {
		s.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationCreateOrUpdate,
			ApplicationName: se.Name,
			Server:          host,
			Port:            port,
			Protocol:        protocol,
		}
	}
}

// Generic handles generic events.
func (s *serviceEntryEventHandler) Generic(ge event.GenericEvent, wq workqueue.RateLimitingInterface) {
	// We don't really know what to do with generic events.
	// We will just ignore this.
	wq.Done(ge.Object)
}

func shouldWatchLabel(labels map[string]string, watchAllByDefault bool) bool {
	switch labels[watchLabel] {
	case watchEnabledLabel:
		return true
	case watchDisabledLabel:
		return false
	default:
		return watchAllByDefault
	}
}

func getHosts(se *vb1.ServiceEntry) (hosts []string) {
	for _, host := range se.Spec.Hosts {
		if len(validation.IsDNS1123Subdomain(host)) == 0 {
			hosts = append(hosts, host)
		}
	}

	return hosts
}

func getServiceEntryPortocolAndPort(ports []*netv1b1.Port) (string, uint32) {
	var (
		protocol string
		port     uint32
	)

	for _, sePort := range ports {
		switch strings.ToLower(sePort.Protocol) {
		case "https":
			// HTTPS has the priority
			return "https", sePort.Number
		case "http":
			// HTTP has second priority: is stored but not returned because
			// we want to see if maybe we also have https in other iterations.
			protocol, port = "http", sePort.Number
		case "mongo":
			// mongo is not supported
			continue
		default:
			if protocol == "" {
				// Everything else has lowest priority, so it will be added
				// only if http is not there.
				protocol, port = "https", sePort.Number
			}
		}

	}

	return protocol, port
}
