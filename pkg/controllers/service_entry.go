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
	"reflect"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/annotations"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/rs/zerolog"
	netv1b1 "istio.io/api/networking/v1beta1"
	vb1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	"k8s.io/apimachinery/pkg/types"
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

	oldHosts := map[string]bool{}
	for _, oldHost := range oldParsedHosts {
		oldHosts[oldHost] = true
	}

	if !shouldWatchLabel(curr.Labels, s.options.WatchAllServiceEntries) {
		if !shouldWatchLabel(old.Labels, s.options.WatchAllServiceEntries) {
			return
		}

		l.Info().Str("reason", "no watch enabled").Msg("sending delete...")
		s.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationRemove,
			ApplicationName: curr.Name,
			Servers:         oldParsedHosts,
			OriginalObject: annotations.Object{
				Name: types.NamespacedName{Name: curr.Name, Namespace: curr.Namespace},
				Type: annotations.ServiceEntry,
			},
		}
		return
	}

	// TODO: this part is a bit complicated and must be taken care with much
	// more attention, especially if the watchAll changes. Right now it works,
	// but it will be probably refactored in a cleaner and more understandable
	// way.
	if curr.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL {
		if s.options.WatchAllServiceEntries {
			if old.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL {
				return
			}

			l.Info().Str("reason", "MESH_INTERNAL detected").Msg("sending delete...")
			s.opsChan <- &sdwan.Operation{
				Type:            sdwan.OperationRemove,
				ApplicationName: curr.Name,
				Servers:         oldParsedHosts,
				OriginalObject: annotations.Object{
					Name: types.NamespacedName{Name: curr.Name, Namespace: curr.Namespace},
					Type: annotations.ServiceEntry,
				},
			}
			return
		}

		if old.Spec.Location == netv1b1.ServiceEntry_MESH_EXTERNAL {
			return
		}
		l.Warn().Strs("hosts", currParsedHosts).Msg("service entry location is not MESH_EXTERNAL")
	} else {
		if s.options.WatchAllServiceEntries {
			if old.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL {
				l.Info().Str("reason", "change to MESH_EXTERNAL from MESH_INTERNAL").
					Strs("new-hosts", currParsedHosts).
					Strs("old-hosts", oldParsedHosts).
					Msg("sending update...")

				// First, delete...
				s.opsChan <- &sdwan.Operation{
					Type:            sdwan.OperationRemove,
					ApplicationName: curr.Name,
					Servers:         oldParsedHosts,
					OriginalObject: annotations.Object{
						Name: types.NamespacedName{Name: curr.Name, Namespace: curr.Namespace},
						Type: annotations.ServiceEntry,
					},
				}

				// ... then, add
				s.opsChan <- &sdwan.Operation{
					Type:            sdwan.OperationAdd,
					ApplicationName: curr.Name,
					Servers:         currParsedHosts,
					OriginalObject: annotations.Object{
						Name: types.NamespacedName{Name: curr.Name, Namespace: curr.Namespace},
						Type: annotations.ServiceEntry,
					},
				}
			}
		}
	}

	if curr.Spec.Resolution != netv1b1.ServiceEntry_DNS {
		l.Warn().Strs("hosts", currParsedHosts).Msg("service entry resolution is not DNS")
	}

	if len(currParsedHosts) == 0 {
		if len(oldParsedHosts) == 0 {
			return
		}

		l.Info().Str("reason", "no valid hosts").Msg("sending delete...")
		s.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationRemove,
			ApplicationName: curr.Name,
			Servers:         oldParsedHosts,
			OriginalObject: annotations.Object{
				Name: types.NamespacedName{Name: curr.Name, Namespace: curr.Namespace},
				Type: annotations.ServiceEntry,
			},
		}

		return
	}

	if reflect.DeepEqual(currHosts, oldHosts) {
		return
	}

	l.Info().Str("reason", "different hosts").
		Strs("new-hosts", currParsedHosts).
		Strs("old-hosts", oldParsedHosts).
		Msg("sending update...")

	// First, delete...
	s.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationRemove,
		ApplicationName: curr.Name,
		Servers:         oldParsedHosts,
		OriginalObject: annotations.Object{
			Name: types.NamespacedName{Name: curr.Name, Namespace: curr.Namespace},
			Type: annotations.ServiceEntry,
		},
	}

	// ... then, add
	s.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationAdd,
		ApplicationName: curr.Name,
		Servers:         currParsedHosts,
		OriginalObject: annotations.Object{
			Name: types.NamespacedName{Name: curr.Name, Namespace: curr.Namespace},
			Type: annotations.ServiceEntry,
		},
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
		return
	}

	parsedHosts := getHosts(se)
	if len(parsedHosts) == 0 {
		return
	}

	if se.Spec.Location != netv1b1.ServiceEntry_MESH_EXTERNAL && s.options.WatchAllServiceEntries {
		return
	}

	s.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationRemove,
		ApplicationName: se.Name,
		Servers:         parsedHosts,
		OriginalObject: annotations.Object{
			Name: types.NamespacedName{Name: se.Name, Namespace: se.Namespace},
			Type: annotations.ServiceEntry,
		},
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
		if s.options.WatchAllServiceEntries {
			l.Info().Msg("service entry location is not MESH_EXTERNAL: skipping...")
			return
		} else {
			l.Warn().Msg("service entry location is not MESH_EXTERNAL")
		}
	}

	if se.Spec.Resolution != netv1b1.ServiceEntry_DNS {
		l.Warn().Msg("service entry resolution is not DNS")
	}

	s.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationAdd,
		ApplicationName: se.Name,
		Servers:         parsedHosts,
		OriginalObject: annotations.Object{
			Name: types.NamespacedName{Name: se.Name, Namespace: se.Namespace},
			Type: annotations.ServiceEntry,
		},
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
