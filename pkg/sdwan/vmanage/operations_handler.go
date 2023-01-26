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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	vmanagego "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/applist"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/cloudx"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/customapp"
	verrors "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/errors"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/status"
	"github.com/rs/zerolog"
)

const (
	customAppListDesc string = "Managed by Egress Watcher."
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
	// ----------------------------------------
	// Init
	// ----------------------------------------

	if opsChan == nil {
		return fmt.Errorf("nil channel passed")
	}

	ops := []*sdwan.Operation{}
	waitingTimer := time.NewTimer(o.waitingWindow)
	// We stop it immediately, because we only want it to be active
	// when we have at least one operation.
	waitingTimer.Stop()

	log := o.log.With().Str("worker", "Operations Handler").Logger()
	log.Info().Msg("worker in free mode")

	// ----------------------------------------
	// Watch for the operations
	// ----------------------------------------

	for {
		select {

		// -- Need to quit?
		case <-mainCtx.Done():
			log.Err(mainCtx.Err()).Msg("cancel requested")
			waitingTimer.Stop()
			return nil

		// -- Received an operation?
		case op := <-opsChan:
			log.Info().
				Str("type", string(op.Type)).
				Str("name", op.ApplicationName).
				Strs("hosts", op.Servers).
				Msg("received operation request")

			if len(ops) == 0 {
				if o.waitingWindow > 0 {
					log.Info().Str("waiting-duration", o.waitingWindow.String()).Msg("starting waiting mode")
				}

				waitingTimer.Reset(o.waitingWindow)
			}

			ops = append(ops, op)
			for len(opsChan) > 0 && o.waitingWindow == 0 {
				// If the waiting window is disabled, then we will try to get
				// all other pending operations from the channel. This way we
				// can try to perform everything in bulk instead of one thing
				// at time: that would be disastrous for performance!
				ops = append(ops, <-opsChan)
			}

		// -- Need to go into busy mode (i.e. apply configuration on vManage)?
		case <-waitingTimer.C:
			o.busyMode(mainCtx, ops)

			// Reset
			ops = []*sdwan.Operation{}
			log.Info().Msg("back in free mode")
		}
	}
}

func (o *OperationsHandler) busyMode(ctx context.Context, operations []*sdwan.Operation) {
	// First create any custom applications
	applicationsToEnable := o.handleCreateOps(ctx, operations)

	// Apply
	pushRequired, err := o.client.CloudExpress().Applications().
		Toggle(ctx, cloudx.ToggleOptions{
			Enable: applicationsToEnable,
			// TODO: add stuff to disable
			Disable: []string{},
		})
	if err != nil {
		o.log.Err(err).Msg("cannot enable/disable custom application")
		return
	}

	if pushRequired {
		o.log.Info().Msg("applying configuration to all devices...")
		operationID, err := o.client.CloudExpress().Devices().
			ApplyConfigurationToAllDevices(ctx)
		if err != nil {
			o.log.Err(err).Msg("could not apply configuration to all devices")
			return
		}

		o.log.Info().Str("operation ID", *operationID).
			Msg("waiting for operation to complete...")
		summary, err := o.client.Status().
			WaitForOperationToFinish(ctx, status.WaitOptions{
				OperationID: *operationID,
			})
		if err != nil {
			o.log.Err(err).Msg("error while waiting for opeartion to complete")
			return
		}

		o.log.Info().Str("status", summary.Status).
			Str("operation ID", *operationID).
			Msg("applied configuration to all devices")
	}
}

func (o *OperationsHandler) handleCreateOps(mainCtx context.Context, operations []*sdwan.Operation) []string {
	appListsToEnable := []string{}

	// ----------------------------------------
	// Create the custom applications (and lists)
	// ----------------------------------------

	for _, op := range operations {
		// Previously, we had a "categorization" loop which would categorize
		// operations according to the operation type to perform and later
		// pass only the relevant data to the create, update, or delete
		// functions. We're not going to have thousands of operations to
		// justify an algorithm like that, so we just skip them instead.
		if op.Type != sdwan.OperationAdd {
			continue
		}

		for _, serverName := range op.Servers {
			// -- First create the application
			appID, err := func() (string, error) {
				ctx, canc := context.WithTimeout(mainCtx, 30*time.Second)
				defer canc()

				return o.createCustomApplication(ctx, serverName)
			}()
			if err != nil {
				// logging is done in the function
				continue
			}

			// -- Then create the custom application list
			_, err = func() (string, error) {
				ctx, canc := context.WithTimeout(mainCtx, 30*time.Second)
				defer canc()

				return o.createCustomApplicationList(ctx, serverName, appID)
			}()
			if err != nil {
				// logging is done in the function
				// TODO: delete the custom application if this didn't go right.
				continue
			}

			appListsToEnable = append(appListsToEnable, replaceDots(serverName))
		}
	}

	return appListsToEnable
}

// replaceDots replaces all the dots in a name with underscores.
//
// This is just a shorthand function used to return a suitable application
// or application list name from a server name.
func replaceDots(hostName string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(hostName, ".", "_"),
		"*", "_")
}

func (o *OperationsHandler) createCustomApplication(ctx context.Context, serverName string) (string, error) {
	name := replaceDots(serverName)
	l := o.log.With().Str("name", name).Str("hostname", serverName).Logger()

	// -- First, check if it already exists
	existing, err := o.client.CustomApplications().GetByName(ctx, name)
	switch {
	case err == nil:
		l.Info().Msg("a custom application with this name already exists")

		for _, servName := range existing.ServerNames {
			if servName == serverName {
				return existing.ID, nil
			}
		}

		l.Warn().Msg("existing custom application does not contain server " +
			"name included in resource")

		return existing.ID, nil
	case !errors.Is(err, verrors.ErrorNotFound):
		l.Err(err).
			Msg("cannot check if application already exists: skipping...")
		return "", fmt.Errorf("cannot check if application already exists: "+
			"%w", err)
	default:
		l.Debug().Msg("creating custom application...")
	}

	// -- Create the custom application
	appID, err := o.client.CustomApplications().
		Create(ctx, customapp.CreateUpdateOptions{
			Name:        name,
			ServerNames: []string{serverName},
			// TODO: handle IPs, protocol and port
			L3L4Attributes: customapp.L3L4Attributes{},
		})
	if err != nil {
		return "", err
	}

	l.Info().Str("application-id", *appID).
		Msg("custom application successfully created")
	return *appID, nil
}

func (o *OperationsHandler) createCustomApplicationList(ctx context.Context, serverName, appID string) (string, error) {
	name := replaceDots(serverName)
	l := o.log.With().Str("name", name).Logger()

	// -- First, check if it already exists
	existing, err := o.client.ApplicationLists().GetByName(ctx, name)
	switch {
	case err == nil:
		l.Info().Msg("a custom application list with this name already exists")

		for _, apps := range existing.Applications {
			if apps.ID == appID {
				return "", nil
			}
		}

		l.Warn().Str("application-id", appID).
			Msg("existing custom application list does not include " +
				"requested application ID: no further action will be taken")
		return "", fmt.Errorf("custom application list does not include " +
			"app ID")

	case !errors.Is(err, verrors.ErrorNotFound):
		l.Err(err).
			Msg("cannot check if custom application list already exists: " +
				"skipping...")

		return "", fmt.Errorf("cannot check if application already exists: "+
			"%w", err)
	default:
		l.Debug().Msg("creating custom application list...")
	}

	applistID, err := o.client.ApplicationLists().
		Create(ctx, applist.CreateUpdateOptions{
			Name:        name,
			Description: customAppListDesc,
			Applications: []applist.Application{
				{
					Name: name,
					ID:   appID,
				},
			},
			// TODO: provide a way to define custom probes.
			Probe: applist.Probe{
				Type:  applist.FQDNProbe,
				Value: serverName,
			},
		})

	if err != nil {
		l.Err(err).Msg("cannot create custom application list")
		return "", fmt.Errorf("cannot create custom application list: %w", err)
	}

	return *applistID, nil
}
