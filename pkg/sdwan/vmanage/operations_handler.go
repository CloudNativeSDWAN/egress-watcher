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
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/approute"
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

	// Get the *names* of the applications to disable
	applicationsToDisable := func() (disable []string) {
		for _, op := range operations {
			if op.Type != sdwan.OperationRemove {
				continue
			}

			for _, host := range op.Servers {
				disable = append(disable, replaceDots(host))
			}
		}

		return
	}()

	if len(applicationsToEnable) == 0 && len(applicationsToDisable) == 0 {
		o.log.Debug().Msg("no changes to apply, stopping here")
		return
	}

	// Apply
	pushRequired, err := o.client.CloudExpress().Applications().
		Toggle(ctx, cloudx.ToggleOptions{
			Enable:  applicationsToEnable,
			Disable: applicationsToDisable,
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

	// And finally, (re)activate the approute policies
	o.activatePolicies(ctx, applicationsToEnable, []string{})

	// Now delete the custom applications, if any
	if len(applicationsToDisable) > 0 {
		o.handleRemoveOps(ctx, operations)
	}

	o.log.Info().Msg("all done")
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

func (o *OperationsHandler) handleRemoveOps(mainCtx context.Context, operations []*sdwan.Operation) {
	toRemove := func() map[string]bool {
		toRemoveMap := map[string]bool{}
		for _, op := range operations {
			if op.Type != sdwan.OperationRemove {
				continue
			}

			for _, serverName := range op.Servers {
				toRemoveMap[replaceDots(serverName)] = true
			}
		}

		return toRemoveMap
	}()

	// First, get the list of applications. We need this because we need
	// to check if the lists are referenced somewhere else.
	listIds := map[string]*applist.ApplicationList{}
	lists, _ := o.client.ApplicationLists().List(mainCtx)
	for _, list := range lists {
		if _, exists := toRemove[list.Name]; exists {
			// TODO: also check if application is managed by someone other
			// than us, if that is not the case, then log that it won't be
			// touched.
			listIds[list.Name] = list
		}
	}

	// ----------------------------------------
	// Remove the custom applications lists
	// and associated custom applications
	// ----------------------------------------

	o.log.Info().Msg("deleting custom application lists...")
	for _, list := range listIds {
		if list.ReferenceCount > 0 {
			o.log.Warn().
				Str("name", list.Name).
				Str("reason", "referenced somewhere else").
				Int("reference-count", list.ReferenceCount).
				Msg("cannot delete this custom application list, skipping...")
			continue
		}

		if err := o.client.ApplicationLists().Delete(mainCtx, list.ID); err != nil {
			o.log.Err(err).Str("name", list.Name).
				Msg("cannot delete custom application list, skipping...")
			continue
		}

		o.log.Info().Str("name", list.Name).
			Msg("custom application list deleted successfully")

		// Get ID of apps to delete
		appIDs := []string{}
		for _, apps := range list.Applications {
			//
			appIDs = append(appIDs, apps.ID)
		}

		o.log.Info().Str("name", list.Name).
			Msg("deleting associated custom applications...")

		for _, appID := range appIDs {
			err := o.client.CustomApplications().Delete(mainCtx, appID)
			if err != nil {
				o.log.Err(err).Str("id", appID).
					Msg("cannot delete associated custom application with provided " +
						"id, skipping...")
			} else {
				o.log.Info().Str("id", appID).
					Msg("associated custom application deleted successfully")
			}
		}
	}
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

func (o *OperationsHandler) activatePolicies(ctx context.Context, appsToAdd, appsToRemove []string) {
	o.log.Info().Msg("starting to activate policies")

	appRoutePols, err := o.client.AppRoute().List(context.Background())
	if err != nil {
		o.log.Err(err).Msg("cannot get approute policies to update")
		return
	}
	o.log.Debug().Int("#", len(appRoutePols)).Msg("pulled approute policies")

	for _, arPol := range appRoutePols {
		processID, err := o.client.AppRoute().
			UpdateApplicationListsOnPolicy(ctx, arPol.ID,
				approute.AddRemoveAppListOptions{
					Add:    appsToAdd,
					Remove: appsToRemove,
				})
		if err != nil {
			o.log.Err(err).Str("id", arPol.ID).
				Msg("cannot update application list on policy")
			return
		}

		o.log.Info().Str("id", arPol.ID).
			Msg("updated application list on approute")
		o.log.Debug().Str("process-id", *processID).Msg("received process ID")

		for _, activatedID := range arPol.ActivatedByVSmartPolicies {
			vpol, err := o.client.VSmartPolicies().Get(ctx, activatedID)
			if err != nil {
				o.log.Err(err).Str("id", activatedID).
					Msg("cannot retrieve vSmart policy by ID")
				return
			}

			if err := o.client.VSmartPolicies().
				UpdateCentralPolicy(context.Background(), *vpol); err != nil {
				o.log.Err(err).Str("id", vpol.ID).
					Msg("could not update central policy")
				return
			}
			o.log.Info().Str("id", vpol.ID).Str("name", vpol.Name).
				Msg("updated vsmart policy")

			operationID, err := o.client.VSmartPolicies().
				ActivatePolicy(context.Background(), vpol.ID, *processID)
			if err != nil {
				o.log.Err(err).Str("id", vpol.ID).Str("name", vpol.Name).
					Msg("err smart activate")
				return
			}
			o.log.Info().Str("id", vpol.ID).Str("name", vpol.Name).
				Msg("activated vSmart policy")
			o.log.Debug().Str("id", *operationID).Msg("received operation ID")
			o.log.Info().Msg("waiting for operation to finish...")

			_, err = o.client.Status().WaitForOperationToFinish(ctx, status.WaitOptions{
				OperationID: *operationID,
			})
			if err != nil {
				o.log.Err(err).Msg("error while waiting for operation to finish")
				return
			}
		}
	}
}
