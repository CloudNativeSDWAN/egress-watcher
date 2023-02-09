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
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/approute"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/policy"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan/vmanage/types/vsmart"
	"github.com/rs/zerolog"
)

const (
	defaultOpTimeout     time.Duration = 5 * time.Minute
	defaultReauthTimeout time.Duration = 30 * time.Second
)

func (v *Client) WatchForOperations(mainCtx context.Context, opsChan chan *sdwan.Operation, waitingWindow time.Duration, log zerolog.Logger) error {
	toRemove, toAdd := []*sdwan.Operation{}, []*sdwan.Operation{}

	// We stop it immediately, because we only want it to be active
	// when we have at least one operation.
	waitingTimer := time.NewTimer(waitingWindow)
	waitingTimer.Stop()

	log.Info().Msg("worker in free mode")

	for {
		select {
		case <-mainCtx.Done():
			log.Info().Msg("cancel requested")
			return nil
		case op := <-opsChan:
			log.Info().
				Str("type", string(op.Type)).
				Str("name", op.ApplicationName).
				Strs("hosts", op.Servers).
				Msg("received operation request")

			if len(toRemove) == 0 && len(toAdd) == 0 {
				waitingTimer = time.NewTimer(waitingWindow)

				if waitingWindow > 0 {
					log.Info().Str("waiting-duration", waitingWindow.String()).Msg("starting waiting mode")
				}
			}

			toBeCategorized := []*sdwan.Operation{op}

			for len(opsChan) > 0 && waitingWindow == 0 {
				// If the waiting window is disabled, then we will try to get
				// all other pending operations, so we will not only work on
				// one operation at time: that would be disastrous for
				// performance!
				toBeCategorized = append(toBeCategorized, <-opsChan)
			}

			for _, cat := range toBeCategorized {
				switch cat.Type {
				case sdwan.OperationAdd:
					toAdd = append(toAdd, cat)
				case sdwan.OperationRemove:
					toRemove = append(toRemove, cat)
				default:
					log.Error().Str("type", string(cat.Type)).Msg("invalid operation type provided: skipping...")
				}
			}
		case <-waitingTimer.C:
			log.Info().Msg("worker in busy mode")

			if err := func() error {
				log.Debug().Msg("checking authentication...")
				ctx, canc := context.WithTimeout(mainCtx, defaultReauthTimeout)
				defer canc()

				valid, err := v.Auth().AreTokensStillValid(ctx)
				if err != nil {
					return fmt.Errorf("cannot check token validity: %w", err)
				}
				if valid {
					// Tokens still valid.
					return nil
				}

				log.Debug().Msg("renewing tokens...")
				err = v.Auth().RenewTokens(ctx)
				if err != nil {
					return fmt.Errorf("could not renew tokens: %w", err)
				}

				return nil
			}(); err != nil {
				// TODO: what to do? Best thing would probably be to panic:
				// this is a critical part of our program, as we can't do
				// our job in this case. In next version, we will have sentinel
				// errors and we will crash only according to what error is
				// returned (e.g. crash only if we can't renew)
				log.Err(err).
					Msg("can't check if tokens are still valid: next operations may fail")
			}

			doAction := func(ops []*sdwan.Operation) error {
				ctx, canc := context.WithTimeout(mainCtx, defaultOpTimeout)
				defer canc()

				var err error
				if ops[0].Type == sdwan.OperationRemove {
					err = v.removeApplications(ctx, toRemove, log)
				} else {
					err = v.addApplications(ctx, toAdd, log)
				}

				return err
			}

			// -- First, remove the ones that must be removed.
			if len(toRemove) > 0 {
				if err := doAction(toRemove); err != nil {
					log.Err(err).Msg("error while removing custom applications")
				}
			}

			log.Debug().Dur("duration", 5*time.Second).
				Msg("cooling down...")
			coolDown := time.NewTimer(5 * time.Second)
			select {
			case <-mainCtx.Done():
				// Avoid adding custom applications, then.
				return nil
			case <-coolDown.C:
				log.Debug().Msg("finished cool down")
			}

			// -- Then, add the new applications
			if len(toAdd) > 0 {
				if err := doAction(toAdd); err != nil {
					log.Err(err).Msg("error while adding custom applications")
				}
			}

			// Reset
			toRemove, toAdd = []*sdwan.Operation{}, []*sdwan.Operation{}
			log.Info().Msg("back in free mode")
		}
	}
}

func (v *Client) removeApplications(ctx context.Context, ops []*sdwan.Operation, log zerolog.Logger) error {
	names := make([]string, len(ops))
	for i, op := range ops {
		names[i] = op.ApplicationName
	}
	log = log.With().Str("worker", "remover").Logger()

	log.Info().Strs("applications", names).Msg("removing applications, this may take a while...")

	// -- Disable the applictions.
	pushRequired, err := v.CloudX().DisableApplicationsByName(ctx, names)
	if err != nil {
		return fmt.Errorf("could not disable applications: %w", err)
	}

	log.Debug().Strs("applications", names).Msg("applications disabled successfully")

	// -- Now, push the new configuration to Cloud Express.
	if pushRequired {
		log.Debug().Msg("a push is required")

		opID, err := v.CloudX().ApplyConfigurationToAllDevices(ctx)
		if err != nil {
			return fmt.Errorf("could not apply configuration: %w", err)
		}

		opl := log.With().Str("operation-id", opID).Logger()
		opl.Debug().Msg("configuration pushed to all devices")

		opl.Debug().Msg("waiting for operation to complete...")
		if err := v.Status().WaitUntilOperationCompletes(ctx, opID); err != nil {
			return fmt.Errorf("error while waiting for operation %s to complete: %w", opID, err)
		}
		opl.Debug().Msg("finished")
	}

	// -- Now get the apps and see where they are referenced.
	polAppLists := map[string]*policy.ApplicationList{}
	for _, appName := range names {
		app, err := v.PolicyApplicationsList().GetApplicationListByName(ctx, appName)
		if err != nil {
			return fmt.Errorf(`could not get policy application list with name "%s": %w`, appName, err)
		}

		polAppLists[app.ID] = app
	}
	if len(polAppLists) == 0 {
		return fmt.Errorf("no policy application lists found")
	}
	log.Debug().Int("#", len(polAppLists)).Msg("retrieved the policy applications lists")

	// -- Get the references for each policy application list.
	appRoutes := map[string]*approute.Policy{}
	for _, polAppList := range polAppLists {
		for _, ref := range polAppList.References {

			if ref.ID == "" || !strings.EqualFold(ref.Type, "approute") {
				// Skip if this is not AppRoute or the ID is empty (it does happen).
				continue
			}

			if _, exists := appRoutes[ref.ID]; exists {
				// Skip if we already have this.
				continue
			}

			ar, err := v.AppRoute().GetPolicy(ctx, ref.ID)
			if err != nil {
				return fmt.Errorf(`could not get approute policy with id %s: %w`, ref.ID, err)
			}

			appRoutes[ar.DefinitionID] = ar
		}
	}
	if len(appRoutes) == 0 {
		return fmt.Errorf("no associated AppRoute policies found")
	}
	log.Debug().Int("#", len(appRoutes)).Msg("retrieved associated AppRoute policies")

	// -- For each AppRoute found, we need to remove the applications from there.
	newAppRoutes := []*approute.Policy{}
	for _, ar := range appRoutes {
		newAppRoute := *ar
		newAppRoute.Sequences = []*approute.Sequence{}

		for _, sequence := range ar.Sequences {
			foundAny := false
			for _, entry := range sequence.Match.Entries {
				if _, exists := polAppLists[entry.Reference]; exists {
					foundAny = true
					break
				}
			}

			if !foundAny {
				newAppRoute.Sequences = append(newAppRoute.Sequences, sequence)
			}
		}

		newAppRoutes = append(newAppRoutes, &newAppRoute)
	}
	log.Debug().Msg("parsed and modified AppRoutes before updating")

	// -- Try a bulk update.
	processID, err := v.AppRoute().BulkUpdate(ctx, newAppRoutes)
	if err != nil {
		return fmt.Errorf("could not perform bulk update: %w", err)
	}
	log.Debug().Str("process-id", processID).Msg("initialized AppRoute policies bulk update")

	// -- Let's now activate the policies.
	vsmartPols := map[string]*vsmart.Policy{}
	{
		// Get all vsmart policies, instead of pulling them one by one.
		// TODO: this may be done in another way: get only the vsmart
		// policies that really apply this and ignore anything else.
		polIDs := map[string]bool{}
		for _, ar := range appRoutes {
			for _, activatedID := range ar.ActivatedIDs {
				if _, exists := vsmartPols[activatedID]; exists {
					continue
				}

				polIDs[activatedID] = true
			}
		}

		vpols, err := v.VSmart().ListPolicies(ctx)
		if err != nil {
			return fmt.Errorf("could not load vSmart policies: %w", err)
		}

		for _, vpol := range vpols {
			if _, exists := polIDs[vpol.ID]; exists {
				vsmartPols[vpol.ID] = vpol
			}
		}
	}
	if len(vsmartPols) == 0 {
		return fmt.Errorf("no vSmart policies found")
	}
	log.Debug().Int("#", len(vsmartPols)).Msg("retrieved vSmart policies")

	// -- Now activate each one of them
	for _, vpol := range vsmartPols {
		l := log.With().Str("id", vpol.ID).Str("name", vpol.Name).Logger()
		if err := v.VSmart().UpdateCentralPolicyByID(ctx, vpol.ID, vpol); err != nil {
			return fmt.Errorf("could not update vSmart central policy: %w", err)
		}
		l.Debug().Msg("updated vSmart policy")

		opID, err := v.VSmart().ActivatePolicyByID(ctx, vpol.ID, processID)
		if err != nil {
			return fmt.Errorf("could not update vSmart central policy: %w", err)
		}
		l.Debug().Str("operation-id", opID).Msg("activated vSmart policy")

		l.Debug().Str("operation-id", opID).Msg("waiting for operation to complete")
		if err := v.Status().WaitUntilOperationCompletes(ctx, opID); err != nil {
			return err
		}
		l.Debug().Str("operation-id", opID).Msg("finished")
	}

	// -- Delete the policy application list.
	for _, polAppList := range polAppLists {
		if err := v.
			PolicyApplicationsList().
			DeleteApplication(ctx, polAppList.ID); err != nil {
			return fmt.Errorf("error while deleting application with ID %s: %w", polAppList.ID, err)
		}

		log.Debug().
			Str("id", polAppList.ID).
			Str("name", polAppList.Name).
			Msg("deleted policy application list")
	}

	// -- Delete the custom application.
	for _, polAppList := range polAppLists {
		for _, entry := range polAppList.ApplicationEntries {
			if entry.Name == polAppList.Name && entry.Reference != "" {
				if err := v.
					PolicyApplicationsList().
					DeleteCustomApplication(ctx, entry.Reference); err != nil {
					return fmt.Errorf("could not delete custom application with ID %s: %w", entry.Reference, err)
				}

				log.Debug().
					Str("id", entry.Reference).
					Str("name", entry.Name).
					Msg("deleted custom application")
			}
		}
	}

	log.Info().Msg("all done")

	return nil
}

func (v *Client) addApplications(ctx context.Context, ops []*sdwan.Operation, log zerolog.Logger) error {
	names := make([]string, len(ops))
	customApplications := make([]*policy.CustomApplication, len(ops))
	for i, op := range ops {
		customApplications[i] = &policy.CustomApplication{
			Name:        op.ApplicationName,
			ServerNames: op.Servers,
		}
		names[i] = op.ApplicationName
	}
	log = log.With().Str("worker", "adder").Logger()

	{
		log.Debug().Msg("checking for existing custom applications before continuing")
		existingCustomApps, err := v.PolicyApplicationsList().
			ListCustomApplications(ctx)
		if err != nil {
			log.Err(err).Msg("error while checking existing applications: next operations may fail")
		}

		for _, exCustApp := range existingCustomApps {
			for i := 0; i < len(customApplications); i++ {
				if customApplications[i].Name == exCustApp.Name {
					customApplications[i].ID = exCustApp.ID
					log.Debug().
						Str("app-id", customApplications[i].ID).
						Str("current-app", customApplications[i].Name).
						Msg("custom application already exists, skipping creation...")
				}
			}
		}
	}

	log.Info().Strs("names", names).Msg("adding custom applications, this may take a while...")

	// The next two steps can be done in just one loop, but since this involves
	// creating two separate resources which reference each other, it's better
	// to first create all the ones of the same type first, so we can easily
	// revert later.

	// -- First, create the custom applications.
	for i, customApp := range customApplications {
		if customApp.ID != "" {
			continue
		}

		appID, err := v.PolicyApplicationsList().
			CreateCustomApplication(ctx, customApp)
		if err != nil {
			return fmt.Errorf("could not create custom application with name %s: %w", customApp.Name, err)
		}
		log.Debug().
			Str("app-id", appID).
			Str("current-app", customApp.Name).
			Msg("created custom application and received application ID")

		customApplications[i].ID = appID
	}

	// -- Create the policy application lists for each custom application.
	// listIDs is map that associates custom app name -> policy application list ID
	listIDs := map[string]string{}
	for _, customApp := range customApplications {
		// Does it already exist?
		appList, err := v.PolicyApplicationsList().
			GetApplicationListByName(ctx, customApp.Name)
		if err != nil {
			if !errors.Is(err, sdwan.ErrNotFound) {
				log.Err(err).
					Str("current-app", customApp.Name).
					Msg("error while checking if policy exists, next operations may fail")
			}
		} else {
			log.Debug().
				Str("list-id", appList.ID).
				Str("current-app", customApp.Name).
				Msg("a policy application list already exists for this: skipping...")
			listIDs[customApp.Name] = appList.ID

			continue
		}

		listID, err := v.
			PolicyApplicationsList().
			CreatePolicyApplicationList(ctx, customApp)
		if err != nil {
			return fmt.Errorf("could not create policy appliction list with name %s: %w", customApp.Name, err)
		}
		log.Debug().
			Str("list-id", listID).
			Str("current-app", customApp.Name).
			Msg("created policy application list and received list ID")

		listIDs[customApp.Name] = listID
	}

	// -- Enable the applications.
	pushRequired, err := v.CloudX().EnableApplicationsByName(ctx, names)
	if err != nil {
		return fmt.Errorf("could not enabled applications: %w", err)
	}
	log.Debug().Msg("applications enabled successfully")

	if pushRequired {
		log.Debug().Msg("a push is required")

		opID, err := v.CloudX().ApplyConfigurationToAllDevices(ctx)
		if err != nil {
			return fmt.Errorf("could not apply configuration: %w", err)
		}
		opl := log.With().Str("operation-id", opID).Logger()
		opl.Debug().Msg("configuration pushed to all devices")

		opl.Debug().Msg("waiting for operation to complete")
		if err := v.Status().WaitUntilOperationCompletes(ctx, opID); err != nil {
			return fmt.Errorf("could not get status of operation %s: %w", opID, err)
		}
		opl.Debug().Msg("finished")
	}

	// -- Get all vSmart policies.
	vsmartPolicies, err := v.VSmart().ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("could not load list of approute policies: %w", err)
	}
	if len(vsmartPolicies) == 0 {
		return fmt.Errorf("no vSmart policies found")
	}
	log.Debug().Int("#", len(vsmartPolicies)).Msg("retrieved vSmart policies")

	// -- Get AppRoutes associated with.
	appRoutes := []*approute.Policy{}
	for _, vpol := range vsmartPolicies {
		for _, asm := range vpol.Definition.Assemblies {

			alreadyThere := false
			for _, appr := range appRoutes {
				if appr.DefinitionID == asm.DefinitionId {
					alreadyThere = true
				}
			}

			if alreadyThere {
				continue
			}

			ar, err := v.AppRoute().GetPolicy(ctx, asm.DefinitionId)
			if err != nil {
				return fmt.Errorf("could not load approute with ID %s: %w", asm.DefinitionId, err)
			}

			appRoutes = append(appRoutes, ar)
		}
	}
	if len(appRoutes) == 0 {
		return fmt.Errorf("no AppRoutes policies found")
	}
	log.Debug().Int("#", len(appRoutes)).Msg("retrieved AppRoute policies found")

	// -- Bulk update.
	newAppRoutes := []*approute.Policy{}
	for _, appRoute := range appRoutes {
		ar := *appRoute

		sequenceID := 1
		if len(ar.Sequences) > 0 {
			sequenceID = ar.Sequences[len(ar.Sequences)-1].ID + 10
		}

		// TODO: Technically this is not wrong, but there must be some entity
		// or endpoint that that can do this for us. Reasearch this.
		for customAppName, listID := range listIDs {
			ar.Sequences = append(ar.Sequences, &approute.Sequence{
				ID:     sequenceID,
				Name:   "App Route",
				Type:   "appRoute",
				IPType: "ipv4",
				Match: &approute.Match{
					Entries: []*approute.Entry{
						{
							Field:     "saasAppList",
							Reference: listID,
						},
					},
				},
				Actions: []*approute.Action{
					{
						Type:      "cloudSaas",
						Parameter: "",
					},
					{
						Type:      "count",
						Parameter: fmt.Sprintf("%s_ctr", customAppName),
					},
				},
			})
			sequenceID += 10
		}

		newAppRoutes = append(newAppRoutes, &ar)
	}
	log.Debug().Msg("parsed and modified approutes before bulk update")

	processID, err := v.AppRoute().BulkUpdate(ctx, newAppRoutes)
	if err != nil {
		return fmt.Errorf("could not bulk update: %w", err)
	}
	log.Debug().
		Str("pocess-id", processID).
		Msg("performed a bulk update and received processID")

	// -- Update the vsmart policies.
	for _, vpol := range vsmartPolicies {
		l := log.With().Str("id", vpol.ID).Str("name", vpol.Name).Logger()

		if err := v.VSmart().UpdateCentralPolicyByID(ctx, vpol.ID, vpol); err != nil {
			return fmt.Errorf("could not update vSmart central policy: %w", err)
		}
		l.Debug().Msg("updated vSmart policy")

		opID, err := v.VSmart().ActivatePolicyByID(ctx, vpol.ID, processID)
		if err != nil {
			return fmt.Errorf("could not update vSmart central policy: %w", err)
		}
		l.Debug().Str("operation-id", opID).Msg("activated vSmart policy")

		l.Debug().Str("operation-id", opID).Msg("waiting for operation to complete")
		if err := v.Status().WaitUntilOperationCompletes(ctx, opID); err != nil {
			return err
		}
		l.Debug().Str("operation-id", opID).Msg("finished")
	}

	log.Info().Msg("all done")

	return nil
}
