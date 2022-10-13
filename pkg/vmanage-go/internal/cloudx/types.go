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

package cloudx

import (
	cx "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/cloudx"
)

type InternalApplication struct {
	AppType       string `json:"appType"`
	LongName      string `json:"longName"`
	IsCustomApp   bool   `json:"isCustomApp"`
	TotalSites    int    `json:"totalSites"`
	GoodSites     int    `json:"goodSites"`
	BadSites      int    `json:"badSites"`
	AverageSites  int    `json:"averageSites"`
	PolicyEnabled bool   `json:"policyEnabled"`
	AppVPNList    string `json:"appVpnList"`
}

func (a *InternalApplication) ToApplication() *cx.Application {
	return &cx.Application{
		Name:     a.AppType,
		LongName: a.LongName,
		Type: func() cx.ApplicationType {
			if a.IsCustomApp {
				return cx.CustomApplication
			}

			return cx.StandardApplication
		}(),
		SiteCounts: func() *cx.SiteCounts {
			if a.TotalSites == 0 &&
				a.AverageSites == 0 &&
				a.BadSites == 0 &&
				a.GoodSites == 0 {
				return nil
			}

			return &cx.SiteCounts{
				Total:   a.TotalSites,
				Good:    a.GoodSites,
				Bad:     a.BadSites,
				Average: a.AverageSites,
			}
		}(),
		PolicyEnabled: a.PolicyEnabled,
	}
}

type UpdateApplicationsRequestBody struct {
	AppList []InternalApplication `json:"appList"`
}

func NewUpdateApplicationRequestBody(apps []*cx.Application) *UpdateApplicationsRequestBody {
	body := &UpdateApplicationsRequestBody{
		AppList: []InternalApplication{},
	}

	for _, app := range apps {
		body.AppList = append(body.AppList, InternalApplication{
			AppType:       app.Name,
			LongName:      app.LongName,
			IsCustomApp:   app.Type == cx.CustomApplication,
			PolicyEnabled: app.PolicyEnabled,
		})
	}

	return body
}

type InternalDevice struct {
	SiteID string `json:"site-id"`
	// VedgeList         []VedgeList `json:"vedgeList"`
}

type AttachConfigurationRequestBody struct {
	SiteList []int `json:"siteList"`
	IsEdited bool  `json:"isEdited"`
}

func NewAttachConfigurationRequestBody(siteIDs []int) *AttachConfigurationRequestBody {
	return &AttachConfigurationRequestBody{
		SiteList: siteIDs,
		IsEdited: true,
	}
}
