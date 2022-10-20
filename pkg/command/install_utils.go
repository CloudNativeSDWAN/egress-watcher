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

package command

import (
	"context"
	"fmt"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/controllers"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func createNamespace(clientset *kubernetes.Clientset, usernamespace string) error {
	ns := &apiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: usernamespace,
		},
	}

	nsOut, err := clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {

		return fmt.Errorf("Namespace: error creating the namespace %w", err)

	}
	fmt.Printf("Created serviceaccount %v.\n", nsOut.GetObjectMeta().GetName())
	return nil
}

func createServiceAccount(clientset *kubernetes.Clientset, usernamespace, name string) error {
	servacc := &apiv1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-service-account",
			Namespace: usernamespace,
		},
	}

	serviceAccountOut, err := clientset.CoreV1().ServiceAccounts(usernamespace).Create(context.TODO(), servacc, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("ServiceAccount: error creating the serviceaccount %w", err)
	}
	fmt.Printf("Created serviceaccount %v.\n", serviceAccountOut.GetObjectMeta().GetName())
	return nil
}

func createClusterRole(clientset *kubernetes.Clientset, usernamespace, name string) error {
	cr := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-role",
			Namespace: usernamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"networking.istio.io"},
				Resources: []string{"serviceentries"},
				Verbs: []string{
					"watch",
					"get",
					"list",
				},
			},
		},
	}

	clusterRoleOut, err := clientset.RbacV1().ClusterRoles().Create(context.TODO(), cr, metav1.CreateOptions{})

	if err != nil {
		return fmt.Errorf("ClusterRole: error creating the clusterrole %w", err)
	}
	fmt.Printf("Created clusterRole %v.\n", clusterRoleOut.GetObjectMeta().GetName())
	return nil
}

func createClusterRoleBinding(clientset *kubernetes.Clientset, usernamespace, name string) error {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-role-binding",
			Namespace: usernamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "egress-watcher-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "egress-watcher-service-account",
				Namespace: usernamespace,
			},
		},
	}

	clusterRoleBindingOut, err := clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), crb, metav1.CreateOptions{})

	if err != nil {
		return fmt.Errorf("ClusterRoleBinding: error creating the clusterrolebinding %w", err)
	}
	fmt.Printf("Created clusterRoleBindingccount %v.\n", clusterRoleBindingOut.GetObjectMeta().GetName())
	return nil
}

func createConfigMap(clientset *kubernetes.Clientset, usernamespace, name, usersettingsfilename, sdwan_url, sdwan_username, sdwan_pass string) error {
	defWindow := 30 * time.Second
	opt := Options{
		ServiceEntryController: &controllers.ServiceEntryOptions{
			WatchAllServiceEntries: false,
		},

		Sdwan: &sdwan.Options{
			WaitingWindow: &defWindow,
			BaseURL:       sdwan_url,
			Authentication: &sdwan.Authentication{
				Username: sdwan_username,
				Password: sdwan_pass,
			},
		},
	}
	yaml_opt, _ := yaml.Marshal(opt)
	cm := apiv1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-settings",
			Namespace: usernamespace,
		},

		Data: map[string]string{
			usersettingsfilename: string(yaml_opt),
		},
	}

	configOut, err := clientset.CoreV1().ConfigMaps(usernamespace).Create(context.TODO(), &cm, metav1.CreateOptions{})

	if err != nil {
		return fmt.Errorf("ConfigMap: error creating the configmap %w", err)
	}
	fmt.Printf("Created configmap %v.\n", configOut.GetObjectMeta().GetName())
	return nil
}

func createSecret(clientset *kubernetes.Clientset, usernamespace, name, sdwan_username, sdwan_pass string) error {
	secr := &apiv1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vmanage-credentials",
			Namespace: usernamespace,
		},
		Data: map[string][]byte{
			"username": []byte(sdwan_username),
			"password": []byte(sdwan_pass),
		},
		Type: "Opaque",
	}

	secretOut, err := clientset.CoreV1().Secrets(usernamespace).Create(context.TODO(), secr, metav1.CreateOptions{})

	if err != nil {
		return fmt.Errorf("Secret: error creating the secret %w", err)
	}
	fmt.Printf("Created secret %v.\n", secretOut.GetObjectMeta().GetName())
	return nil
}

func createDeployment(clientset *kubernetes.Clientset, sdwan_url string, usernamespace string, image string) error {
	deploymentsClient := clientset.AppsV1().Deployments(usernamespace)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher",
			Namespace: "egress-watcher",
			Labels: map[string]string{
				"app": "egress-watcher"},
		},
		Spec: appsv1.DeploymentSpec{
			//Replicas: "2",
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "egress-watcher",
				},
			},
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "egress-watcher",
					},
				},
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						{
							Name:            "egress-watcher",
							Image:           image,
							ImagePullPolicy: "Always",
							Args: []string{
								"run",
								"with-vmanage",
								"--settings-file=/settings/settings.yaml",
								"--sdwan.username=$(SDWAN_USERNAME)",
								"--sdwan.password=$(SDWAN_PASSWORD)",
								"—verbosity=0",
							},
							VolumeMounts: []apiv1.VolumeMount{
								{
									Name:      "config-volume",
									MountPath: "/settings",
								},
							},
							Resources: apiv1.ResourceRequirements{
								Limits: apiv1.ResourceList{
									"cpu":    resource.MustParse("200m"),
									"memory": resource.MustParse("100Mi"),
								},

								Requests: apiv1.ResourceList{
									"cpu":    resource.MustParse("100m"),
									"memory": resource.MustParse("50Mi"),
								},
							},

							Env: []apiv1.EnvVar{{
								Name: "SDWAN_USERNAME",
								ValueFrom: &apiv1.EnvVarSource{
									SecretKeyRef: &apiv1.SecretKeySelector{
										LocalObjectReference: apiv1.LocalObjectReference{
											Name: "vmanage-credentials",
										},
										Key: "username",
									},
								}},

								{
									Name: "SDWAN_PASSWORD",
									ValueFrom: &apiv1.EnvVarSource{
										SecretKeyRef: &apiv1.SecretKeySelector{
											LocalObjectReference: apiv1.LocalObjectReference{
												Name: "vmanage-credentials",
											},
											Key: "password",
										},
									}},
							},
						}},

					Volumes: []apiv1.Volume{
						{Name: "config-volume",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: "egress-watcher-settings"},
								},
							},
						},
					},
					ServiceAccountName: "egress-watcher-service-account",
				},
			},
		},
	}

	// Create Deployment
	fmt.Println("Creating deployment...")
	result, err := deploymentsClient.Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		//panic(err)
		return fmt.Errorf("Deployment: error creating the deployment %w", err)
	}
	fmt.Printf("Created deployment %q.\n", result.GetObjectMeta().GetName())
	return nil

}
