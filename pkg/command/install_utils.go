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

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	namespaceName       = "egress-watcher"
	serviceAccountName  = "egress-watcher-service-account"
	clusterRole         = "egress-watcher-role"
	clusterRoleBinding  = "egress-watcher-role-binding"
	applicationSettings = "egress-watcher-settings"
)

func createNamespace(clientset *kubernetes.Clientset, usernamespace string) error {
	ns := &apiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: usernamespace,
		},
	}
	_, err := clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	return err

}

func createServiceAccount(clientset *kubernetes.Clientset, usernamespace, name string) error {
	servacc := &apiv1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: usernamespace,
		},
	}

	_, err := clientset.CoreV1().ServiceAccounts(usernamespace).Create(context.TODO(), servacc, metav1.CreateOptions{})
	return err

}

func createClusterRole(clientset *kubernetes.Clientset, usernamespace, name string) error {
	cr := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterRole,
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

	_, err := clientset.RbacV1().ClusterRoles().Create(context.TODO(), cr, metav1.CreateOptions{})
	return err

}

func createClusterRoleBinding(clientset *kubernetes.Clientset, usernamespace, name string) error {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterRoleBinding,
			Namespace: usernamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: usernamespace,
			},
		},
	}

	_, err := clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), crb, metav1.CreateOptions{})
	return err

}

func createConfigMap(clientset *kubernetes.Clientset, opt Options, usernamespace, name string) error {

	yaml_opt, _ := yaml.Marshal(opt)
	cm := apiv1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      applicationSettings,
			Namespace: usernamespace,
		},

		Data: map[string]string{
			usersettingsfilename: string(yaml_opt),
		},
	}

	_, err := clientset.CoreV1().ConfigMaps(usernamespace).Create(context.TODO(), &cm, metav1.CreateOptions{})
	return err

}

func createSecret(clientset *kubernetes.Clientset, usernamespace, name string, opt Options) error {
	secr := &apiv1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: usernamespace,
		},
		Data: map[string][]byte{
			"username": []byte(opt.Sdwan.Authentication.Username),
			"password": []byte(opt.Sdwan.Authentication.Password),
		},
		Type: "Opaque",
	}

	_, err := clientset.CoreV1().Secrets(usernamespace).Create(context.TODO(), secr, metav1.CreateOptions{})
	return err

}

func createDeployment(clientset *kubernetes.Clientset, sdwan_url string, usernamespace string, image string) error {
	deploymentsClient := clientset.AppsV1().Deployments(usernamespace)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      namespaceName,
			Namespace: usernamespace,
			Labels: map[string]string{
				"app": namespaceName},
		},
		Spec: appsv1.DeploymentSpec{
			//Replicas: "2",
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": namespaceName,
				},
			},
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": namespaceName,
					},
				},
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						{
							Name:            namespaceName,
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
										Name: applicationSettings},
								},
							},
						},
					},
					ServiceAccountName: serviceAccountName,
				},
			},
		},
	}

	// Create Deployment
	_, err := deploymentsClient.Create(context.TODO(), deployment, metav1.CreateOptions{})
	return err

}

func cleanUP(clientset *kubernetes.Clientset, objecttype int) error {

	for i := 0; i <= objecttype; i++ {

		switch i {

		case 0:
			err := clientset.RbacV1().ClusterRoles().Delete(context.TODO(), clusterRole, metav1.DeleteOptions{})
			if err != nil {
				return err
			}

		case 1:
			err := clientset.RbacV1().ClusterRoleBindings().Delete(context.TODO(), clusterRoleBinding, metav1.DeleteOptions{})
			if err != nil {
				return err
			}

		case 2:
			err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{})
			if err != nil {
				return err
			}

		}

	}

	return nil
}
