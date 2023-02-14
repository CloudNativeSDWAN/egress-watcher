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
//
// Credit to @chowndarya for the original work and functions created here.

package command

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/enescakir/emoji"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type installer struct {
	namespace string
	name      string
	clientset *kubernetes.Clientset

	namespaceExisted bool
	saExisted        bool

	clusterRoleName        string
	clusterRoleBindingName string
	serviceAccountName     string
	secretName             string
	settingsName           string
}

func newInstaller(clientset *kubernetes.Clientset, namespace, name string) (*installer, error) {
	if clientset == nil {
		return nil, fmt.Errorf("no clientset provided")
	}
	if namespace == "" {
		namespace = defaultNamespace
	}
	if name == "" {
		name = defaultName
	}

	inst := newInstallerWithNames(name)
	inst.namespace = namespace
	inst.clientset = clientset

	// Check if namespace already exists
	nsExisted, err := func() (bool, error) {
		ctx, canc := context.WithTimeout(context.Background(), 10*time.Second)
		defer canc()

		_, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return false, nil
			}

			return false, err
		}

		return true, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("cannot check if namespace %s already exists: %w", namespace, err)
	}
	if nsExisted {
		inst.namespaceExisted = nsExisted
		return inst, nil
	}

	// Check if service account already exists
	saExisted, err := func() (bool, error) {
		ctx, canc := context.WithTimeout(context.Background(), 10*time.Second)
		defer canc()

		_, err := clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return false, nil
			}

			return false, err
		}

		return true, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("cannot check if service account %s already exists: %w", inst.serviceAccountName, err)
	}

	inst.saExisted = saExisted
	return inst, nil
}

func newInstallerWithNames(name string) *installer {
	return &installer{
		name:                   name,
		clusterRoleName:        name + "-cluster-role",
		clusterRoleBindingName: name + "-cluster-role-binding",
		serviceAccountName:     name + "-service-account",
		secretName:             name + "-credentials",
		settingsName:           name + "-settings",
	}
}

func (i *installer) install(ctx context.Context, containerImage string, opts Options) error {
	// Array of functions to execute for installing
	installers := []func(context.Context) error{
		i.createClusterRole,
		i.createClusterRoleBinding,
		i.createNamespace,
		i.createServiceAccount,
		func(ctx context.Context) error {
			return i.createSecret(ctx, opts)
		},
		func(ctx context.Context) error {
			return i.createConfigMap(ctx, opts)
		},
		func(ctx context.Context) error {
			return i.createDeployment(ctx, containerImage)
		},
	}

	// Array of resources for printing
	resources := []string{
		"cluster role",
		"cluster role binding",
		"namespace",
		"service account",
		"secret",
		"config map",
		"deployment",
	}

	for index, inst := range installers {
		fmt.Printf("creating %s...", resources[index])

		if err := inst(ctx); err != nil {
			fmt.Println(" ", emoji.CrossMark, err)
			i.cleanUp(ctx)
			return err
		}

		fmt.Println(" ", emoji.CheckMarkButton)
	}

	return nil
}

func (i *installer) createClusterRole(ctx context.Context) (err error) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.clusterRoleName,
			Namespace: i.namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"networking.istio.io"},
				Resources: []string{"serviceentries"},
				Verbs:     []string{"watch", "get", "list"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "get", "list"},
			},
		},
	}

	_, err = i.clientset.RbacV1().ClusterRoles().
		Create(ctx, cr, metav1.CreateOptions{})
	return
}

func (i *installer) createClusterRoleBinding(ctx context.Context) (err error) {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.clusterRoleBindingName,
			Namespace: i.namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     i.clusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      i.serviceAccountName,
				Namespace: i.namespace,
			},
		},
	}

	_, err = i.clientset.RbacV1().ClusterRoleBindings().
		Create(ctx, crb, metav1.CreateOptions{})
	return
}

func (i *installer) createNamespace(ctx context.Context) (err error) {
	_, err = i.clientset.CoreV1().Namespaces().
		Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: i.namespace,
			},
		}, metav1.CreateOptions{})

	return
}

func (i *installer) createServiceAccount(ctx context.Context) (err error) {
	_, err = i.clientset.CoreV1().ServiceAccounts(i.namespace).Create(context.TODO(), &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.serviceAccountName,
			Namespace: i.namespace,
		},
	}, metav1.CreateOptions{})

	return
}

func (i *installer) createSecret(ctx context.Context, opts Options) (err error) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.secretName,
			Namespace: i.namespace,
		},
		Data: map[string][]byte{
			"username": []byte(opts.Sdwan.Authentication.Username),
			"password": []byte(opts.Sdwan.Authentication.Password),
		},
		Type: "Opaque",
	}

	_, err = i.clientset.CoreV1().Secrets(i.namespace).
		Create(ctx, secret, metav1.CreateOptions{})
	return
}

func (i *installer) createConfigMap(ctx context.Context, opts Options) (err error) {
	yamlOpts, err := yaml.Marshal(opts)
	if err != nil {
		return fmt.Errorf("cannot marshal options to yaml: %w", err)
	}

	_, err = i.clientset.CoreV1().
		ConfigMaps(i.namespace).Create(ctx, &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.settingsName,
			Namespace: i.namespace,
		},

		Data: map[string]string{
			"settings.yaml": string(yamlOpts),
		},
	}, metav1.CreateOptions{})
	return
}

func (i *installer) createDeployment(ctx context.Context, containerImage string) (err error) {
	deploymentsClient := i.clientset.AppsV1().Deployments(i.namespace)
	configVolumeName := "config-volume"

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.name,
			Namespace: i.namespace,
			Labels: map[string]string{
				"app": defaultName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": defaultName,
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": defaultName,
					},
				},
				Spec: v1.PodSpec{

					Containers: []v1.Container{
						{
							Name:            i.namespace,
							Image:           containerImage,
							ImagePullPolicy: v1.PullAlways,
							Args: []string{
								"run",
								"with-vmanage",
								"--settings-file=/settings/settings.yaml",
								"--sdwan.username=$(SDWAN_USERNAME)",
								"--sdwan.password=$(SDWAN_PASSWORD)",
								"—verbosity=0",
							},
							VolumeMounts: []v1.VolumeMount{
								{
									Name:      configVolumeName,
									MountPath: "/settings",
								},
							},
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									"memory": resource.MustParse("100Mi"),
								},
								Requests: v1.ResourceList{
									"cpu":    resource.MustParse("100m"),
									"memory": resource.MustParse("50Mi"),
								},
							},

							Env: []v1.EnvVar{
								{
									Name: "SDWAN_USERNAME",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: i.secretName,
											},
											Key: "username",
										},
									},
								},

								{
									Name: "SDWAN_PASSWORD",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: i.secretName,
											},
											Key: "password",
										},
									},
								},
							},
						},
					},

					Volumes: []v1.Volume{
						{
							Name: configVolumeName,
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{
										Name: i.settingsName,
									},
								},
							},
						},
					},
					ServiceAccountName: i.serviceAccountName,
				},
			},
		},
	}

	_, err = deploymentsClient.Create(ctx, deployment, metav1.CreateOptions{})
	return
}

func (i *installer) cleanUp(ctx context.Context) error {
	// Array of functions that remove a resource.
	removers := []func(context.Context) error{
		func(ctx context.Context) error {
			return i.clientset.RbacV1().ClusterRoles().
				Delete(context.TODO(), i.clusterRoleName, metav1.DeleteOptions{})
		},
		func(ctx context.Context) error {
			return i.clientset.RbacV1().ClusterRoleBindings().
				Delete(context.TODO(), i.clusterRoleBindingName, metav1.DeleteOptions{})
		},
		func(ctx context.Context) error {
			return i.clientset.AppsV1().Deployments(i.namespace).
				Delete(context.TODO(), i.name, metav1.DeleteOptions{})
		},
		func(ctx context.Context) error {
			if i.saExisted {
				return nil
			}
			return i.clientset.CoreV1().ServiceAccounts(i.namespace).
				Delete(context.TODO(), i.serviceAccountName, metav1.DeleteOptions{})
		},
		func(ctx context.Context) error {
			return i.clientset.CoreV1().ConfigMaps(i.namespace).
				Delete(context.TODO(), i.settingsName, metav1.DeleteOptions{})
		},
		func(ctx context.Context) error {
			return i.clientset.CoreV1().Secrets(i.namespace).
				Delete(context.TODO(), i.secretName, metav1.DeleteOptions{})
		},
		func(ctx context.Context) error {
			if i.namespaceExisted {
				return nil
			}
			return i.clientset.CoreV1().Namespaces().
				Delete(context.TODO(), i.namespace, metav1.DeleteOptions{})
		},
	}

	// Array of resources type names, each of these maps to the same item
	// on the previous one.
	resources := []string{
		"cluster role",
		"cluster role binding",
		"deployment",
		"service account",
		"config map",
		"secret",
		"namespace",
	}

	fmt.Println("undoing changes ", emoji.BackArrow)

	// Remove each resource
	for j, remover := range removers {
		if err := remover(ctx); err != nil && !k8serrors.IsNotFound(err) {
			fmt.Printf("could not delete %s: %s\n", resources[j], err)
		}
	}

	return nil
}

func askForPassword() (pass string) {
	for {
		fmt.Print("Please enter your SDWAN password (input will be hidden): ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		pass = string(bytePassword)
		if pass != "" {
			return
		}

		fmt.Println("password provided is invalid")
	}
}
