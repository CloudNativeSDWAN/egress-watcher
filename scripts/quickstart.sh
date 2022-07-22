#!/bin/bash

echo "This script will deploy the egress-watcher with some sample values."
echo "The SD-WAN will be vManage."
echo

vmanage_username=""
while [ -z "$vmanage_username" ]; do
    read -p "Enter your vManage username: " vmanage_username
done

vmanage_password=""
while [ -z "$vmanage_password" ]; do
    printf "Enter your vManage password: "
    stty_orig=$(stty -g)
    stty -echo
    IFS= read -r vmanage_password
    stty "$stty_orig"
    echo
    # read -s "Enter your vManage password: " vmanage_password
done

vmanage_url=""
echo "Enter your vManage url in the form of scheme://address:port/path"
read -p "   (default: https://localhost:443/dataservice): " vmanage_url
if [ -z "$vmanage_url" ]; then
    vmanage_url="localhost"
fi

if [[ $vmanage_url != *"/dataservice" ]]; then
    append=""
    if [[ $vmanage_url == *"/" ]]; then
        append="dataservice"
    else
        append="/dataservice"
    fi

    vmanage_url+=$append
fi

vmanage_insecure="false"
vmanage_insecure_confirm=""
while [ "$vmanage_insecure_confirm" != "y" ] && [ "$vmanage_insecure_confirm" != "n" ]; do
read -p "Accept self-signed certificates? [y/n] " vmanage_insecure_confirm
vmanage_insecure_confirm=$(echo "$vmanage_insecure_confirm" | tr '[:upper:]' '[:lower:]')
done

if [ "$vmanage_insecure_confirm" == "y" ]; then
vmanage_insecure="true"
fi

echo
echo "Deploying on Kubernetes:"

kubectl create -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: egress-watcher
---
apiVersion: v1
kind: ServiceAccount
metadata:
  creationTimestamp: null
  name: egress-watcher-service-account
  namespace: egress-watcher
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: egress-watcher-role
rules:
- apiGroups:
  - networking.istio.io
  resources:
  - serviceentries
  verbs:
  - watch
  - get
  - list
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  creationTimestamp: null
  name: egress-watcher-role-binding
subjects:
  - kind: ServiceAccount
    name: egress-watcher-service-account
    namespace: egress-watcher
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: egress-watcher-role
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: egress-watcher-settings
  namespace: egress-watcher
data:
  settings.yaml: |
    serviceEntry:
      watchAllServiceEntries: true
    sdwan:
      baseUrl: $vmanage_url
      insecure: $vmanage_insecure
      waitingWindow: 30s
    prettyLogs: true
    verbosity: 1
EOF

kubectl create secret generic vmanage-credentials \
--from-literal=username=$vmanage_username \
--from-literal=password=$vmanage_password \
-n egress-watcher

kubectl create -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: egress-watcher
  name: egress-watcher
  namespace: egress-watcher
spec:
  replicas: 1
  selector:
    matchLabels:
      app: egress-watcher
  template:
    metadata:
      labels:
        app: egress-watcher
    spec:
      containers:
      - image: ghcr.io/cloudnativesdwan/egress-watcher:latest
        imagePullPolicy: Always
        name: egress-watcher
        args:
        - "run"
        - "with-vmanage"
        - "--settings-file=/settings/settings.yaml"
        - "--sdwan.username=\$(SDWAN_USERNAME)"
        - "--sdwan.password=\$(SDWAN_PASSWORD)"
        - "--verbosity=0"
        volumeMounts:
        - name: config-volume
          mountPath: /settings
        resources:
            limits:
              cpu: 200m
              memory: 100Mi
            requests:
              cpu: 100m
              memory: 50Mi
        env:
        - name: SDWAN_USERNAME
          valueFrom:
            secretKeyRef:
              name: vmanage-credentials
              key: username
        - name: SDWAN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: vmanage-credentials
              key: password
      volumes:
      - name: config-volume
        configMap:
          name: egress-watcher-settings
      serviceAccountName: egress-watcher-service-account
      serviceAccount: egress-watcher-service-account
status: {}
EOF

echo
echo "Waiting for pod to be running..."

times=0
current_status=""
while [ "$current_status" != "Running" ]; do
    times=$((times+1))

    if [ $times -gt 10 ]; then
        echo "giving up after 10 attempts"
        exit 1
    fi

    current_status=$(kubectl get pods --selector=app=egress-watcher  -o jsonpath="{.items[0].status.phase}" -n egress-watcher)
    if [ "$current_status" != "Running" ]; then
        sleep 3
    fi
done

pod_name=$(kubectl get pods --selector=app=egress-watcher  -o jsonpath="{.items[0].metadata.name}" -n egress-watcher)

echo "Pod $pod_name is running."
echo "All done. You can now start deploying ServiceEntry resources."