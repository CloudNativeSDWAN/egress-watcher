# Egress Watcher

![GitHub](https://img.shields.io/github/license/CloudNativeSDWAN/egress-watcher)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/CloudNativeSDWAN/egress-watcher)
[![Go Report Card](https://goreportcard.com/badge/github.com/CloudNativeSDWAN/egress-watcher)](https://goreportcard.com/report/github.com/CloudNativeSDWAN/egress-watcher)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CloudNativeSDWAN/egress-watcher/Test)
![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/CloudNativeSDWAN/egress-watcher?include_prereleases)

Reflect your *Egress* definitions from different object types to your
*SD-WAN* for processing and routes optmization.

Find some context on the project in our [Talk](https://www.youtube.com/watch?v=POEedeeRs_8) @ KubeCon EU 2022 and in this *Cisco Tech Blog* [article](https://techblog.cisco.com/blog/tell-your-sd-wan).

## Supported projects and providers

### Supported Egress types

As of now, we support egress hosts defined as *ISTIO* `ServiceEntry` objects
and we reflect the changes we detect in them.

Though only *ISTIO* is supported as of now, the project's architecture is
designed to accomodate different types as defined by other projects.

### Supported SD-WANs

The project is designed to be inter-operable between different SD-WANs, which
need to be specified in its commands.

As of now, we support *vManage* as SD-WAN and it must be included as argument
in the [run command](#run-command).

## Install

Make sure *Istio* is up and running properly on your Kubernetes cluster. If not
please [install it](https://istio.io/latest/docs/setup/), first.

Clone the project:

```bash
git clone https://github.com/CloudNativeSDWAN/egress-watcher.git && cd egress-watcher
make build
```

The project is now ready to be used locally from `./bin` directory as
`./bin/egress-watcher`

## Usage

### Commands

There are currently two commands:

* `help`: Help about any command
* `run`: Run locally.

### run command

The `run` command runs the program with certain options that can be provided
either with flags and/or a file.
An example of a file is provided in the root directory with `settings.yaml`.

`run` needs an argument specifying the SD-WAN controller it needs to work with:

* for *vManage* specify `vmanage` (or `with-vmanage`)

Currently it supports the following flags:

* `--context`: the context of the kubeconfig to use. **This flag is not
supported yet and will be silently ignored**.
* `--kubeconfig`: path to the kubeconfig file to use. **This flag is not
supported yet and will be silently ignored: the default kubeconfig is used**.
* `--settings-file`: path to settings file to load. This is optional. Take a
look at `settings.yaml` in this same directory to view an example.
* `--sdwan.base-url`: sdwan's base url to use when forming requests.
  Must be in the form of `http(s)://<host:port>/path`, e.g.
  `http://example.com:9876/api` or `https://10.11.12.13:1234/my/path`. This is
**required**, unless this value is provided from file with `--settings-file`.
* `--watch-all-service-entries, -w`: watch all `ServiceEntry` objects without
the need for manual `egress-watch: enabled` label.
To ignore a service entry you will have to label it as
`egress-watch: disabled`.
* `--sdwan.username`: the username for authentication. **Required**.
* `--sdwan.password`: the password for authentication. **Required**.
* `--sdwan.insecure`: whether to accept self-signed certificates.

As a rule of thumb, remember that flag options **overwrite** options provided
via file.

Please note that, as we support more egress types and SD-WANs, the above
flags and command may change.

### Watch ServiceEntry

With default options the watcher will only watch `ServiceEntry` with **label**
`egress-watch: enabled` and ignore those that don't.

`--watch-all-service-entries` makes the program behave in the opposite way and
namespaces must be explicitly disabled with a **label**
`egress-watch: disabled`.

## Run locally

Make sure you followed [Install](#install).

Run the watcher:

```bash
./bin/egress-watcher run vmanage \
--sdwan.username <username> \
--sdwan.password <pass> \
--sdwan.base-url <base_url> \
--sdwan.insecure
```

Try to deploy a `ServiceEntry` object you can use the provided example in
`artifacts/yamls/istio`:

```bash
# In another shell terminal
kubectl create -f ./artifacts/yamls/istio
```

Get back to the shell terminal where you were running the watcher and you
should see a couple of log lines.

## Run on Kubernetes

Build and push the docker image via `make` command. For example, with
*Dockerhub*:

```bash
export IMAGE="YOUR_IMAGE/REPO:TAG"
make docker-build docker-push IMG=$IMAGE
```

Set the appropriate values in the `settings.yaml` file - especially the base
URL for SD-WAN. You will also need to create secrets for the SD-WAN provider
you are using, for example when using *vManage* - make sure you replace
`<USERNAME>` and `<PASSWORD>` accordingly:

```bash
kubectl create ns egress-watcher
kubectl create secret generic vmanage-credentials --from-literal=username=<USERNAME> --from-literal=password=<PASSWORD> -n egress-watcher
kubectl create configmap egress-watcher-settings --from-file=./settings.yaml -n egress-watcher
kubectl create -f ./artifacts/yamls/k8s -n egress-watcher
sleep 2
kubectl set image deployment/egress-watcher egress-watcher=$IMAGE -n egress-watcher
export POD_NAME=$(kubectl get pods --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' -n egress-watcher | grep egress-watcher)
kubectl logs -f $POD_NAME -n egress-watcher
```

Now, on a separate shell terminal, deploy our provided example:

```bash
# In another shell terminal
kubectl create -f ./artifacts/yamls/istio
```

## Contributing

Thank you for interest in contributing to Egress Watcher.
Before starting, please make sure you know and agree to our [Code of conduct](./code-of-conduct.md).

1. Fork it
2. Download your fork
    `git clone https://github.com/your_username/egress-watcher && cd egress-watcher`
3. Create your feature branch
    `git checkout -b my-new-feature`
4. Make changes and add them
    `git add .`
5. Commit your changes
    `git commit -m 'Add some feature'`
6. Push to the branch
    `git push origin my-new-feature`
7. Create new pull request to this repository

## License

Egress Watcher is free and open-source software licensed under the *Apache 2.0*
License.
                            
Refer to [our license file](https://github.com/CloudNativeSDWAN/egress-watcher/blob/main/LICENSE).
