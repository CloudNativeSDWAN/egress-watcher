# Egress Watcher

![GitHub](https://img.shields.io/github/license/CloudNativeSDWAN/egress-watcher)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/CloudNativeSDWAN/egress-watcher)
[![Go Report Card](https://goreportcard.com/badge/github.com/CloudNativeSDWAN/egress-watcher)](https://goreportcard.com/report/github.com/CloudNativeSDWAN/egress-watcher)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CloudNativeSDWAN/egress-watcher/Test)
![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/CloudNativeSDWAN/egress-watcher?include_prereleases)

Reflect your *Egress* definitions from different object types to your
*SD-WAN* for processing and traffic optmization.

Find some context on the project in our [Talk](https://www.youtube.com/watch?v=POEedeeRs_8) @ KubeCon EU 2022 and in this *Cisco Tech Blog* [article](https://techblog.cisco.com/blog/tell-your-sd-wan).

Feel free to reach out with any comment or question, you can find us at: cnwan@cisco.com

## Supported projects and providers

### Supported Egress types

As of now, we support egress hosts defined as *ISTIO* `ServiceEntry` objects
or as IPs defined in the `Egress` fields of a *Kubernetes* `NetworkPolicy`,
and we reflect the changes we detect in them.

The project is designed to accomodate different types of egress policies or external services defined by other
projects.

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

## Quickstart

For a quick test of the project, you can try the `scripts/quickstart.sh` script
included in this repository that will guide you through deploying *Egress
Watcher* iteratively with some default values and working with an Istio's `ServiceEntry`
already prepared.

Simply run the script like the following from the root folder of the
repository:

```bash
./scripts/quickstart.sh
```

and follow the instructions from the script.

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

* `--kubeconfig`: path to the kubeconfig file to use.
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
* `--watch-all-network-policies`: as above, but with `NetworkPolicy` objects.
* `--sdwan.username`: the username for authentication. **Required**.
* `--sdwan.password`: the password for authentication. **Required**.
* `--sdwan.insecure`: whether to accept self-signed certificates.
* `--pretty-logs`: whether to log data in a slower but human readable format.
* `--verbosity`: to set up the verbosity level. It can be from `0` (most
verbose) to `3` (only log important errors). Default is `1`.
* `--waiting-window`: the duration of the waiting mode. Set this to 0 to
  disable it entirely. For example, if you set `1m`, Egress Watcher will
  wait one minute for other changes to appear before applying them in
  order to improve performance and do bulk operations. Default is `30s`.
* `--sdwan.enable`: whether to enable/disable the configuration/policies
  for the added applicaitons. By default, this is not enabled, which means
  that the egress watcher will just add/update/delete applications and will
  not enable or disable the policies that apply them.

As a rule of thumb, remember that flag options **overwrite** options provided
via file.

Please note that, as we support more egress types and SD-WANs, the above
flags and command may change.

### Watch objects

With default options the watcher will only watch supported objects that have
**label** `egress-watch: enabled` and ignore those that don't.

`--watch-all-service-entries` and `--watch-all-network-policies` makes the
program behave in the opposite way and in order to ignore them the **label**
`egress-watch: disabled` must be included in the object.

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

Try to deploy a `ServiceEntry` object. You can use the provided example in
`artifacts/yamls/examples/istio`:

```bash
# In another shell terminal
kubectl create -f ./artifacts/yamls/examples/istio
```

For a `NetworkPolicy` you can do instead:

```bash
# In another shell terminal
kubectl create -f ./artifacts/yamls/examples/network_policy
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

Now, on a separate shell terminal, deploy one of our provided examples:

```bash
# In another shell terminal...

# A service entry...
kubectl create -f ./artifacts/yamls/examples/istio

# Or a network policy
kubectl create -f ./artifacts/yamls/examples/network_policy
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
