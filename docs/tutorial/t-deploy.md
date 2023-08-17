# Get TLS Certificates Operator up and running
This is part of the [TLS Certificates Operator Tutorial](/t/tls-certificates-operator-tutorial-overview/11605). Please refer to this page for more information and the overview of the content.

## Requirements
In this tutorial it is assumed that the CA certificate, application certificate and CA chain certificate (if required) are already provided and located in the working directory.

## Deploy TLS Certificates Operator
To deploy the TLS Certificates Operator, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/tls-certificates-operator) and deploy it to your model:
```shell
juju deploy tls-certificates-operator \
  --config certificate=$(base64 -w0 certificate.pem) \
  --config ca-certificate=$(base64 -w0 ca_certificate.pem)
```

Juju will now fetch TLS Certificates Operator and begin deploying it to the local MicroK8s. This process can take several minutes depending on how provisioned (RAM, CPU, etc) your machine is. You can track the progress by running:
```shell
juju status --watch 1s
```

This command is useful for checking the status of TLS Certificates Operator and gathering information about the machines hosting TLS Certificates Operator. Some of the helpful information it displays include IP addresses, ports, state, etc. The command updates the status of TLS Certificates Operator every second and as the application starts you can watch the status and messages of TLS Certificates Operator change. Wait until the application is ready - when it is ready, `juju status` will show:
```shell
Model     Controller  Cloud/Region        Version  SLA          Timestamp
tutorial  charm-dev   microk8s/localhost  3.1.5    unsupported  12:00:43+01:00

App                        Version  Status  Scale  Charm                      Channel  Rev  Address         Exposed  Message
tls-certificates-operator           active      1  tls-certificates-operator  stable    22  10.152.183.167  no

Unit                          Workload  Agent  Address       Ports  Message
tls-certificates-operator/0*  active   idle   10.1.142.108
```
To exit the screen from `juju status --watch 1s`, enter `Ctrl+c`.
If you want to further inspect juju logs, can watch for logs with `juju debug-log`.
More info on logging at [juju logs](https://juju.is/docs/olm/juju-logs).

The deployment of the charm is completed when its status is in `Active/Idle` state.

## Configure certificate authority (CA) chain (Optional)
If required, it is possible to configure also the CA chain. To do so, assuming CA chain is named `ca_chain.pem`:
```shell
juju config tls-certificates-operator ca-chain=$(base64 -w0 ca_chain.pem)
```

## Integrations (Relations for Juju 2.9)
Relations, or what Juju 3.0+ documentation [describes as an Integration](https://juju.is/docs/sdk/integration), are the way to provide the configured certificates for the desired application.

To relate the TLS Certificates Operator charm to any charm through the `tls-certificates` interface:
```shell
juju relate tls-certificates-operator <your-charm>
```
Wait for `juju status --watch 1s` to show all applications/units as `active`.

You can check that the relation is established issuing `juju status --relations`:
```
# Example of the properly established relation:
Relation provider                       Requirer                   Interface         Type
tls-certificates-operator:certificates  <your-charm>:certificates  tls-certificates  regular
```