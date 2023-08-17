# Get TLS Certificates Operator up and running
This is part of the [TLS Certificates Operator Tutorial](/t/tls-certificates-operator-tutorial-overview/11605). Please refer to this page for more information and the overview of the content.

## Deploy TLS Certificates Operator
To deploy the TLS Certificates Operator, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/tls-certificates-operator) and deploy it to your model:
```shell
juju deploy tls-certificates-operator
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
tls-certificates-operator           active      1  tls-certificates-operator  stable    22  10.152.183.167  no       installing agent

Unit                          Workload  Agent  Address       Ports  Message
tls-certificates-operator/0*  blocked   idle   10.1.142.108         Configuration options missing: ['certificate', 'ca-certificate']
```
To exit the screen from `juju status --watch 1s`, enter `Ctrl+c`.
If you want to further inspect juju logs, can watch for logs with `juju debug-log`.
More info on logging at [juju logs](https://juju.is/docs/olm/juju-logs).

The deployment of the charm is completed when its status is in `Waiting/Idle` state.