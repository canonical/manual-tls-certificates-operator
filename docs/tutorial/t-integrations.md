# Relate TLS Certificates Operator to other charms
This is part of the [TLS Certificates Operator Tutorial](/t/tls-certificates-operator-tutorial-overview/11605). Please refer to this page for more information and the overview of the content.

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