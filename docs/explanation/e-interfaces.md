# Interfaces/endpoints

The charm supports `tls-certificates` interface.

Adding a relation is accomplished with `juju relate` (or `juju integrate` for Juju 3.x) via endpoint `database`. Example:

```shell
# Deploy TLS Certificates Operator
juju deploy tls-certificates-operator

# Deploy the relevant application charms
juju deploy <your-charm>

# Relate TLS Certificates Operator with your application
juju relate tls-certificates-operator <your-charm>

# Check established relation (using tls-certificates interface):
juju status --relations

# Example of the properly established relation:
Relation provider                       Requirer                   Interface         Type
tls-certificates-operator:certificates  <your-charm>:certificates  tls-certificates  regular
```