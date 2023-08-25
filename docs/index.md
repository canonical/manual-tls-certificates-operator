The TLS Certificates Operator charm is responsible for distributing x.509 certificates in contexts where certificates are obtained through a manual process.

## Usage
Deploy the charm:
```shell
juju deploy tls-certificates-operator
juju status --watch 1s
```
The deployment of the charm is completed when its status is in `Active/Idle` state.

At this point you can relate the TLS Certificates Operator to a requirer of TLS certificates through the `tls-certificates` interface:
```shell
juju relate tls-certificates-operator <your-charm>
```

## In this documentation

|                                                                                                                                                          |
|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| [How-to guides](/t/tls-certificates-operator-how-to-provision-certificates/11612) </br> **Step-by-step guides** covering key operations and common tasks |
| [Reference](https://charmhub.io/tls-certificates-operator/actions) </br> **Technical information** - specifications, APIs, architecture                  |

## Project and community

TLS Certificates Operator is a member of the Ubuntu family. It’s an open source project that warmly welcomes community projects, contributions, suggestions, fixes and constructive feedback.

* [Code of conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Contribute and report bugs to the [charm](https://github.com/canonical/tls-certificates-operator)

# Navigation
| Level | Path                     | Navlink                                                                                    |
|-------|--------------------------|--------------------------------------------------------------------------------------------|
| 1     | how-to                   | [How-to guides]()                                                                          |
| 2     | h-provision-certificates | [Provision certificates](/t/tls-certificates-operator-how-to-provision-certificates/11612) |
| 1     | reference                | [Reference]()                                                                              |
| 2     | r-actions                | [Actions](https://charmhub.io/tls-certificates-operator/actions)                           |
| 2     | r-configurations         | [Configurations](https://charmhub.io/tls-certificates-operator/configure)                  |
| 2     | r-integrations           | [Integrations](https://charmhub.io/tls-certificates-operator/integrations)                 |
| 2     | r-libraries              | [Libraries](https://charmhub.io/tls-certificates-operator/libraries)                       |
| 2     | r-resources              | [Resources](https://charmhub.io/tls-certificates-operator/resources)                       |