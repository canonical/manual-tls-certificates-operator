# Configuration of TLS Certificates Operator
This is part of the [TLS Certificates Operator Tutorial](/t/tls-certificates-operator-tutorial-overview/11605). Please refer to this page for more information and the overview of the content.

## Requirements
In this page it is assumed that the CA certificate, application certificate and CA chain certificate (if required) are already provided and located in the working directory.

## Configure application certificate
To configure the application certificate, named `certificate.pem`:
```shell
juju config tls-certificates-operator certificate=$(base64 -w0 certificate.pem)
```

## Configure certificate authority (CA) certificate
To configure the CA certificate, named `ca_certificate.pem`:
```shell
juju config tls-certificates-operator ca-certificate=$(base64 -w0 ca_certificate.pem)
```

At this point, the charm should be in `Active/Idle` state.

## Configure certificate authority (CA) chain
If required, it is possible to configure also the CA chain. To do so, assuming CA chain is named `ca_chain.pem`:
```shell
juju config tls-certificates-operator ca-chain=$(base64 -w0 ca_chain.pem)
```