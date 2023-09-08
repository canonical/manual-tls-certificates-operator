# How to provide TLS certificates to requesting charms
TLS Certificates Operator allows the provisioning of certificates to requiring charms.

## 1. Retrieve the certificate signing request
The first thing is to retrieve the certificate signing request created by the requirer application.
To do so, the TLS Certificates Operator provides two actions:
* `get-outstanding-certificate-requests`: returns all certificate signing requests without an associated certificate
* `get-certificate-request`: returns the certificate signing request for a specific relation ID

The following sections explain how to run both of them.

### a. Retrieve all certificates signing requests without an associated certificate
The following action will return all certificate signing requests that don't have certificates already provided, along with further information (`relation-id`, `application_name` and `unit_name`):
```shell
juju run tls-certificates-operator/leader get-outstanding-certificate-requests
```

### b. Retrieve a specific certificate signing request
The following action is used to get the certificate signing request and its information of a specific relation by providing the `relation-id` as a parameter:
```shell
juju run tls-certificates-operator/leader get-certificate-request \
  relation-id=<id>
```

The output of this action is the certificate signing request, which will be used by your trusted certificate provider to generate a certificate for the application.

## 2. Provide the certificate
Once you have the certificate signed, it is possible to provide it to the application unit which requested it.

The following action is used to provide the certificate to the requirer, allowing to specify the associated certificate signing request and unit name:
```shell
juju run tls-certificates-operator/leader provide-certificate \
  relation-id=<id> \
  certificate="$(base64 -w0 certificate.pem)" \
  ca-chain="$(base64 -w0 ca-chain.pem)" \
  ca-certificate="$(base64 -w0 ca-certificate.pem)" \
  certificate-signing-request="$(base64 -w0 csr.pem)" \
  unit-name="<unit-name>"
```
At this point the certificate is available for the requirer unit which requested it.