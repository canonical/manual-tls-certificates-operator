# tls-certificates-operator

This charm is used to provide X.509 certificates in environments where certificates are obtained through a manual process.

## Usage

### Providing X.509 certificates to requesting units

The following three Juju actions make it possible for the user to manually provide certificates to units of the requirer charm.

The following action will return all certificate requests that don't have certificates already provided, along with further information (relation_id, application_name and unit_name)

```bash
juju run tls-certificates-operator/leader get-outstanding-certificate-requests
```

The second action is used to get the certificate requests and their information from a specific relation by providing the relation_id as a parameter:

```bash
juju run tls-certificates-operator/leader get-certificate-request \
  relation_id=<id>
```

The third action allows the user to provide the certificates and specify the csr.
```bash
juju run tls-certificates-operator/leader provide-certificate \
  relation_id=<id> \
  certificate="$(base64 -w0 certificate.pem)" \
  ca_chain="$(base64 -w0 ca_chain.pem)" \
  ca_certificate="$(base64 -w0 ca_certificate.pem)" \
  certificate_signing_request="$(base64 -w0 csr.pem)\
```

## Relations

This charm provides certificates using the `tls-certificates` relation.
