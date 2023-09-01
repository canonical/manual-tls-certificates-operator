# TLS Certificates Operator

This charm is used to provide X.509 certificates in environments where certificates are obtained through a manual process.

## Usage

### Providing X.509 certificates to requesting units

The following Juju actions make it possible for the user to manually provide certificates to units of the requirer charm.
If the optional parameter relation-id is provided then only the information of the specified relation is returned.

The following action will return all certificate requests that don't have certificates already provided, along with further information (relation_id, application_name and unit_name)

```bash
juju run tls-certificates-operator/leader get-outstanding-certificate-requests \
  relation_id=<id>
```


The second action allows the user to provide the certificates and specify the csr.
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
