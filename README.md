# TLS Certificates Operator

This charm is used to provide X.509 certificates in environments where certificates are obtained through a manual process.

## Usage

Deploy the charm and integrate it to a certificate requirer:

```bash
juju deploy tls-certificates-operator --channel beta
juju integrate tls-certificates-operator <TLS Certificates Requirer>
```

### Providing X.509 certificates to requesting units

The following Juju actions make it possible for the user to manually provide certificates to units of the requirer charm.
If the optional parameter relation-id is provided then only the information of the specified relation is returned.

The following action will return all certificate requests that don't have certificates already provided, along with further information (relation-id, application_name and unit_name)

```bash
juju run-action tls-certificates-operator/leader get-outstanding-certificate-requests \
  relation-id=<id>
```


The second action allows the user to provide the certificates and specify the csr.
```bash
juju run-action tls-certificates-operator/leader provide-certificate \
  relation-id=<id> \
  certificate="$(base64 -w0 certificate.pem)" \
  ca-chain="$(base64 -w0 ca-chain.pem)" \
  ca-certificate="$(base64 -w0 ca-certificate.pem)" \
  certificate-signing-request="$(base64 -w0 csr.pem)" \
```

## Integrations

This charm provides certificates using the `tls-certificates` integration.
