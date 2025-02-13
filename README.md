# Manual TLS Certificates
[![CharmHub Badge](https://charmhub.io/manual-tls-certificates/badge.svg)](https://charmhub.io/manual-tls-certificates)

This charm is used to provide X.509 certificates in environments where certificates are obtained through a manual process.

## Usage as a certificate authority

Deploy the charm and integrate it to a certificate requirer:

```bash
juju deploy manual-tls-certificates --channel beta
juju integrate manual-tls-certificates <TLS Certificates Requirer>
```

### Providing X.509 certificates to requesting units

The following Juju actions make it possible for the user to manually provide certificates to units of the requirer charm.
If the optional parameter relation-id is provided then only the information of the specified relation is returned.

The following action will return all certificate requests that don't have certificates already provided, along with further information (relation-id, application_name and unit_name)

NOTE: If you happen to scale `manual-tls-certificates`, you must run actions on the leader unit. However, there is currently no benefit to scaling this charm.

```bash
juju run manual-tls-certificates/leader get-outstanding-certificate-requests relation-id=<id>
```

The second action allows the user to provide the certificates and specify the csr.

```bash
juju run manual-tls-certificates/leader provide-certificate \
  relation-id=<id> \
  certificate="$(base64 -w0 certificate.pem)" \
  ca-chain="$(base64 -w0 ca-chain.pem)" \
  ca-certificate="$(base64 -w0 ca-certificate.pem)" \
  certificate-signing-request="$(base64 -w0 csr.pem)" \
```

## Usage as a provider of certificates to trust

Deploy the charm and integrate it to requirer of `certificate_transfer`:

```bash
juju deploy --channel beta manual-tls-certificates trusted-certificates
juju integrate trusted-certificates <Certificate Transfer Requirer>
```

### Configuring trusted certificates

The charm supports the `trusted-certificate-bundle` configuration to provide
a list of certificates that requirers should trust, in PEM format.

Assuming you have a list of certificates that should be trusted in the file
`bundle.yaml` that looks like this:

```pem
-----BEGIN CERTIFICATE-----
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
bTvWRcTns/sRTw1iXlmwXT0K1yQgeDjG/2s=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
```

You can configure the charm with that bundle with the command:

```bash
juju config trusted-certificates trusted-certificate-bundle="$(cat bundle.pem)"
```

## Integrations

This charm provides signed certificates for CSRs using the `tls-certificates` integration.

This charm provides certificates to trust using the `certificate-transfer` integration
