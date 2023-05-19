# tls-certificates-operator

This charm is used for applications requiring TLS certificates.

## Usage

### With user provided certificates

Here we use a set of certificates placed them under the working directory.

```bash
juju deploy tls-certificates-operator \
 --config certificate="$(base64 -w0 certificate.pem)" \
 --config ca-chain="$(base64 -w0 ca_chain.pem)" \
 --config ca-certificate="$(base64 -w0 ca_certificate.pem)"
juju relate tls-certificates-operator your-charm
```

### With self-signed certificates (deprecated)

> **Warning**: This feature is deprecated and will be dropped in the future, please use the 
> [self-signed-certificates](https://charmhub.io/self-signed-certificates) operator.

```bash
juju deploy tls-certificates-operator \
  --config generate-self-signed-certificates=true \
  --config ca-common-name=<your ca common name>
juju relate tls-certificates-operator your-charm
```

## Config

List of configuration options:
- **generate-self-signed-certificates (boolean)**: Generate self-signed certificates and ignores provided certificates.
- **ca-common-name (string)**: Certificate Authority Common Name (only use if 'generate-self-signed-certificates' is set to true).
- **certificate (string)**: Base64 encoded TLS certificate (do not use if 'generate-self-signed-certificates' is set to true).
- **ca-certificate (string)**: Base64 encoded CA Certificate (do not use if 'generate-self-signed-certificates' is set to true).
- **ca-chain (string)**: Base64 encoded CA Chain (do not use if 'generate-self-signed-certificates' is set to true).
- **ca-certificate-validity(int)**: Integer representing the number of days for which the self-signed certificates are valid (only use if 'generate-self-signed-certificates' is set to true). Its value should not be smaller than `certificate-validity`.
- **certificate-validity(int)**: Integer representing the number of days for which the self-signed certificates are valid (only use if 'generate-self-signed-certificates' is set to true). Its value should not be larger than `ca-certificate-validity`.


## Relations

This charm provides certificates using the `tls-certificates` relation.
