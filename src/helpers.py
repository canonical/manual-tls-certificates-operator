#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Methods used to generate self-signed certificates."""

import logging
from typing import List

from cryptography import x509
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


class InvalidCAChainError(ValueError):
    """Raised when a CA chain cannot be parsed or validated."""


def parse_pem_bundle(pem_bundle: str) -> List[x509.Certificate]:
    """Return list of certificates contained in a PEM bundle.

    Args:
        pem_bundle (str): String containing list of certificates in PEM format

    Returns:
        list: List of certificates

    Raises:
        ValueError: if the argument cannot be parsed
    """
    return x509.load_pem_x509_certificates(pem_bundle.encode("utf-8"))


def parse_ca_chain(ca_chain_pem: str) -> List[x509.Certificate]:
    """Return list of certificates based on a PEM CA Chain file.

    Args:
        ca_chain_pem (str): String containing list of certificates. This string should look like:
            -----BEGIN CERTIFICATE-----
            <cert 1>
            -----END CERTIFICATE-----
            -----BEGIN CERTIFICATE-----
            <cert 2>
            -----END CERTIFICATE-----

    Returns:
        list: List of certificates
    """
    try:
        chain = parse_pem_bundle(ca_chain_pem)
    except ValueError as e:
        raise InvalidCAChainError(
            "Invalid CA chain: unable to parse the certificate bundle."
        ) from e
    for index, (cert, ca_cert) in enumerate(zip(chain, chain[1:]), start=1):
        if cert.issuer != ca_cert.subject:
            raise InvalidCAChainError(
                f"Invalid CA chain: certificate {index}'s issuer does not match certificate "
                f"{index + 1}'s subject. Certificates must be ordered from the leaf certificate "
                "to the root CA certificate."
            )
        try:
            cert.verify_directly_issued_by(ca_cert)
        except (ValueError, TypeError, InvalidSignature) as e:
            raise InvalidCAChainError(
                f"Invalid CA chain: certificate {index} is not directly signed by certificate "
                f"{index + 1}."
            ) from e
    return chain
