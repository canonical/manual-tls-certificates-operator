#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Methods used to generate self-signed certificates."""

import re
from typing import List

from cryptography import x509


def certificate_is_valid(certificate: bytes) -> bool:
    """Returns whether a certificate is valid.

    Args:
        certificate: Certificate in bytes

    Returns:
        bool: True/False
    """
    try:
        x509.load_pem_x509_certificate(certificate)
        return True
    except ValueError:
        return False


def certificate_signing_request_is_valid(certificate_signing_request: bytes) -> bool:
    """Returns whether a certificate request is valid.

    Args:
        certificate_signing_request: Certificate signing request in bytes

    Returns:
        bool: True/False
    """
    try:
        x509.load_pem_x509_csr(certificate_signing_request)
        return True
    except ValueError:
        return False


def parse_ca_chain(ca_chain_pem: str) -> List[str]:
    """Returns list of certificates based on a PEM CA Chain file.

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
    chain_list = re.findall(
        pattern="(?=-----BEGIN CERTIFICATE-----)(.*?)(?<=-----END CERTIFICATE-----)",
        string=ca_chain_pem,
        flags=re.DOTALL,
    )
    if not chain_list:
        raise ValueError("No certificate found in chain file")
    return chain_list
