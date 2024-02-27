#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Methods used to generate self-signed certificates."""

import logging
import re
from typing import List

from cryptography import x509
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


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


def ca_chain_is_valid(ca_chain: List[str]) -> bool:
    """Returns whether a ca chain is valid.

    It uses the x509 certificate method verify_directly_issued_by, which checks
    the certificate issuer name matches the issuer subject name and that
    the certificate is signed by the issuer's private key.

    Args:
        ca_chain: composed by a list of certificates.

    Returns:
        whether the ca chain is valid.
    """
    if len(ca_chain) < 1:
        logger.warning("Invalid CA chain: It must contain at least 1 certificates.")
        return False
    for ca_cert, cert in zip(ca_chain, ca_chain[1:]):
        try:
            ca_cert_object = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
            cert_object = x509.load_pem_x509_certificate(cert.encode("utf-8"))
            cert_object.verify_directly_issued_by(ca_cert_object)
        except (ValueError, TypeError, InvalidSignature) as e:
            logger.warning("Invalid CA chain: %s", e)
            return False
    return True
