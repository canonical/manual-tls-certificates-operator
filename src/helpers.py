#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Methods used to generate self-signed certificates."""

import logging
from typing import List

from cryptography import x509
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


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
    chain = x509.load_pem_x509_certificates(ca_chain_pem.encode("utf-8"))
    for cert, ca_cert in zip(chain, chain[1:]):
        try:
            cert.verify_directly_issued_by(ca_cert)
        except (ValueError, TypeError, InvalidSignature) as e:
            raise ValueError("Invalid CA chain: %s", e)
    return chain
