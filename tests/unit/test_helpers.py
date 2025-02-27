# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from datetime import timedelta

from charms.tls_certificates_interface.v4.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from cryptography import x509

from helpers import parse_ca_chain


class TestHelpers(unittest.TestCase):
    def test_give_valid_ca_chain_when_parse_ca_chain_then_list_of_certificates_is_returned(
        self,
    ):
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            validity=timedelta(days=365),
            common_name="Test CA",
        )
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="Test Certificate",
        )
        certificate = generate_certificate(
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=timedelta(days=365),
            csr=csr,
        )
        ca_chain = f"{str(certificate)}\n{str(ca_certificate)}"

        ca_chain_list = parse_ca_chain(ca_chain)
        self.assertEqual(len(ca_chain_list), 2)
        for cert in ca_chain_list:
            self.assertIsInstance(cert, x509.Certificate)

    def test_given_invalid_ca_chain_when_parse_ca_chain_then_value_error_is_raised(
        self,
    ):
        ca_chain = "Not a CA Chain"
        with self.assertRaises(ValueError):
            parse_ca_chain(ca_chain)

    def test_given_invalid_issuer_ca_chain_when_parse_ca_chain_then_value_error_is_raised(self):
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            validity=timedelta(days=365),
            common_name="Test CA",
        )
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="Test Certificate",
        )
        certificate = generate_certificate(
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=timedelta(days=365),
            csr=csr,
        )
        ca_chain = f"{str(ca_certificate)}\n{str(certificate)}"
        with self.assertRaises(ValueError):
            parse_ca_chain(ca_chain)
