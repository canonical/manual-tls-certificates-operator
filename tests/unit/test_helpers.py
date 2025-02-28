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

from helpers import parse_ca_chain, parse_pem_bundle


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

    def test_given_multiple_certificates_not_as_a_chain_when_parse_pem_bundle_then_certificates_are_returned(  # noqa: E501
        self,
    ):
        private_key1 = generate_private_key()
        certificate1 = generate_ca(
            private_key=private_key1,
            validity=timedelta(days=365),
            common_name="Test CA 1",
        )
        private_key2 = generate_private_key()
        certificate2 = generate_ca(
            private_key=private_key2,
            validity=timedelta(days=365),
            common_name="Test CA 2",
        )
        private_key3 = generate_private_key()
        certificate3 = generate_ca(
            private_key=private_key3,
            validity=timedelta(days=365),
            common_name="Test CA 3",
        )
        pem_bundle = "\n".join(str(cert) for cert in (certificate1, certificate2, certificate3))
        certificates = parse_pem_bundle(pem_bundle)
        self.assertEqual(len(certificates), 3)
        for cert in certificates:
            self.assertIsInstance(cert, x509.Certificate)
