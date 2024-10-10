# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from datetime import timedelta
from typing import List

from charms.tls_certificates_interface.v4.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)

from helpers import (
    ca_chain_is_valid,
    certificate_is_valid,
    certificate_signing_request_is_valid,
    parse_ca_chain,
)


class TestHelpers(unittest.TestCase):
    def test_given_valid_certificate_when_certificate_is_valid_then_returns_true(
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
        certificate_bytes = str(certificate).encode("utf-8")
        self.assertTrue(certificate_is_valid(certificate_bytes))

    def test_given_invalid_certificate_when_certificate_is_valid_then_returns_false(
        self,
    ):
        certificate = "Not a valid certificate"
        certificate_bytes = certificate.encode("utf-8")
        self.assertFalse(certificate_is_valid(certificate_bytes))

    def test_given_valid_certificate_signing_request_when_certificate_signing_request_is_valid_then_returns_true(  # noqa: E501
        self,
    ):
        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            common_name="Test Certificate",
        )
        certificate_signing_request_bytes = str(csr).encode("utf-8")
        self.assertTrue(certificate_signing_request_is_valid(certificate_signing_request_bytes))

    def test_given_invalid_certificate_signing_request_when_certificate_signing_request_is_valid_then_returns_false(  # noqa: E501
        self,
    ):
        certificate_signing_request = "Not a certificate signing request"
        certificate_signing_request_bytes = certificate_signing_request.encode("utf-8")
        self.assertFalse(certificate_signing_request_is_valid(certificate_signing_request_bytes))

    def test_give_ca_chain_when_parse_ca_chain_then_list_of_certificates_is_returned(
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
        ca_chain = f"{str(ca_certificate)}\n{str(certificate)}"

        ca_chain_list = parse_ca_chain(ca_chain)
        self.assertEqual(len(ca_chain_list), 2)
        certificate_1_bytes = ca_chain_list[0].encode("utf-8")
        certificate_2_bytes = ca_chain_list[1].encode("utf-8")
        self.assertTrue(certificate_is_valid(certificate_1_bytes))
        self.assertTrue(certificate_is_valid(certificate_2_bytes))

    def test_given_invalid_ca_chain_when_parse_ca_chain_then_value_error_is_raised(
        self,
    ):
        ca_chain = "Not a CA Chain"
        with self.assertRaises(ValueError):
            parse_ca_chain(ca_chain)

    def test_given_valid_ca_chain_when_ca_chain_is_valid_then_returns_true(self):
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
        ca_chain_list = parse_ca_chain(ca_chain)
        self.assertTrue(ca_chain_is_valid(ca_chain_list))

    def test_given_empty_list_ca_chain_when_ca_chain_is_valid_returns_false(self):
        ca_chain_list: List[str] = []
        self.assertFalse(ca_chain_is_valid(ca_chain_list))

    def test_given_zero_certificate_in_ca_chain_when_ca_chain_is_valid_returns_false(self):
        self.assertFalse(ca_chain_is_valid([]))

    def test_given_invalid_issuer_ca_chain_when_ca_chain_is_valid_returns_false(self):
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
        ca_chain_list = parse_ca_chain(ca_chain)
        ca_chain_list.reverse()
        self.assertFalse(ca_chain_is_valid(ca_chain_list))

    def test_given_invalid_certificate_in_ca_chain_when_ca_chain_is_valid_then_returns_false(self):
        ca_chain = "Not a CA Chain"
        ca_chain_list = [ca_chain, ca_chain]
        self.assertFalse(ca_chain_is_valid(ca_chain_list))
