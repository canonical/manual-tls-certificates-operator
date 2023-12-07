# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from typing import List

from helpers import (
    ca_chain_is_valid,
    certificate_is_valid,
    certificate_signing_request_is_valid,
    parse_ca_chain,
)


class TestHelpers(unittest.TestCase):
    @staticmethod
    def get_certificate_from_file(filename: str) -> str:
        with open(filename, "r") as file:
            certificate = file.read()
        return certificate

    def test_given_valid_certificate_when_certificate_is_valid_then_returns_true(
        self,
    ):
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        certificate_bytes = certificate.encode("utf-8")
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
        certificate_signing_request = self.get_certificate_from_file(filename="tests/csr.pem")
        certificate_signing_request_bytes = certificate_signing_request.encode("utf-8")
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
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
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
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        ca_chain_list = parse_ca_chain(ca_chain)
        self.assertTrue(ca_chain_is_valid(ca_chain_list))

    def test_given_empty_list_ca_chain_when_ca_chain_is_valid_returns_false(self):
        ca_chain_list: List[str] = []
        self.assertFalse(ca_chain_is_valid(ca_chain_list))

    def test_given_one_certificate_in_ca_chain_when_ca_chain_is_valid_returns_false(self):
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        ca_chain_list = parse_ca_chain(ca_chain)[:-1]
        self.assertFalse(ca_chain_is_valid(ca_chain_list))

    def test_given_invalid_issuer_ca_chain_when_ca_chain_is_valid_returns_false(self):
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        ca_chain_list = parse_ca_chain(ca_chain)
        ca_chain_list.reverse()
        self.assertFalse(ca_chain_is_valid(ca_chain_list))

    def test_given_invalid_certificate_in_ca_chain_when_ca_chain_is_valid_then_returns_false(self):
        ca_chain = "Not a CA Chain"
        ca_chain_list = [ca_chain, ca_chain]
        self.assertFalse(ca_chain_is_valid(ca_chain_list))
