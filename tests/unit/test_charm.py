# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import unittest
from unittest.mock import Mock, patch

from ops import testing

from charm import TLSCertificatesOperatorCharm


class TestCharm(unittest.TestCase):
    # TODO use these methods
    @staticmethod
    def _decode_from_base64(bytes_content: bytes) -> str:
        return bytes_content.decode("utf-8")

    @staticmethod
    def _encode_in_base64(string_content: str) -> bytes:
        """Decodes given string to Base64.

        Args:
            string_content (str): String content

        Returns:
            bytes: bytes
        """
        return base64.b64encode(string_content.encode("utf-8"))

    @staticmethod
    def get_certificate_from_file(filename: str) -> str:
        with open(filename, "r") as file:
            certificate = file.read()
        return certificate

    def setUp(self):
        self.harness = testing.Harness(TLSCertificatesOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_no_requirer_application_when_get_outstanding_certificate_requests_action_then_empty_list_returned(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.charm._on_get_outstanding_certificate_requests_action(event=event)
        event.fail.assert_called_once_with(
            message="No certificates relation has been created yet."
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.get_requirer_csrs_with_no_certs"  # noqa: E501, W505
    )
    def test_given_requirer_application_when_get_outstanding_certificate_requests_action_then_csrs_information_is_returned(  # noqa: E501
        self, patch_get_requirer_units_csrs_with_no_certs
    ):
        self.harness.add_relation("certificates", "requirer")
        example_unit_csrs = [
            {
                "relation_id": 1234,
                "unit_name": "unit/0",
                "application_name": "application",
                "unit_csrs": [{"certificate_signing_request": "some csr"}],
            }
        ]
        patch_get_requirer_units_csrs_with_no_certs.return_value = example_unit_csrs
        event = Mock()
        self.harness.charm._on_get_outstanding_certificate_requests_action(event=event)
        event.set_results.assert_called_once_with({"Result": example_unit_csrs})

    def test_given_relation_id_not_exist_when_get_certificate_request_action_then_action_returns_empty_list(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.add_relation("certificates", "requirer")
        event.params = {"relation-id": 1235}
        self.harness.charm._on_get_certificate_request_action(event=event)
        event.set_results.assert_called_once_with({"Result": []})

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_valid_input_when_provide_certificate_action_then_certificate_is_provided(
        self,
        patch_set_relation_certificate,
    ):
        self.harness.set_leader(True)
        self.harness.add_relation("certificates", "requirer")
        csr = self.get_certificate_from_file(filename="tests/csr.pem")
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        csr = TestCharm._encode_in_base64(csr)
        certificate_bytes = TestCharm._encode_in_base64(certificate)
        ca_certificate_bytes = TestCharm._encode_in_base64(ca_certificate)
        ca_chain_bytes = TestCharm._encode_in_base64(ca_chain)

        event = Mock()
        event.params = {
            "certificate-signing-request": TestCharm._decode_from_base64(csr),
            "certificate": TestCharm._decode_from_base64(certificate_bytes),
            "ca-certificate": TestCharm._decode_from_base64(ca_certificate_bytes),
            "ca-chain": TestCharm._decode_from_base64(ca_chain_bytes),
            "relation-id": 1234,
        }
        self.harness.charm._on_provide_certificate_action(event=event)
        event.set_results.assert_called_once_with(
            {"Result": "Certificates successfully provided."}
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_not_encoded_correctly_when_provide_certificate_action_then_action_fails(  # noqa: E501
        self,
        patch_set_relation_certificate,
    ):
        self.harness.set_leader(True)
        self.harness.add_relation("certificates", "requirer")
        event = Mock()
        event.params = {
            "certificate-signing-request": "wrong encoding",
            "certificate": "wrong encoding",
            "ca-certificate": "wrong encoding",
            "ca-chain": "wrong encoding",
            "relation-id": 1234,
        }
        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Action input is not valid.")

    def given_unit_is_not_leader_when_provide_certificate_action_then_action_fails(self):
        csr = TestCharm._encode_in_base64("whatever csr")
        certificate = TestCharm._encode_in_base64("whatever cert")
        ca = TestCharm._encode_in_base64("whatever ca")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        ca_chain_bytes = TestCharm._encode_in_base64(ca_chain)
        event = Mock()
        event.params = {
            "certificate-signing-request": TestCharm._decode_from_base64(csr),
            "certificate": TestCharm._decode_from_base64(certificate),
            "ca-certificate": TestCharm._decode_from_base64(ca),
            "ca-chain": TestCharm._decode_from_base64(ca_chain_bytes),
            "relation-id": 1234,
        }
        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Action cannot be run on non-leader unit.")
