# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import unittest
from unittest.mock import Mock, patch

from ops import testing
from ops.model import ActiveStatus

from charm import TLSCertificatesOperatorCharm


class TestCharm(unittest.TestCase):
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
        self.harness.set_leader(True)
        self.harness.begin()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.get_requirer_csrs_with_no_certs"  # noqa: E501, W505
    )
    def test_given_outstanding_requests_when_certificate_creation_request_then_status_is_active(
        self, patch_get_requirer_units_csrs_with_no_certs
    ):
        patch_get_requirer_units_csrs_with_no_certs.return_value = [
            {
                "relation_id": 1234,
                "unit_name": "unit/0",
                "application_name": "application",
                "unit_csrs": [{"certificate_signing_request": "some csr"}],
            }
        ]
        self.harness.charm._on_certificate_creation_request(Mock())
        self.assertEqual(
            ActiveStatus("1 outstanding requests, use juju actions to provide certificates"),
            self.harness.charm.unit.status,
        )

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
        event.set_results.assert_called_once_with({"result": example_unit_csrs})

    def test_given_relation_id_not_exist_when_get_certificate_request_action_then_action_returns_empty_list(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.add_relation("certificates", "requirer")
        event.params = {"relation_id": 1235}
        self.harness.charm._on_get_certificate_request_action(event=event)
        event.set_results.assert_called_once_with({"result": []})

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_valid_input_when_provide_certificate_action_then_certificate_is_provided(
        self,
        patch_set_relation_certificate,
    ):
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
            "certificate_signing_request": TestCharm._decode_from_base64(csr),
            "certificate": TestCharm._decode_from_base64(certificate_bytes),
            "ca_certificate": TestCharm._decode_from_base64(ca_certificate_bytes),
            "ca_chain": TestCharm._decode_from_base64(ca_chain_bytes),
            "relation_id": 1234,
        }
        self.harness.charm._on_provide_certificate_action(event=event)
        event.set_results.assert_called_once_with(
            {"result": "Certificates successfully provided."}
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_not_encoded_correctly_when_provide_certificate_action_then_action_fails(  # noqa: E501
        self,
        patch_set_relation_certificate,
    ):
        self.harness.add_relation("certificates", "requirer")
        event = Mock()
        event.params = {
            "certificate_signing_request": "wrong encoding",
            "certificate": "wrong encoding",
            "ca_certificate": "wrong encoding",
            "ca_chain": "wrong encoding",
            "relation_id": 1234,
        }
        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Action input is not valid.")
