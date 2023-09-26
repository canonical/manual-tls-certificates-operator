# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import unittest
from unittest.mock import Mock, patch

from ops import testing
from ops.model import ActiveStatus

from charm import TLSCertificatesOperatorCharm

TLS_CERTIFICATES_PROVIDES_PATH = (
    "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2"
)


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

        csr = self.get_certificate_from_file(filename="tests/csr.pem")
        csr_bytes = TestCharm._encode_in_base64(csr)
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        certificate_bytes = TestCharm._encode_in_base64(certificate)
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_certificate_bytes = TestCharm._encode_in_base64(ca_certificate)
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        ca_chain_bytes = TestCharm._encode_in_base64(ca_chain)

        self.decoded_csr = TestCharm._decode_from_base64(csr_bytes)
        self.decoded_certificate = TestCharm._decode_from_base64(certificate_bytes)
        self.decoded_ca_certificate = TestCharm._decode_from_base64(ca_certificate_bytes)
        self.decoded_ca_chain = TestCharm._decode_from_base64(ca_chain_bytes)

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs_with_no_certs")
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
        self.harness.charm._set_active_status(Mock())
        self.assertEqual(
            ActiveStatus("1 outstanding requests, use juju actions to provide certificates"),
            self.harness.charm.unit.status,
        )

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs_with_no_certs")
    def test_given_no_units_with_no_certs_then_status_is_active_and_no_outstanding_requests(
        self, patch_get_requirer_units_csrs_with_no_certs
    ):
        patch_get_requirer_units_csrs_with_no_certs.return_value = []
        self.harness.charm._set_active_status(Mock())
        self.assertEqual(ActiveStatus("No outstanding requests."), self.harness.charm.unit.status)

    def test_given_no_requirer_application_when_get_outstanding_certificate_requests_action_then_event_fails(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.charm._on_get_outstanding_certificate_requests_action(event=event)
        event.fail.assert_called_once_with(
            message="No certificates relation has been created yet."
        )

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs_with_no_certs")
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

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs_with_no_certs")
    def test_given_requirer_and_no_outstanding_certs_when_get_outstanding_certificate_requests_action_then_empty_list_is_returned(  # noqa: E501
        self, patch_get_requirer_units_csrs_with_no_certs
    ):
        self.harness.add_relation("certificates", "requirer")
        patch_get_requirer_units_csrs_with_no_certs.return_value = []
        event = Mock()
        self.harness.charm._on_get_outstanding_certificate_requests_action(event=event)
        event.set_results.assert_called_once_with({"result": []})

    def test_given_relation_id_not_exist_when_get_outstanding_certificate_requests_action_then_action_returns_empty_list(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.add_relation("certificates", "requirer")
        event.params = {"relation_id": 1235}
        self.harness.charm._on_get_outstanding_certificate_requests_action(event=event)
        event.set_results.assert_called_once_with({"result": []})

    def test_given_relation_not_created_when_provide_certificate_action_then_event_fails(self):
        csr = self.get_certificate_from_file(filename="tests/csr.pem")
        csr = TestCharm._encode_in_base64(csr)

        event = Mock()
        event.params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": 1234,
        }

        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(
            message="No certificates relation has been created yet."
        )

    def test_given_certificate_not_encoded_correctly_when_provide_certificate_action_then_action_fails(  # noqa: E501
        self,
    ):
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

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs")
    def test_given_csr_does_not_exist_in_requirer_when_provide_certificate_action_then_event_fails(
        self, patch_get_requirer_csrs
    ):
        requirer_app_name = "requirer"
        relation_id = self.harness.add_relation("certificates", requirer_app_name)
        csr = self.get_certificate_from_file(filename="tests/csr.pem")
        csr = TestCharm._encode_in_base64(csr)

        example_unit_csrs = [
            {
                "relation_id": relation_id,
                "application_name": requirer_app_name,
                "unit_name": f"{requirer_app_name}/0",
                "unit_csrs": [],
            }
        ]
        patch_get_requirer_csrs.return_value = example_unit_csrs

        event = Mock()
        event.params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": relation_id,
        }
        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(
            message="Certificate signing request was not found in requirer data."
        )

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs")
    def test_given_not_matching_csr_and_certificate_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, patch_get_requirer_csrs
    ):
        requirer_app_name = "requirer"
        relation_id = self.harness.add_relation("certificates", requirer_app_name)
        csr_from_file = self.get_certificate_from_file(filename="tests/csr.pem")
        example_unit_csrs = [
            {
                "relation_id": relation_id,
                "application_name": requirer_app_name,
                "unit_name": f"{requirer_app_name}/0",
                "unit_csrs": [{"certificate_signing_request": csr_from_file}],
            }
        ]
        patch_get_requirer_csrs.return_value = example_unit_csrs
        incorrect_cert = self.decoded_ca_certificate

        event = Mock()
        event.params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": incorrect_cert,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": relation_id,
        }

        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Certificate and CSR do not match.")

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_valid_input_when_provide_certificate_action_then_certificate_is_provided(
        self, patch_set_relation_cert, patch_get_requirer_csrs
    ):
        requirer_app_name = "requirer"
        relation_id = self.harness.add_relation("certificates", requirer_app_name)
        csr_from_file = self.get_certificate_from_file(filename="tests/csr.pem")
        example_unit_csrs = [
            {
                "relation_id": relation_id,
                "application_name": requirer_app_name,
                "unit_name": f"{requirer_app_name}/0",
                "unit_csrs": [{"certificate_signing_request": csr_from_file}],
            }
        ]
        patch_get_requirer_csrs.return_value = example_unit_csrs

        event = Mock()
        event.params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": relation_id,
        }

        self.harness.charm._on_provide_certificate_action(event=event)
        event.set_results.assert_called_once_with(
            {"result": "Certificates successfully provided."}
        )
        patch_set_relation_cert.assert_called_once()

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_requirer_csrs")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_runtime_error_during_when_provide_certificate_action_then_event_fails(
        self, patch_set_relation_cert, patch_get_requirer_csrs
    ):
        requirer_app_name = "requirer"
        relation_id = self.harness.add_relation("certificates", requirer_app_name)
        csr_from_file = self.get_certificate_from_file(filename="tests/csr.pem")
        example_unit_csrs = [
            {
                "relation_id": relation_id,
                "application_name": requirer_app_name,
                "unit_name": f"{requirer_app_name}/0",
                "unit_csrs": [{"certificate_signing_request": csr_from_file}],
            }
        ]
        patch_get_requirer_csrs.return_value = example_unit_csrs
        patch_set_relation_cert.side_effect = RuntimeError()

        event = Mock()
        event.params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": relation_id,
        }

        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Relation does not exist with the provided id.")
