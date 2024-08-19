# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import json
from unittest.mock import patch

import pytest
import scenario
from charms.tls_certificates_interface.v4.tls_certificates import (
    RequirerCSR,
    TLSCertificatesError,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops.model import ActiveStatus

from charm import ManualTLSCertificatesCharm

TLS_CERTIFICATES_PROVIDES_PATH = (
    "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesProvidesV4"
)


class TestCharm:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=ManualTLSCertificatesCharm,
        )

    @staticmethod
    def _decode_from_base64(bytes_content: bytes) -> str:
        return bytes_content.decode("utf-8")

    @staticmethod
    def _encode_in_base64(string_content: str) -> bytes:
        """Decode given string to Base64.

        Args:
            string_content (str): String content

        Returns:
            bytes: bytes
        """
        return base64.b64encode(string_content.encode("utf-8"))

    @pytest.fixture(autouse=True)
    def setup(self):
        self.ca_private_key = generate_private_key()
        self.ca_certificate = generate_ca(
            private_key=self.ca_private_key,
            validity=365,
            common_name="example.com",
        )
        self.private_key = generate_private_key()
        self.csr = generate_csr(
            private_key=self.private_key,
            common_name="example.com",
        )
        self.certificate = generate_certificate(
            csr=self.csr,
            validity=365,
            ca=self.ca_certificate,
            ca_private_key=self.ca_private_key,
        )
        self.ca_chain = self.ca_certificate
        csr_bytes = TestCharm._encode_in_base64(str(self.csr))
        certificate_bytes = TestCharm._encode_in_base64(str(self.certificate))
        ca_certificate_bytes = TestCharm._encode_in_base64(str(self.ca_certificate))
        ca_chain_bytes = TestCharm._encode_in_base64(str(self.ca_chain))
        self.decoded_csr = TestCharm._decode_from_base64(csr_bytes)
        self.decoded_certificate = TestCharm._decode_from_base64(certificate_bytes)
        self.decoded_ca_certificate = TestCharm._decode_from_base64(ca_certificate_bytes)
        self.decoded_ca_chain = TestCharm._decode_from_base64(ca_chain_bytes)

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_outstanding_certificate_requests")
    def test_given_outstanding_requests_when_certificate_creation_request_then_status_is_active(
        self, patch_get_requirer_units_csrs_with_no_certs
    ):
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, common_name="example.com")
        patch_get_requirer_units_csrs_with_no_certs.return_value = [
            RequirerCSR(
                relation_id=1234,
                certificate_signing_request=csr,
            )
        ]

        state_in = scenario.State()

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == ActiveStatus(
            "1 outstanding requests, use juju actions to provide certificates"
        )

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_outstanding_certificate_requests")
    def test_given_no_units_with_no_certs_when_charm_is_deployed_then_status_is_active_and_no_outstanding_requests(  # noqa: E501
        self, patch_get_outstanding_certificate_requests
    ):
        patch_get_outstanding_certificate_requests.return_value = []

        state_in = scenario.State()

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == ActiveStatus("No outstanding requests.")

    def test_given_no_requirer_application_when_get_outstanding_certificate_requests_action_then_event_fails(  # noqa: E501
        self,
    ):
        state_in = scenario.State()

        action_output = self.ctx.run_action("get-outstanding-certificate-requests", state_in)

        assert action_output.success is False
        assert action_output.failure == "No certificates relation has been created yet."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_outstanding_certificate_requests")
    def test_given_requirer_application_when_get_outstanding_certificate_requests_action_then_csrs_information_is_returned(  # noqa: E501
        self, patch_get_outstanding_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, common_name="example.com")
        requirer_csr = RequirerCSR(
            relation_id=1234,
            certificate_signing_request=csr,
        )
        patch_get_outstanding_certificate_requests.return_value = [requirer_csr]

        state_in = scenario.State(
            relations=[certificates_relation],
        )

        action_output = self.ctx.run_action("get-outstanding-certificate-requests", state_in)

        assert action_output.success is True
        assert action_output.results
        assert action_output.results["result"] == json.dumps(
            [{"csr": str(csr), "relation_id": 1234}]
        ), action_output.results["result"]

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_outstanding_certificate_requests")
    def test_given_requirer_and_no_outstanding_certs_when_get_outstanding_certificate_requests_action_then_empty_list_is_returned(  # noqa: E501
        self, patch_get_outstanding_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        patch_get_outstanding_certificate_requests.return_value = []
        state_in = scenario.State(
            relations=[certificates_relation],
        )

        action_output = self.ctx.run_action("get-outstanding-certificate-requests", state_in)

        assert action_output.success is True
        assert action_output.results
        assert action_output.results["result"] == "[]"

    def test_given_relation_id_not_exist_when_get_outstanding_certificate_requests_action_then_action_returns_empty_list(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations=[certificates_relation],
        )

        action = scenario.Action(
            name="get-outstanding-certificate-requests",
            params={"relation-id": 1235},
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is True
        assert action_output.results
        assert action_output.results["result"] == "[]"

    def test_given_relation_not_created_when_provide_certificate_action_then_event_fails(
        self,
    ):
        state_in = scenario.State()

        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": 1234,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "No certificates relation has been created yet."

    def test_given_certificate_not_encoded_correctly_when_provide_certificate_action_then_action_fails(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations=[certificates_relation],
        )
        params = {
            "certificate-signing-request": "wrong encoding",
            "certificate": "wrong encoding",
            "ca-certificate": "wrong encoding",
            "ca-chain": "wrong encoding",
            "relation-id": 1234,
        }

        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Action input is not valid."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_csr_does_not_exist_in_requirer_when_provide_certificate_action_then_event_fails(
        self, patch_get_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        private_key = generate_private_key()
        different_csr = generate_csr(private_key=private_key, common_name="different")
        example_unit_csrs = [
            RequirerCSR(
                relation_id=certificates_relation.relation_id,
                certificate_signing_request=different_csr,
            )
        ]
        patch_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations=[certificates_relation],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.relation_id,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "CSR was not found in any requirer databags."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_no_relation_id_provided_csr_does_not_exist_in_requirer_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, patch_get_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )

        private_key = generate_private_key()
        different_csr = generate_csr(private_key=private_key, common_name="different")
        example_unit_csrs = [
            RequirerCSR(
                relation_id=certificates_relation.relation_id,
                certificate_signing_request=different_csr,
            )
        ]
        patch_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations=[certificates_relation],
        )

        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,  # type: ignore[reportArgumentType]
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "CSR was not found in any requirer databags."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_no_relation_id_provided_csr_exists_in_2_requirers_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, patch_get_certificate_requests
    ):
        certificates_relation_1 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        certificates_relation_2 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        patch_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=certificates_relation_2.relation_id,
                certificate_signing_request=self.csr,
            )
        ]
        state_in = scenario.State(
            relations=[certificates_relation_1, certificates_relation_2],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,  # type: ignore[reportArgumentType]
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Multiple requirers with the same CSR found."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_relation_id_doesnt_match_found_csr_relation_id_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, patch_get_certificate_requests
    ):
        certificates_relation_1 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        certificates_relation_2 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        patch_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=certificates_relation_1.relation_id,
                certificate_signing_request=self.csr,
            )
        ]
        state_in = scenario.State(
            relations=[certificates_relation_1, certificates_relation_2],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": 12345,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert (
            action_output.failure
            == "Requested relation id is not the correct id of any found CSR's."
        )

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_not_matching_csr_and_certificate_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, patch_get_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCSR(
                relation_id=certificates_relation.relation_id,
                certificate_signing_request=self.csr,
            )
        ]
        patch_get_certificate_requests.return_value = example_unit_csrs
        incorrect_cert = self.decoded_ca_certificate
        state_in = scenario.State(
            relations=[certificates_relation],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": incorrect_cert,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.relation_id,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Certificate and CSR do not match."

    @patch("charm.ca_chain_is_valid")
    def test_given_invalid_ca_chain_when_provide_certificate_action_then_event_fails(
        self, patch_ca_chain_valid
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        patch_ca_chain_valid.return_value = False
        state_in = scenario.State(
            relations=[certificates_relation],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.relation_id,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Action input is not valid."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_valid_input_when_provide_certificate_action_then_certificate_is_provided(
        self, patch_set_relation_cert, patch_get_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCSR(
                relation_id=certificates_relation.relation_id,
                certificate_signing_request=self.csr,
            )
        ]
        patch_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations=[certificates_relation],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.relation_id,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is True
        assert action_output.results
        assert action_output.results["result"] == "Certificates successfully provided."
        patch_set_relation_cert.assert_called_once()

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_valid_input_without_relation_id_when_provide_certificate_action_then_certificate_is_provided(  # noqa: E501
        self, patch_set_relation_cert, patch_get_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCSR(
                relation_id=certificates_relation.relation_id,
                certificate_signing_request=self.csr,
            )
        ]
        patch_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations=[certificates_relation],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,  # type: ignore[reportArgumentType]
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is True
        assert action_output.results
        assert action_output.results["result"] == "Certificates successfully provided."
        patch_set_relation_cert.assert_called_once()

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_tls_certificates_error_during_set_relation_certificate_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, patch_set_relation_cert, patch_get_certificate_requests
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCSR(
                relation_id=certificates_relation.relation_id,
                certificate_signing_request=self.csr,
            )
        ]
        patch_get_certificate_requests.return_value = example_unit_csrs
        patch_set_relation_cert.side_effect = TLSCertificatesError()
        state_in = scenario.State(
            relations=[certificates_relation],
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.relation_id,
        }
        action = scenario.Action(
            name="provide-certificate",
            params=params,
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Relation does not exist with the provided id."
