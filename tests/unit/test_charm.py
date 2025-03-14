# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
import scenario
from charms.tls_certificates_interface.v4.tls_certificates import (
    RequirerCertificateRequest,
    TLSCertificatesError,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import ActiveStatus

from charm import ManualTLSCertificatesCharm

CERTIFICATE_TRANSFER_PROVIDES_PATH = (
    "charms.certificate_transfer_interface.v1.certificate_transfer.CertificateTransferProvides"
)
TLS_CERTIFICATES_PROVIDES_PATH = (
    "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesProvidesV4"
)


@pytest.fixture()
def test_cert() -> str:
    return """-----BEGIN CERTIFICATE-----
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
bTvWRcTns/sRTw1iXlmwXT0K1yQgeDjG/2s=
-----END CERTIFICATE-----"""


@pytest.fixture()
def test_ca() -> str:
    return """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""


@pytest.fixture()
def test_cert_bundle(test_cert: str, test_ca: str) -> str:
    return f"{test_cert}\n{test_ca}"


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
            validity=timedelta(days=365),
            common_name="example.com",
        )
        self.private_key = generate_private_key()
        self.csr = generate_csr(
            private_key=self.private_key,
            common_name="example.com",
        )
        self.certificate = generate_certificate(
            csr=self.csr,
            validity=timedelta(days=365),
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
        self, mock_get_requirer_units_csrs_with_no_certs: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, common_name="example.com")
        mock_get_requirer_units_csrs_with_no_certs.return_value = [
            RequirerCertificateRequest(
                relation_id=1234,
                certificate_signing_request=csr,
                is_ca=False,
            )
        ]

        state_in = scenario.State()

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == ActiveStatus(
            "1 outstanding requests, use juju actions to provide certificates"
        )

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_outstanding_certificate_requests")
    def test_given_no_units_with_no_certs_when_charm_is_deployed_then_status_is_active_and_no_outstanding_requests(  # noqa: E501
        self, mock_get_outstanding_certificate_requests: MagicMock
    ):
        mock_get_outstanding_certificate_requests.return_value = []

        state_in = scenario.State()

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == ActiveStatus("No outstanding requests.")

    def test_given_no_requirer_application_when_get_outstanding_certificate_requests_action_then_event_fails(  # noqa: E501
        self,
    ):
        state_in = scenario.State()

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("get-outstanding-certificate-requests"), state_in)

        assert exc.value.message == "No certificates relation has been created yet."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_outstanding_certificate_requests")
    def test_given_requirer_application_when_get_outstanding_certificate_requests_action_then_csrs_information_is_returned(  # noqa: E501
        self, mock_get_outstanding_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, common_name="example.com")
        requirer_csr = RequirerCertificateRequest(
            relation_id=1234,
            certificate_signing_request=csr,
            is_ca=False,
        )
        mock_get_outstanding_certificate_requests.return_value = [requirer_csr]

        state_in = scenario.State(
            relations={certificates_relation},
        )

        self.ctx.run(self.ctx.on.action("get-outstanding-certificate-requests"), state_in)

        assert self.ctx.action_results
        assert self.ctx.action_results["result"] == json.dumps(
            [{"csr": str(csr), "relation_id": 1234}]
        ), self.ctx.action_results["result"]

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_outstanding_certificate_requests")
    def test_given_requirer_and_no_outstanding_certs_when_get_outstanding_certificate_requests_action_then_empty_list_is_returned(  # noqa: E501
        self, mock_get_outstanding_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        mock_get_outstanding_certificate_requests.return_value = []
        state_in = scenario.State(
            relations={certificates_relation},
        )

        self.ctx.run(self.ctx.on.action("get-outstanding-certificate-requests"), state_in)

        assert self.ctx.action_results
        assert self.ctx.action_results["result"] == "[]"

    def test_given_relation_id_not_exist_when_get_outstanding_certificate_requests_action_then_action_returns_empty_list(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={certificates_relation},
        )

        self.ctx.run(
            self.ctx.on.action(
                "get-outstanding-certificate-requests", params={"relation-id": 1235}
            ),
            state_in,
        )

        assert self.ctx.action_results
        assert self.ctx.action_results["result"] == "[]"

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

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "No certificates relation has been created yet."

    def test_given_certificate_not_encoded_correctly_when_provide_certificate_action_then_action_fails(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={certificates_relation},
        )
        params = {
            "certificate-signing-request": "wrong encoding",
            "certificate": "wrong encoding",
            "ca-certificate": "wrong encoding",
            "ca-chain": "wrong encoding",
            "relation-id": 1234,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "Action input is not valid."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_csr_does_not_exist_in_requirer_when_provide_certificate_action_then_event_fails(
        self, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        private_key = generate_private_key()
        different_csr = generate_csr(private_key=private_key, common_name="different")
        example_unit_csrs = [
            RequirerCertificateRequest(
                relation_id=certificates_relation.id,
                certificate_signing_request=different_csr,
                is_ca=False,
            )
        ]
        mock_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations={certificates_relation},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.id,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "CSR was not found in any requirer databags."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_no_relation_id_provided_csr_does_not_exist_in_requirer_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )

        private_key = generate_private_key()
        different_csr = generate_csr(private_key=private_key, common_name="different")
        example_unit_csrs = [
            RequirerCertificateRequest(
                relation_id=certificates_relation.id,
                certificate_signing_request=different_csr,
                is_ca=False,
            )
        ]
        mock_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations={certificates_relation},
        )

        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "CSR was not found in any requirer databags."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_no_relation_id_provided_csr_exists_in_2_requirers_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation_1 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        certificates_relation_2 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=certificates_relation_2.id,
                certificate_signing_request=self.csr,
                is_ca=False,
            )
        ]
        state_in = scenario.State(
            relations={certificates_relation_1, certificates_relation_2},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "Multiple requirers with the same CSR found."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_relation_id_doesnt_match_found_csr_relation_id_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation_1 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        certificates_relation_2 = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=certificates_relation_1.id,
                certificate_signing_request=self.csr,
                is_ca=False,
            )
        ]
        state_in = scenario.State(
            relations={certificates_relation_1, certificates_relation_2},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": 12345,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert (
            exc.value.message == "Requested relation id is not the correct id of any found CSR's."
        )

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    def test_given_not_matching_csr_and_certificate_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCertificateRequest(
                relation_id=certificates_relation.id,
                certificate_signing_request=self.csr,
                is_ca=False,
            )
        ]
        mock_get_certificate_requests.return_value = example_unit_csrs
        incorrect_cert = self.decoded_ca_certificate
        state_in = scenario.State(
            relations={certificates_relation},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": incorrect_cert,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.id,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "Certificate and CSR do not match."

    def test_given_invalid_ca_chain_when_provide_certificate_action_then_event_fails(
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={certificates_relation},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": "Invalid CA chain",
            "relation-id": certificates_relation.id,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "Action input is not valid."

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_valid_input_when_provide_certificate_action_then_certificate_is_provided(
        self, mock_set_relation_cert: MagicMock, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCertificateRequest(
                relation_id=certificates_relation.id,
                certificate_signing_request=self.csr,
                is_ca=False,
            )
        ]
        mock_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations={certificates_relation},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.id,
        }

        self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert self.ctx.action_results
        assert self.ctx.action_results["result"] == "Certificates successfully provided."
        mock_set_relation_cert.assert_called_once()

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_valid_input_without_relation_id_when_provide_certificate_action_then_certificate_is_provided(  # noqa: E501
        self, mock_set_relation_cert: MagicMock, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCertificateRequest(
                relation_id=certificates_relation.id,
                certificate_signing_request=self.csr,
                is_ca=False,
            )
        ]
        mock_get_certificate_requests.return_value = example_unit_csrs
        state_in = scenario.State(
            relations={certificates_relation},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
        }

        self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert self.ctx.action_results
        assert self.ctx.action_results["result"] == "Certificates successfully provided."
        mock_set_relation_cert.assert_called_once()

    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.get_certificate_requests")
    @patch(f"{TLS_CERTIFICATES_PROVIDES_PATH}.set_relation_certificate")
    def test_given_tls_certificates_error_during_set_relation_certificate_when_provide_certificate_action_then_event_fails(  # noqa: E501
        self, mock_set_relation_cert: MagicMock, mock_get_certificate_requests: MagicMock
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        example_unit_csrs = [
            RequirerCertificateRequest(
                relation_id=certificates_relation.id,
                certificate_signing_request=self.csr,
                is_ca=False,
            )
        ]
        mock_get_certificate_requests.return_value = example_unit_csrs
        mock_set_relation_cert.side_effect = TLSCertificatesError()
        state_in = scenario.State(
            relations={certificates_relation},
        )
        params = {
            "certificate-signing-request": self.decoded_csr,
            "certificate": self.decoded_certificate,
            "ca-certificate": self.decoded_ca_certificate,
            "ca-chain": self.decoded_ca_chain,
            "relation-id": certificates_relation.id,
        }

        with pytest.raises(scenario.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("provide-certificate", params=params), state_in)

        assert exc.value.message == "Relation does not exist with the provided id."

    @pytest.mark.parametrize(
        "config",
        [
            pytest.param({}, id="Empty config"),
            pytest.param(
                {"trusted-certificate-bundle": "Not a cert bundle"},
                id="Not a cert bundle",
            ),
        ],
    )
    def test_given_invalid_config_and_no_relations_when_config_changed_then_error_is_not_logged(
        self, config: dict, caplog: pytest.LogCaptureFixture
    ):
        state_in = scenario.State(
            config=config,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)
        assert "Trust certificate relation cannot be fulfilled" not in caplog.text

    @pytest.mark.parametrize(
        "config",
        [
            pytest.param({}, id="Empty config"),
            pytest.param(
                {"trusted-certificate-bundle": "Not a cert bundle"},
                id="Not a cert bundle",
            ),
        ],
    )
    def test_given_invalid_config_and_relations_when_config_changed_then_error_is_logged(
        self, config: dict, caplog: pytest.LogCaptureFixture
    ):
        transfer_relation1 = scenario.Relation(
            endpoint="trust_certificate",
            interface="certificates_transfer",
            remote_app_name="app1",
        )
        transfer_relation2 = scenario.Relation(
            endpoint="trust_certificate",
            interface="certificates_transfer",
            remote_app_name="app2",
        )
        state_in = scenario.State(
            config=config,
            relations={transfer_relation1, transfer_relation2},
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)
        assert "Trust certificate relation cannot be fulfilled" in caplog.text

    @patch(f"{CERTIFICATE_TRANSFER_PROVIDES_PATH}.add_certificates")
    def test_given_valid_bundle_in_config_when_config_changed_then_all_relations_are_updated(
        self,
        mock_add_certificates: MagicMock,
        test_cert_bundle: str,
        test_cert: str,
        test_ca: str,
        caplog: pytest.LogCaptureFixture,
    ):
        transfer_relation1 = scenario.Relation(
            endpoint="trust_certificate",
            interface="certificates_transfer",
            remote_app_name="app1",
        )
        transfer_relation2 = scenario.Relation(
            endpoint="trust_certificate",
            interface="certificates_transfer",
            remote_app_name="app2",
        )
        state_in = scenario.State(
            config={"trusted-certificate-bundle": test_cert_bundle},
            relations={transfer_relation1, transfer_relation2},
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)
        assert "Trust certificate relation cannot be fulfilled" not in caplog.text
        mock_add_certificates.assert_called_with(
            {
                test_cert,
                test_ca,
            }
        )

    @pytest.mark.parametrize(
        "config",
        [
            pytest.param({}, id="Empty config"),
            pytest.param({"trusted-certificate-bundle": ""}, id="Empty value"),
            pytest.param(
                {"trusted-certificate-bundle": "Not a cert bundle"},
                id="Not a cert bundle",
            ),
        ],
    )
    def test_given_invalid_config_when_trust_certificate_relation_joined_then_error_is_logged(
        self, config: dict, caplog: pytest.LogCaptureFixture
    ):
        transfer_relation = scenario.Relation(
            endpoint="trust_certificate",
            interface="certificates_transfer",
            remote_app_name="app1",
        )
        state_in = scenario.State(
            config=config,
            relations={transfer_relation},
        )

        self.ctx.run(self.ctx.on.relation_joined(transfer_relation), state_in)
        assert "Trust certificate relation cannot be fulfilled" in caplog.text

    @patch(f"{CERTIFICATE_TRANSFER_PROVIDES_PATH}.add_certificates")
    def test_given_valid_bundle_in_config_when_trust_certificate_relation_joined_then_certificate_is_set(  # noqa: E501
        self,
        mock_add_certificates: MagicMock,
        test_cert_bundle: str,
        test_cert: str,
        test_ca: str,
        caplog: pytest.LogCaptureFixture,
    ):
        transfer_relation = scenario.Relation(
            endpoint="trust_certificate",
            interface="certificates_transfer",
            remote_app_name="app1",
        )
        state_in = scenario.State(
            config={"trusted-certificate-bundle": test_cert_bundle},
            relations={transfer_relation},
        )

        self.ctx.run(self.ctx.on.relation_joined(transfer_relation), state_in)
        assert "Trust certificate relation cannot be fulfilled" not in caplog.text
        mock_add_certificates.assert_called_with(
            {test_cert, test_ca},
            relation_id=transfer_relation.id,
        )

    def test_given_certificate_transfer_requirer_related_but_no_bundle_configured_when_collect_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        transfer_relation = scenario.Relation(
            endpoint="trust_certificate",
            interface="certificates_transfer",
            remote_app_name="app1",
        )
        state_in = scenario.State(
            relations={transfer_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == ActiveStatus("No trusted certificate bundle configured")
