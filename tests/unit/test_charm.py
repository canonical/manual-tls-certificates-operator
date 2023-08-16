# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import datetime
import json
import unittest
from unittest.mock import Mock, patch

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore
    generate_csr,
)
from cryptography import x509
from cryptography.x509 import DNSName
from ops import testing
from ops.model import ActiveStatus, Application, BlockedStatus, Relation, WaitingStatus

from charm import TLSCertificatesOperatorCharm
from self_signed_certificates import (
    generate_ca,
    generate_certificate,
    generate_private_key,
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
        self.harness.begin()

    def test_given_configuration_options_are_set_and_unit_is_leader_when_config_changed_then_status_is_active(  # noqa: E501
        self,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)

        self.assertEqual(ActiveStatus(), self.harness.charm.unit.status)

    def test_given_configuration_options_are_set_and_unit_is_leader_when_config_changed_then_cert_is_added_to_peer_relation_data(  # noqa: E501
        self,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)

        relation_data = self.harness.get_relation_data(
            relation_id=peer_relation_id, app_or_unit=self.harness.charm.app.name
        )

        assert relation_data["config_ca_certificate"] == ca_certificate.strip()
        assert relation_data["config_certificate"] == certificate.strip()
        assert json.loads(relation_data["config_ca_chain"]) == [
            ca_certificate.strip(),
            certificate.strip(),
        ]

    def test_given_configuration_options_are_set_without_ca_chain_and_unit_is_leader_when_config_changed_then_cert_is_added_to_peer_relation_data(  # noqa: E501
        self,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)

        relation_data = self.harness.get_relation_data(
            relation_id=peer_relation_id, app_or_unit=self.harness.charm.app.name
        )

        assert relation_data["config_ca_certificate"] == ca_certificate.strip()
        assert relation_data["config_certificate"] == certificate.strip()
        assert json.loads(relation_data["config_ca_chain"]) == [
            ca_certificate.strip(),
            certificate.strip(),
        ]

    def test_given_configuration_options_are_set_and_unit_is_not_leader_when_config_changed_then_status_is_active(  # noqa: E501
        self,
    ):
        self.harness.add_relation("replicas", self.harness.charm.app.name)
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(
            filename="tests/ca_certificate.pem"
        ).strip()
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.set_leader(False)

        self.harness.update_config(key_values=key_values)

        self.assertEqual(ActiveStatus(), self.harness.charm.unit.status)

    def test_given_unit_is_leader_and_generate_self_signed_certificate_set_to_true_but_no_common_name_when_config_changed_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_leader(True)
        self.harness.add_relation("replicas", self.harness.charm.app.name)

        self.harness.update_config(key_values={"generate-self-signed-certificates": True})

        self.assertEqual(
            BlockedStatus(
                "Configuration `ca-common-name` must be set when "
                "`generate-self-signed-certificates` is set to True."
            ),
            self.harness.charm.unit.status,
        )

    def test_given_unit_is_leader_and_generate_self_signed_certificate_set_to_true_default_validity(  # noqa: E501
        self,
    ):
        self.harness.set_leader(True)
        self.harness.add_relation("replicas", self.harness.charm.app.name)

        self.harness.update_config(
            key_values={"generate-self-signed-certificates": True, "ca-common-name": "RootCA"}
        )

        rel = self.harness.charm.model.get_relation("replicas")

        assert isinstance(rel, Relation)
        assert isinstance(rel.app, Application)

        cert = x509.load_pem_x509_certificate(
            rel.data[rel.app]["self_signed_ca_certificate"].encode("utf-8")
        )
        assert (
            cert.not_valid_after.date()
            == (datetime.datetime.now() + datetime.timedelta(days=365)).date()
        )

    def test_given_unit_is_leader_and_generate_self_signed_certificate_set_to_true_custom_validity(  # noqa: E501
        self,
    ):
        self.harness.set_leader(True)
        self.harness.add_relation("replicas", self.harness.charm.app.name)

        n = 500

        self.harness.update_config(
            key_values={
                "generate-self-signed-certificates": True,
                "ca-common-name": "RootCA",
                "ca-certificate-validity": n,
            }
        )

        rel = self.harness.charm.model.get_relation("replicas")

        assert isinstance(rel, Relation)
        assert isinstance(rel.app, Application)

        cert = x509.load_pem_x509_certificate(
            rel.data[rel.app]["self_signed_ca_certificate"].encode("utf-8")
        )
        assert (
            cert.not_valid_after.date()
            == (datetime.datetime.now() + datetime.timedelta(days=n)).date()
        )

    def test_given_not_consistent_ca_certificate_and_certificate_validity(  # noqa: E501
        self,
    ):
        self.harness.set_leader(True)
        self.harness.add_relation("replicas", self.harness.charm.app.name)

        self.harness.update_config(
            key_values={
                "generate-self-signed-certificates": True,
                "ca-common-name": "RootCA",
                "ca-certificate-validity": 100,
            }
        )

        self.assertTrue(type(self.harness.charm.unit.status), BlockedStatus)

    def test_given_missing_configuration_options_when_config_changed_then_status_is_blocked(self):
        self.harness.add_relation("replicas", self.harness.charm.app.name)
        key_values = {"ca-chain": "Whatever ca chain"}

        self.harness.update_config(key_values=key_values)

        self.assertEqual(
            BlockedStatus("Configuration options missing: ['certificate', 'ca-certificate']"),
            self.harness.charm.unit.status,
        )

    def test_given_non_base64_encoded_certificates_when_config_changed_then_unit_is_blocked(self):
        self.harness.add_relation("replicas", self.harness.charm.app.name)
        key_values = {
            "certificate": "aaa",
            "ca-certificate": "bbb",
            "ca-chain": "ccc",
        }

        self.harness.update_config(key_values=key_values)

        self.assertEqual(
            BlockedStatus("Certificates are not valid"),
            self.harness.charm.unit.status,
        )

    def test_given_user_provided_certs_not_valid_when_config_changed_then_status_is_blocked(self):
        self.harness.add_relation("replicas", self.harness.charm.app.name)
        key_values = {
            "certificate": self._encode_in_base64("bad cert").decode(),
            "ca-chain": json.dumps([self._encode_in_base64("bad ca chain").decode()]),
            "ca-certificate": self._encode_in_base64("bad ca cert").decode(),
        }

        self.harness.update_config(key_values=key_values)

        self.assertEqual(
            BlockedStatus("Certificates are not valid"),
            self.harness.charm.unit.status,
        )

    def test_given_unit_is_not_leader_and_self_signed_certs_are_not_yet_stored_when_config_changed_then_status_is_waiting(  # noqa: E501
        self,
    ):
        key_values = {"generate-self-signed-certificates": True}
        self.harness.set_leader(False)
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)

        self.harness.update_config(key_values=key_values)

        self.assertEqual(
            WaitingStatus("Waiting for root certificates to be generated."),
            self.harness.charm.unit.status,
        )

    def test_given_unit_is_not_leader_and_self_signed_certs_are_stored_when_config_changed_then_status_is_active(  # noqa: E501
        self,
    ):
        self.harness.set_leader(False)
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "self_signed_ca_private_key": "whatever private key",
                "self_signed_ca_certificate": "whatever cert",
                "self_signed_ca_private_key_password": "whatever password",
            },
        )
        self.harness.update_config(key_values={"generate-self-signed-certificates": True})

        self.assertEqual(ActiveStatus(), self.harness.charm.unit.status)

    @patch("charm.generate_certificate")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_self_signed_option_is_true_and_unit_is_leader_and_root_certificates_are_stored_when_certificate_creation_request_then_certificates_are_set(  # noqa: E501
        self,
        patch_set_relation_certificates,
        patch_generate_certificate,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        ca_certificate = "UHl0aG9uIGlzIGZ1bg=="
        certificate = "eafeawewaf=="
        csr = "whatever csr"
        certificate_bytes = certificate.encode("utf-8")
        patch_generate_certificate.return_value = certificate_bytes
        self.harness.update_config(
            key_values={"generate-self-signed-certificates": True, "ca-common-name": "whatever"}
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "self_signed_ca_certificate": ca_certificate,
                "self_signed_ca_private_key": "whatever ca private key",
                "self_signed_ca_private_key_password": "whatever ca password",
            },
        )
        event = Mock()
        event.certificate_signing_request = csr
        event.relation_id = 1234

        self.harness.charm._on_certificate_creation_request(event=event)

        patch_set_relation_certificates.assert_called_with(
            certificate=certificate,
            certificate_signing_request=csr,
            ca=ca_certificate,
            chain=[ca_certificate, certificate],
            relation_id=event.relation_id,
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_user_provided_certificates_and_unit_is_leader_and_root_certificates_are_stored_when_certificate_creation_request_then_certificates_are_set(  # noqa: E501
        self,
        patch_set_relation_certificates,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        csr = "whatever csr"
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)
        event = Mock()
        event.certificate_signing_request = csr
        event.relation_id = 1234

        self.harness.charm._on_certificate_creation_request(event=event)

        patch_set_relation_certificates.assert_called_with(
            certificate=certificate.strip(),
            certificate_signing_request=csr.strip(),
            ca=ca_certificate.strip(),
            chain=[ca_certificate.strip(), certificate.strip()],
            relation_id=event.relation_id,
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_configuration_options_are_set_and_unit_is_not_leader_when_certificate_creation_request_then_certificates_are_not_passed(  # noqa: E501
        self,
        patch_set_relation_certificates,
    ):
        event = Mock()
        event.relation_id = 1234
        common_name = "whatever common name"
        event.common_name = common_name
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = [ca_certificate_bytes.decode("utf-8"), certificate_bytes.decode("utf-8")]
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": json.dumps(ca_chain_bytes),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)

        self.harness.set_leader(False)
        self.harness.charm._on_certificate_creation_request(event=event)

        patch_set_relation_certificates.assert_not_called()

    def test_given_no_config_when_on_certificate_creation_request_then_status_is_blocked(self):
        event = Mock()
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)

        self.harness.charm._on_certificate_creation_request(event=event)

        self.assertEqual(
            BlockedStatus(
                "Configuration options are missing - Certificates can't be passed through relation"
            ),
            self.harness.charm.unit.status,
        )

    def test_given_peer_relation_is_not_created_when_on_certificate_creation_request_then_status_is_waiting(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.set_leader(True)

        self.harness.charm._on_certificate_creation_request(event=event)

        self.assertEqual(
            WaitingStatus("Waiting for peer relation to be created"),
            self.harness.charm.unit.status,
        )

    def test_given_self_signed_certificates_not_yet_stored_when_on_certificate_creation_request_then_status_is_waiting(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.set_leader(True)
        self.harness.update_config(
            key_values={"generate-self-signed-certificates": True, "ca-common-name": "whatever"}
        )
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)

        self.harness.charm._on_certificate_creation_request(event=event)

        self.assertEqual(
            WaitingStatus("Root Certificates are not yet set"),
            self.harness.charm.unit.status,
        )

    def test_given_sans_added_to_csr_when_generate_certificate_then_the_correct_extensions_are_set_in_generated_certificate(  # noqa: E501
        self,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)

        sans = ["www.canonical.com", "test.com"]
        csr = generate_csr(
            generate_private_key(),
            subject="my_subject",
            sans=sans,
        )

        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(ca_private_key, "ca")
        certificate = generate_certificate(csr, ca_certificate, ca_private_key)

        cert = x509.load_pem_x509_certificate(certificate)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        subj_alt_names = san_ext.value.get_values_for_type(DNSName)

        self.assertCountEqual(subj_alt_names, sans)

    @patch("charm.generate_certificate")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.revoke_all_certificates"  # noqa: E501, W505
    )
    def test_given_self_signed_option_is_true_and_unit_is_leader_when_config_changed_then_all_certificates_revoked(  # noqa: E501
        self,
        patch_revoke_all_certificates,
        patch_generate_certificate,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        ca_certificate = "UHl0aG9uIGlzIGZ1bg=="
        certificate = "eafeawewaf=="
        certificate_bytes = certificate.encode("utf-8")
        patch_generate_certificate.return_value = certificate_bytes
        self.harness.update_config(
            key_values={"generate-self-signed-certificates": True, "ca-common-name": "whatever"}
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "self_signed_ca_certificate": ca_certificate,
                "self_signed_ca_private_key": "whatever ca private key",
                "self_signed_ca_private_key_password": "whatever ca password",
            },
        )

        self.harness.update_config(
            key_values={
                "generate-self-signed-certificates": True,
                "ca-common-name": "whatever else",
            }
        )
        patch_revoke_all_certificates.assert_called_with()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.revoke_all_certificates"  # noqa: E501, W505
    )
    def test_given_user_provided_certificates_and_unit_is_leader_when_config_changed_then_all_certificates_are_revoked(  # noqa: E501
        self,
        patch_revoke_all_certificates,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)

        patch_revoke_all_certificates.assert_called_with()

    def test_given_self_signed_option_is_true_and_unit_is_leader_and_root_certificates_are_stored_when_generate_certificate_action_triggered_then_certificates_are_set(  # noqa: E501
        self,
    ):
        peer_relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(peer_relation_id, self.harness.charm.unit.name)
        self.harness.set_leader(True)
        self.harness.update_config(
            key_values={"generate-self-signed-certificates": True, "ca-common-name": "whatever"}
        )

        event = Mock()
        sans = "www.canonical.com test.com"
        event.params = {"sans": sans, "common-name": "test"}
        self.harness.charm._on_generate_self_signed_certificate_action(event=event)

        event.set_results.assert_called_once()
        results = event.set_results.call_args.args[0]
        keys_to_check = ["private-key", "certificate", "ca-chain", "issuing-ca"]
        for key in keys_to_check:
            self.assertIn(key, results)
            self.assertIsNotNone(results[key])

        certificate = results.get("certificate").encode()
        cert = x509.load_pem_x509_certificate(certificate)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        subj_alt_names = san_ext.value.get_values_for_type(DNSName)
        self.assertCountEqual(subj_alt_names, sans.split(" "))

    def test_given_self_signed_option_is_true_and_unit_is_leader_and_self_signed_certs_are_not_yet_stored_when_generate_certificate_action_triggered_then_action_failed(  # noqa: E501
        self,
    ):
        key_values = {"generate-self-signed-certificates": True}
        self.harness.set_leader(True)
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)

        self.harness.update_config(key_values=key_values)

        event = Mock()
        event.params = {"sans": "", "common-name": "test"}
        self.harness.charm._on_generate_self_signed_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Root certificates not yet set")

    def test_given_self_signed_option_is_true_and_unit_is_not_leader_and_root_certificates_are_stored_when_generate_certificate_action_triggered_then_action_failed(  # noqa: E501
        self,
    ):
        key_values = {"generate-self-signed-certificates": True}
        self.harness.set_leader(False)
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)
        self.harness.update_config(key_values=key_values)

        event = Mock()
        event.params = {"sans": "", "common-name": "test"}
        self.harness.charm._on_generate_self_signed_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Action cannot be run on non-leader unit")

    def test_given_self_signed_option_is_false_and_unit_is_leader_when_generate_certificate_action_triggered_then_action_failed(  # noqa: E501
        self,
    ):
        self.harness.add_relation("replicas", self.harness.charm.app.name)
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(
            filename="tests/ca_certificate.pem"
        ).strip()
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.set_leader(True)
        self.harness.update_config(key_values=key_values)

        event = Mock()
        event.params = {"sans": "", "common-name": "test"}
        self.harness.charm._on_generate_self_signed_certificate_action(event=event)
        event.fail.assert_called_once_with(
            message="Action not supported as charm is not configured to be self-signed"
        )

    def test_given_no_requirer_application_when_get_all_certificate_requests_action_then_empty_list_returned(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.charm._on_get_all_certificate_requests_action(event=event)
        event.set_results.assert_called_once_with({"Result": []})

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesProvidesV2.get_requirer_units_csrs_with_no_certs"  # noqa: E501, W505
    )
    def test_given_requirer_application_when_get_all_certificate_requests_action_then_csrs_information_is_returned(  # noqa: E501
        self, patch_get_requirer_units_csrs_with_no_certs
    ):
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
        self.harness.charm._on_get_all_certificate_requests_action(event=event)
        event.set_results.assert_called_once_with({"Result": example_unit_csrs})

    def test_given_relation_id_not_exist_when_get_certificate_request_action_then_action_returns_empty_list(  # noqa: E501
        self,
    ):
        event = Mock()
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
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))

        event = Mock()
        event.params = {
            "certificate-signing-request": base64.b64encode(certificate.encode("utf-8")).decode(),
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
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
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        event = Mock()
        event.params = {
            "certificate-signing-request": base64.b64encode("whatever cert".encode()).decode(),
            "certificate": base64.b64encode("whatever cert".encode()).decode(),
            "ca-certificate": base64.b64encode("whatever ca".encode()).decode(),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "relation-id": 1234,
        }
        self.harness.charm._on_provide_certificate_action(event=event)
        event.fail.assert_called_once_with(message="Action cannot be run on non-leader unit.")
