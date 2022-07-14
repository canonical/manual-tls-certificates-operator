# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import unittest
from unittest.mock import Mock, PropertyMock, patch

from charms.tls_certificates_interface.v0.tls_certificates import Cert
from ops import testing
from ops.model import ActiveStatus, BlockedStatus

from charm import TLSCertificatesOperatorCharm

testing.SIMULATE_CAN_CONNECT = True


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

    def test_given_configuration_options_are_set_when_config_changed_then_status_is_active(self):
        certificate = self.get_certificate_from_file(filename="tests/test_certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/test_ca_certificate.pem")
        private_key = self.get_certificate_from_file(filename="tests/test_private_key.key")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        private_key_bytes = base64.b64encode(private_key.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "private-key": private_key_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)

        self.assertEqual(ActiveStatus(), self.harness.charm.unit.status)

    def test_given_missing_configuration_options_when_config_changed_then_status_is_blocked(self):
        key_values = {"private-key": "whatever private key"}
        self.harness.update_config(key_values=key_values)

        self.assertEqual(
            BlockedStatus("Configuration options missing: ['certificate', 'ca-certificate']"),
            self.harness.charm.unit.status,
        )

    @patch(
        "charms.tls_certificates_interface.v0.tls_certificates.TLSCertificatesProvides.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_configuration_options_are_set_when_certificate_request_then_certificates_are_passed(  # noqa: E501
        self, patch_set_relation_certificates
    ):
        event = Mock()
        event.relation_id = 1234
        common_name = "whatever common name"
        event.common_name = common_name
        certificate = self.get_certificate_from_file(filename="tests/test_certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/test_ca_certificate.pem")
        private_key = self.get_certificate_from_file(filename="tests/test_private_key.key")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        private_key_bytes = base64.b64encode(private_key.encode("utf-8"))
        key_values = {
            "certificate": certificate_bytes.decode("utf-8"),
            "private-key": private_key_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }
        self.harness.update_config(key_values=key_values)

        self.harness.charm._on_certificate_request(event=event)

        patch_set_relation_certificates.assert_called_with(
            certificate=Cert(
                ca=ca_certificate, key=private_key, cert=certificate, common_name=common_name
            ),
            relation_id=event.relation_id,
        )

    @patch(
        "charms.tls_certificates_interface.v0.tls_certificates.TLSCertificatesProvides.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_configuration_options_are_not_set_when_certificate_request_then_certificates_are_passed(  # noqa: E501
        self, patch_set_relation_certificates
    ):
        event = Mock()
        event.relation_id = 1234

        self.harness.charm._on_certificate_request(event=event)

        patch_set_relation_certificates.assert_not_called()

    @patch("self_signed_certificates.SelfSignedCertificates.generate", new=Mock())
    @patch(
        "self_signed_certificates.SelfSignedCertificates.private_key", new_callable=PropertyMock
    )
    @patch(
        "self_signed_certificates.SelfSignedCertificates.certificate", new_callable=PropertyMock
    )
    @patch(
        "self_signed_certificates.SelfSignedCertificates.ca_certificate", new_callable=PropertyMock
    )
    @patch(
        "charms.tls_certificates_interface.v0.tls_certificates.TLSCertificatesProvides.set_relation_certificate"  # noqa: E501, W505
    )
    def test_given_self_signed_option_is_true_when_certificate_request_then_certificates_are_set(
        self,
        patch_set_relation_certificates,
        patch_ca_certificate,
        patch_certificate,
        patch_private_key,
    ):
        ca_certificate = "UHl0aG9uIGlzIGZ1bg=="
        certificate = "eafeawewaf=="
        private_key = "lkfeafewafewa=="
        ca_certificate_bytes = ca_certificate.encode("utf-8")
        certificate_bytes = certificate.encode("utf-8")
        private_key_bytes = private_key.encode("utf-8")
        patch_ca_certificate.return_value = ca_certificate_bytes
        patch_certificate.return_value = certificate_bytes
        patch_private_key.return_value = private_key_bytes
        common_name = "whatever"
        key_values = {"generate-self-signed-certificates": "true"}
        self.harness.update_config(key_values=key_values)
        event = Mock()
        event.common_name = common_name
        event.relation_id = 1234

        self.harness.charm._on_certificate_request(event=event)

        patch_set_relation_certificates.assert_called_with(
            certificate=Cert(
                ca=self._decode_from_base64(ca_certificate_bytes),
                key=self._decode_from_base64(private_key_bytes),
                cert=self._decode_from_base64(certificate_bytes),
                common_name=common_name,
            ),
            relation_id=event.relation_id,
        )

    def test_given_non_base64_encoded_certificates_when_config_changed_then_unit_is_blocked(self):
        key_values = {"certificate": "aaa", "ca-certificate": "bbb", "private-key": "ccc"}

        self.harness.update_config(key_values=key_values)

        self.assertEqual(
            BlockedStatus("Certificates are not valid"),
            self.harness.charm.unit.status,
        )
