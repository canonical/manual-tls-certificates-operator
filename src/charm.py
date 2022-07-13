#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import base64
import logging
from typing import List

from charms.tls_certificates_interface.v0.tls_certificates import (
    Cert,
    CertificateRequestEvent,
    TLSCertificatesProvides,
)
from ops.charm import CharmBase, ConfigChangedEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

from self_signed_certificates import Certificate, PrivateKey, SelfSignedCertificates

logger = logging.getLogger(__name__)


class TLSCertificatesOperatorCharm(CharmBase):
    """Main class to handle Juju events."""

    _stored = StoredState()

    def __init__(self, *args):
        """Observes config change and certificate request events."""
        super().__init__(*args)
        self._stored.set_default(ca_certificate="", certificate="", private_key="")
        self.tls_certificates = TLSCertificatesProvides(self, "certificates")
        self.framework.observe(
            self.tls_certificates.on.certificate_request, self._on_certificate_request
        )
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    @property
    def _self_signed_certificates(self) -> bool:
        """Returns whether the 'generate-self-signed-certificates' config is set tu True.

        Returns:
            bool: True/False
        """
        if self.model.config.get("generate-self-signed-certificates", False):
            return True
        else:
            return False

    @property
    def _certificates_are_valid(self) -> bool:
        """Returns whether user provided certificates are valid.

        Returns:
            bool: True/False
        """
        certificate = Certificate(base64.b64decode(self.model.config.get("certificate")))  # type: ignore[arg-type]  # noqa: E501
        ca_certificate = Certificate(base64.b64decode(self.model.config.get("ca-certificate")))  # type: ignore[arg-type]  # noqa: E501
        private_key = PrivateKey(base64.b64decode(self.model.config.get("private-key")))  # type: ignore[arg-type]  # noqa: E501
        return certificate.is_valid and ca_certificate.is_valid and private_key.is_valid

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Triggered once when the charm is installed.

        Args:
            event (ConfigChangedEvent): Juju event.

        Returns:
            None
        """
        if not self._self_signed_certificates:
            missing_config_options = self.get_missing_configuration_options()
            if missing_config_options:
                self.unit.status = BlockedStatus(
                    f"Configuration options missing: {missing_config_options}"
                )
                return
            if not self._certificates_are_valid:
                self.unit.status = BlockedStatus(
                    f"Configuration options missing: {missing_config_options}"
                )
                return
            else:
                self._stored.ca_certificate = self._decode_from_base64_bytes(
                    base64.b64decode(self.model.config.get("ca-certificate"))  # type: ignore[arg-type]  # noqa: E501
                )
                self._stored.certificate = self._decode_from_base64_bytes(
                    base64.b64decode(self.model.config.get("certificate"))  # type: ignore[arg-type]  # noqa: E501
                )
                self._stored.private_key = self._decode_from_base64_bytes(
                    base64.b64decode(self.model.config.get("private-key"))  # type: ignore[arg-type]  # noqa: E501
                )
        self.unit.status = ActiveStatus()

    def _generate_self_signed_certificates(self, common_name: str) -> None:
        """Generates self-signed certificates and stores them.

        Args:
            common_name (str): Certificate common name (used for subject)

        Returns:
            None
        """
        self_signed_certificates = SelfSignedCertificates()
        self_signed_certificates.generate(common_name=common_name)
        self._stored.ca_certificate = self._decode_from_base64_bytes(
            self_signed_certificates.ca_certificate
        )
        self._stored.certificate = self._decode_from_base64_bytes(
            self_signed_certificates.certificate
        )
        self._stored.private_key = self._decode_from_base64_bytes(
            self_signed_certificates.private_key
        )
        logger.info("Generated self-signed certificates")

    def _on_certificate_request(self, event: CertificateRequestEvent) -> None:
        """Triggered everytime there's a certificate request.

        Args:
            event (CertificateRequestEvent): Event for certificate requests.

        Returns:
            None
        """
        if self._self_signed_certificates:
            if not self._certificates_are_set:
                self._generate_self_signed_certificates(event.common_name)
        else:
            if not self._certificates_are_set:
                logger.error(
                    "Configuration options are missing - "
                    "Certificates can't be passed through relation"
                )
                return
        self.tls_certificates.set_relation_certificate(
            certificate=Cert(
                cert=self._stored.certificate,
                key=self._stored.private_key,
                ca=self._stored.ca_certificate,
                common_name=event.common_name,
            ),
            relation_id=event.relation_id,
        )

    @property
    def _certificates_are_set(self) -> bool:
        """Returns whether certificates are set in stored data.

        Returns:
            bool: Whether all certificates are set.
        """
        return (
            self._stored.ca_certificate != ""  # noqa: W503
            and self._stored.certificate != ""  # noqa: W503
            and self._stored.private_key != ""  # noqa: W503
        )

    def get_missing_configuration_options(self) -> List[str]:
        """Returns the list of missing configuration options.

        Returns:
            list: List of config option names.
        """
        missing_config_options = []
        required_config_options = [
            "certificate",
            "private-key",
            "ca-certificate",
        ]
        for config in required_config_options:
            if not self.model.config.get(config, None):
                missing_config_options.append(config)
        return missing_config_options

    @staticmethod
    def _decode_from_base64_bytes(bytes_content: bytes) -> str:
        """Encodes given byte string in Base64.

        Args:
            bytes_content (bytes): Bytes content

        Returns:
            str: String
        """
        return bytes_content.decode("utf-8")


if __name__ == "__main__":
    main(TLSCertificatesOperatorCharm)
