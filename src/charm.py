#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import base64
import binascii
import logging
import secrets
import string
from typing import List, Tuple

from charms.tls_certificates_interface.v0.tls_certificates import Cert as CertV0
from charms.tls_certificates_interface.v0.tls_certificates import (
    CertificateRequestEvent as CertificateRequestEventV0,
)
from charms.tls_certificates_interface.v0.tls_certificates import (
    TLSCertificatesProvides as TLSCertificatesProvidesV0,
)
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateCreationRequestEvent as CertificateRequestEventV1,
)
from charms.tls_certificates_interface.v1.tls_certificates import (
    TLSCertificatesProvidesV1,
)
from ops.charm import CharmBase, ConfigChangedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from self_signed_certificates import (
    certificate_is_valid,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
    private_key_is_valid,
)

logger = logging.getLogger(__name__)


class TLSCertificatesOperatorCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observes config change and certificate request events."""
        super().__init__(*args)
        self.tls_certificates_v0 = TLSCertificatesProvidesV0(self, "certificates")
        self.tls_certificates_v1 = TLSCertificatesProvidesV1(self, "certificates")
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.tls_certificates_v0.on.certificate_request,
            self._on_certificate_creation_request_v0,
        )
        self.framework.observe(
            self.tls_certificates_v1.on.certificate_creation_request,
            self._on_certificate_creation_request_v1,
        )

    def _on_install(self, event):
        if not self._self_signed_certificates:
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        self._generate_root_certificates()

    def _generate_root_certificates(self) -> None:
        """Generates root certificate to be used to sign certificates.

        Returns:
            None
        """
        replicas_relation = self.model.get_relation("replicas")
        private_key_password = self._generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        ca_certificate = generate_ca(
            private_key=private_key,
            subject=self.model.config.get("ca-common-name"),  # type: ignore[arg-type]  # noqa: E501
            private_key_password=private_key_password.encode(),
        )
        replicas_relation.data[self.app].update(  # type: ignore[union-attr]
            {
                "ca_private_key_password": private_key_password,
                "ca_private_key": private_key.decode(),
                "ca_certificate": ca_certificate.decode(),
            }
        )

    @property
    def _self_signed_certificates(self) -> bool:
        """Returns whether the 'generate-self-signed-certificates' config is set to True.

        Returns:
            bool: True/False
        """
        if self.model.config.get(
            "generate-self-signed-certificates", False
        ) and self.model.config.get("ca-common-name", False):
            return True
        else:
            return False

    @property
    def _certificates_are_valid(self) -> bool:
        """Returns whether user provided certificates are valid.

        Returns:
            bool: True/False
        """
        try:
            certificate_bytes = base64.b64decode(self.model.config.get("certificate"))  # type: ignore[arg-type]  # noqa: E501
            ca_certificate_bytes = base64.b64decode(self.model.config.get("ca-certificate"))  # type: ignore[arg-type]  # noqa: E501
            private_key_bytes = base64.b64decode(self.model.config.get("private-key"))  # type: ignore[arg-type]  # noqa: E501
        except binascii.Error:
            return False
        try:
            assert certificate_is_valid(certificate_bytes)
            assert certificate_is_valid(ca_certificate_bytes)
            assert private_key_is_valid(private_key_bytes)
            return True
        except AssertionError:
            return False

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
                self.unit.status = BlockedStatus("Certificates are not valid")
                return
            if self.unit.is_leader():
                replicas = self.model.get_relation("replicas")
                replicas.data[self.app].update(  # type: ignore[union-attr]
                    {
                        "ca_certificate": self._decode_from_base64_bytes(
                            base64.b64decode(self.model.config.get("ca-certificate"))  # type: ignore[arg-type]  # noqa: E501
                        )
                    }
                )
                replicas.data[self.app].update(  # type: ignore[union-attr]
                    {
                        "certificate": self._decode_from_base64_bytes(
                            base64.b64decode(self.model.config.get("certificate"))  # type: ignore[arg-type]  # noqa: E501
                        )
                    }
                )
                replicas.data[self.app].update(  # type: ignore[union-attr]
                    {
                        "private_key": self._decode_from_base64_bytes(
                            base64.b64decode(self.model.config.get("private-key"))  # type: ignore[arg-type]  # noqa: E501
                        )
                    }
                )
        self.unit.status = ActiveStatus()

    def _generate_self_signed_certificates_v0(self, common_name: str) -> Tuple[str, str]:
        """Generates self-signed certificates.

        Args:
            common_name (str): Certificate common name (used for subject)

        Returns:
            (str, str): Certificate and Private Key
        """
        replicas_relation = self.model.get_relation("replicas")
        ca_certificate = replicas_relation.data[self.app].get("ca_certificate")  # type: ignore[union-attr]  # noqa: E501
        ca_private_key = replicas_relation.data[self.app].get("ca_private_key")  # type: ignore[union-attr]  # noqa: E501
        private_key = generate_private_key()
        csr = generate_csr(private_key=ca_private_key, subject=common_name)
        certificate = generate_certificate(
            ca=ca_certificate.encode(), ca_key=ca_private_key.encode(), csr=csr
        )
        logger.info("Generated self-signed certificates")
        return certificate.decode(), private_key.decode()

    def _generate_self_signed_certificates_v1(self, certificate_signing_request: str) -> str:
        """Generates self-signed certificates.

        Args:
            certificate_signing_request (str): Certificate signing request

        Returns:
            str: Certificate
        """
        replicas_relation = self.model.get_relation("replicas")
        ca_certificate = replicas_relation.data[self.app].get("ca_certificate")  # type: ignore[union-attr]  # noqa: E501
        ca_private_key = replicas_relation.data[self.app].get("ca_private_key")  # type: ignore[union-attr]  # noqa: E501
        certificate = generate_certificate(
            ca=ca_certificate.encode(),
            ca_key=ca_private_key,
            csr=certificate_signing_request.encode(),
        )
        logger.info("Generated self-signed certificates")
        return certificate.decode()

    def _on_certificate_creation_request_v0(self, event: CertificateRequestEventV0) -> None:
        """Triggered everytime there's a certificate request.

        Args:
            event (CertificateRequestEvent): Event for certificate requests.

        Returns:
            None
        """
        if not self.unit.is_leader():
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if self._self_signed_certificates:
            if not self._root_certificates_are_set:
                event.defer()
                return
            certificate, private_key = self._generate_self_signed_certificates_v0(
                event.common_name
            )
            self.tls_certificates_v0.set_relation_certificate(
                certificate=CertV0(
                    cert=certificate,
                    key=private_key,
                    ca=replicas_relation.data[self.app].get("ca_certificate"),
                    common_name=event.common_name,
                ),
                relation_id=event.relation_id,
            )
        else:
            if not self._config_certificates_are_set:
                logger.error(
                    "Configuration options are missing - "
                    "Certificates can't be passed through relation"
                )
                return
            self.tls_certificates_v0.set_relation_certificate(
                certificate=CertV0(
                    cert=replicas_relation.data[self.app].get("certificate"),
                    key=replicas_relation.data[self.app].get("private_key"),
                    ca=replicas_relation.data[self.app].get("ca_certificate"),
                    common_name=event.common_name,
                ),
                relation_id=event.relation_id,
            )

    def _on_certificate_creation_request_v1(self, event: CertificateRequestEventV1):
        if not self.unit.is_leader():
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if self._self_signed_certificates:
            if not self._root_certificates_are_set:
                event.defer()
                return
            certificate = self._generate_self_signed_certificates_v1(
                event.certificate_signing_request
            )
            self.tls_certificates_v1.set_relation_certificate(
                certificate_signing_request=event.certificate_signing_request,
                certificate=certificate,
                ca=replicas_relation.data[self.app].get("ca_certificate"),
                chain=replicas_relation.data[self.app].get("ca_certificate"),
                relation_id=event.relation_id,
            )
        else:
            if not self._config_certificates_are_set:
                logger.error(
                    "Configuration options are missing - "
                    "Certificates can't be passed through relation"
                )
                return

            self.tls_certificates_v1.set_relation_certificate(
                certificate_signing_request=event.certificate_signing_request,
                certificate=replicas_relation.data[self.app].get("certificate"),
                ca=replicas_relation.data[self.app].get("ca_certificate"),
                chain=replicas_relation.data[self.app].get("ca_certificate"),
                relation_id=event.relation_id,
            )

    @property
    def _config_certificates_are_set(self) -> bool:
        """Returns whether certificates are set in stored data.

        Returns:
            bool: Whether all certificates are set.
        """
        replicas = self.model.get_relation("replicas")
        return (
            replicas.data[self.app].get("certificate")  # type: ignore[union-attr]  # noqa: W503 E501
            and replicas.data[self.app].get("ca_certificate")  # type: ignore[union-attr]  # noqa: W503 E501
            and replicas.data[self.app].get("private_key")  # type: ignore[union-attr]  # noqa: W503 E501
        )

    @property
    def _root_certificates_are_set(self) -> bool:
        """Returns whether certificates are set in stored data.

        Returns:
            bool: Whether all certificates are set.
        """
        replicas = self.model.get_relation("replicas")
        return (
            replicas.data[self.app].get("ca_private_key")  # type: ignore[union-attr]  # noqa: W503 E501
            and replicas.data[self.app].get("ca_certificate")  # type: ignore[union-attr]  # noqa: W503 E501
            and replicas.data[self.app].get("ca_private_key_password")  # type: ignore[union-attr]  # noqa: W503 E501
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
        """Decodes bytes to string.

        Args:
            bytes_content (bytes): Bytes content

        Returns:
            str: String
        """
        return bytes_content.decode("utf-8")

    @staticmethod
    def _generate_password() -> str:
        """Generates a random 12 character password.

        Returns:
            str: Password
        """
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(12))


if __name__ == "__main__":
    main(TLSCertificatesOperatorCharm)
