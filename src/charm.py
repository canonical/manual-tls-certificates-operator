#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import base64
import binascii
import json
import logging
import secrets
import string
from typing import List, Optional

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV2,
    generate_csr,
)
from ops.charm import ActionEvent, CharmBase, ConfigChangedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from self_signed_certificates import (
    certificate_is_valid,
    generate_ca,
    generate_certificate,
    generate_private_key,
    parse_ca_chain,
)

logger = logging.getLogger(__name__)

CERTIFICATES_RELATION = "certificates"


class TLSCertificatesOperatorCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observes config change and certificate request events."""
        super().__init__(*args)
        self.tls_certificates = TLSCertificatesProvidesV2(self, CERTIFICATES_RELATION)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.tls_certificates.on.certificate_creation_request,
            self._on_certificate_creation_request,
        )
        self.framework.observe(
            self.on.generate_self_signed_certificate_action,
            self._on_generate_self_signed_certificate_action,
        )
        self.framework.observe(
            self.on.get_all_certificate_requests_action,
            self._on_get_all_certificate_requests_action,
        )
        self.framework.observe(
            self.on.get_certificate_request_action,
            self._on_get_certificate_request_action,
        )
        self.framework.observe(
            self.on.provide_certificate_action,
            self._on_provide_certificate_action,
        )

    @property
    def _certificate_validity(self) -> int:
        """Returns self-signed certificate validity (in days).

        Returns:
            int: Certificate validity (in days)
        """
        return int(self.model.config.get("certificate-validity", 365))

    @property
    def _ca_certificate_validity(self) -> int:
        """Returns CA certificate validity (in days).

        Returns:
            int: CA Certificate validity (in days)
        """
        return int(self.model.config.get("ca-certificate-validity", 365))

    @property
    def _self_signed_certificates(self) -> bool:
        """Returns whether the 'generate-self-signed-certificates' config is set to True.

        Returns:
            bool: True/False
        """
        if self.model.config.get("generate-self-signed-certificates", False):
            return True
        else:
            return False

    @property
    def _config_ca_common_name(self) -> Optional[str]:
        """Returns the user provided common name.

         This common name should only be used when the 'generate-self-signed-certificates' config
         is set to True.

        Returns:
            str: Common name
        """
        return self.model.config.get("ca-common-name", None)

    @property
    def _config_certificates_are_valid(self) -> bool:
        """Returns whether user provided certificates are valid.

        Returns:
            bool: True/False
        """
        try:
            certificate_bytes = base64.b64decode(self.model.config.get("certificate", None))  # type: ignore[arg-type]  # noqa: E501
            ca_certificate_bytes = base64.b64decode(self.model.config.get("ca-certificate", None))  # type: ignore[arg-type]  # noqa: E501
        except (binascii.Error, TypeError):
            return False
        if not certificate_is_valid(certificate_bytes):
            logger.error("Config `certificate` is not valid")
            return False
        if not certificate_is_valid(ca_certificate_bytes):
            logger.error("Config `ca-certificate` is not valid")
            return False
        config_ca_chain = self.model.config.get("ca-chain", None)
        if config_ca_chain:
            try:
                ca_chain_bytes = base64.b64decode(self.model.config.get("ca-chain", None))  # type: ignore[arg-type]  # noqa: E501
            except (binascii.Error, TypeError):
                logger.error(
                    "Config `ca-chain` is not valid because it is badly encoded."
                    "Please use --config ca-chain='$(base64 -w0 ca_chain.pem)'."
                )
                return False
            list_of_certificates = parse_ca_chain(ca_chain_bytes.decode())
            for certificate in list_of_certificates:
                if not certificate_is_valid(certificate.encode()):
                    logger.error("Config `ca-chain` is not valid because of a bad certificate.")
                    return False
        return True

    @property
    def _replicas_relation_created(self) -> bool:
        return self._relation_created("replicas")

    @property
    def _config_certificates_are_stored(self) -> bool:
        """Returns whether certificates are set in stored data.

        Returns:
            bool: Whether all certificates are set.
        """
        replicas = self.model.get_relation("replicas")
        if not replicas:
            return False
        if not self._config_certificate:
            logger.info("Config certificate not stored")
            return False
        if not self._config_ca_certificate:
            logger.info("Config CA certificate not stored")
            return False
        if not self._config_ca_chain:
            logger.info("Config CA chain not stored")
            return False
        return True

    @property
    def _config_certificate(self) -> Optional[str]:
        return self._get_value_from_peer_relation_data("config_certificate")

    @property
    def _config_ca_chain(self) -> List[str]:
        relation_data_config_ca_chain = self._get_value_from_peer_relation_data("config_ca_chain")
        if relation_data_config_ca_chain:
            return json.loads(relation_data_config_ca_chain)
        else:
            return []

    @property
    def _config_ca_certificate(self) -> Optional[str]:
        return self._get_value_from_peer_relation_data("config_ca_certificate")

    @property
    def _self_signed_ca_certificate(self) -> Optional[str]:
        return self._get_value_from_peer_relation_data("self_signed_ca_certificate")

    @property
    def _self_signed_ca_private_key(self) -> Optional[str]:
        return self._get_value_from_peer_relation_data("self_signed_ca_private_key")

    @property
    def _self_signed_ca_private_key_password(self) -> Optional[str]:
        return self._get_value_from_peer_relation_data("self_signed_ca_private_key_password")

    @property
    def _self_signed_root_certificates_are_stored(self) -> bool:
        """Returns whether self-signed certificates are stored in relation data.

        Returns:
            bool: Whether all certificates are set.
        """
        replicas = self.model.get_relation("replicas")
        if not replicas:
            logger.info("Replicas relation not created")
            return False
        if not self._self_signed_ca_certificate:
            logger.info("CA Certificate not stored")
            return False
        if not self._self_signed_ca_private_key:
            logger.info("CA Private key not stored")
            return False
        if not self._self_signed_ca_private_key_password:
            logger.info("CA Private key password not stored")
            return False
        return True

    def _store_self_signed_ca_certificate(self, certificate: str) -> None:
        self._store_item_in_peer_relation_data(key="self_signed_ca_certificate", value=certificate)

    def _store_self_signed_ca_private_key(self, private_key: str) -> None:
        self._store_item_in_peer_relation_data(key="self_signed_ca_private_key", value=private_key)

    def _store_self_signed_ca_private_key_password(self, password: str) -> None:
        self._store_item_in_peer_relation_data(
            key="self_signed_ca_private_key_password", value=password
        )

    def _store_config_ca_certificate(self, certificate: str) -> None:
        self._store_item_in_peer_relation_data(key="config_ca_certificate", value=certificate)

    def _store_config_certificate(self, certificate: str) -> None:
        self._store_item_in_peer_relation_data(key="config_certificate", value=certificate)

    def _store_config_ca_chain(self, ca_chain: List[str]) -> None:
        self._store_item_in_peer_relation_data(key="config_ca_chain", value=json.dumps(ca_chain))

    def _store_item_in_peer_relation_data(self, key: str, value: str) -> None:
        """Stores key/value in peer relation data.

        Args:
            key (str): Relation data key
            value (str): Relation data value

        Returns:
            None
        """
        peer_relation = self.model.get_relation("replicas")
        if not peer_relation:
            raise RuntimeError("No peer relation")
        peer_relation.data[self.app].update({key: value.strip()})

    def _get_value_from_peer_relation_data(self, key: str) -> Optional[str]:
        """Returns value from relation data.

        Args:
            key (str): Relation data key

        Returns:
            str: Relation data value
        """
        replicas = self.model.get_relation("replicas")
        if not replicas:
            return None
        relation_data = replicas.data[self.app].get(key, None)
        if relation_data:
            return relation_data.strip()
        else:
            return None

    def _generate_root_certificates(self) -> None:
        """Generates root certificate to be used to sign certificates.

        Returns:
            None
        """
        private_key_password = self._generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        ca_certificate = generate_ca(
            private_key=private_key,
            subject=self._config_ca_common_name,  # type: ignore[arg-type]  # noqa: E501
            private_key_password=private_key_password.encode(),
            validity=self._ca_certificate_validity,
        )
        self._store_self_signed_ca_certificate(ca_certificate.decode())
        self._store_self_signed_ca_private_key(private_key.decode())
        self._store_self_signed_ca_private_key_password(private_key_password)
        logger.info("Root certificates generated and stored.")

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether given relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: True/False
        """
        try:
            if self.model.get_relation(relation_name):
                return True
            return False
        except KeyError:
            return False

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Triggered when the Juju config is changed.

        Args:
            event (ConfigChangedEvent): Juju event.

        Returns:
            None
        """
        if not self._replicas_relation_created:
            self.unit.status = WaitingStatus("Replicas relation not yet created")
            event.defer()
            return
        if self._self_signed_certificates:
            logger.warning(
                "The `self-signed` feature is deprecated and will be dropped in the furure, "
                "please use the self-signed-certificates operator."
            )
            if self.unit.is_leader():
                if not self._config_ca_common_name:
                    self.unit.status = BlockedStatus(
                        "Configuration `ca-common-name` must be set when "
                        "`generate-self-signed-certificates` is set to True."
                    )
                    return

                if self._certificate_validity > self._ca_certificate_validity:
                    self.unit.status = BlockedStatus(
                        "certificate validity is larger than CA certificate validity"
                    )
                    return

                self._generate_root_certificates()
                self.tls_certificates.revoke_all_certificates()
                logger.info("Revoked all previously issued certificates.")
            else:
                if not self._self_signed_root_certificates_are_stored:
                    self.unit.status = WaitingStatus(
                        "Waiting for root certificates to be generated."
                    )
                    event.defer()
                    return
        else:
            missing_config_options = self.get_missing_configuration_options()
            if missing_config_options:
                self.unit.status = BlockedStatus(
                    f"Configuration options missing: {missing_config_options}"
                )
                return
            if not self._config_certificates_are_valid:
                self.unit.status = BlockedStatus("Certificates are not valid")
                return
            if self.unit.is_leader():
                self._store_certificates_from_config()
                self.tls_certificates.revoke_all_certificates()
                logger.info("Revoked all previously issued certificates.")
        self.unit.status = ActiveStatus()

    def _store_certificates_from_config(self) -> None:
        """Stores user provided certificates based on config values."""
        ca_chain_config = self.model.config.get("ca-chain", None)
        certificate_config = self.model.config.get("certificate", None)
        ca_certificate_config = self.model.config.get("ca-certificate", None)
        if not certificate_config:
            raise ValueError("Config `certificate` not set")
        if not ca_certificate_config:
            raise ValueError("Config `ca-certificate` not set")
        self._store_config_ca_certificate(
            base64.b64decode(ca_certificate_config).decode("utf-8").strip()
        )
        self._store_config_certificate(
            base64.b64decode(certificate_config).decode("utf-8").strip()
        )
        if ca_chain_config:
            ca_chain_list = parse_ca_chain(base64.b64decode(ca_chain_config).decode("utf-8"))
        else:
            ca_chain_list = [
                base64.b64decode(ca_certificate_config).decode("utf-8").strip(),
                base64.b64decode(certificate_config).decode("utf-8").strip(),
            ]
        self._store_config_ca_chain(ca_chain_list)

    def _generate_self_signed_certificates(self, certificate_signing_request: str) -> str:
        """Generates self-signed certificates.

        Args:
            certificate_signing_request (str): Certificate signing request

        Returns:
            str: Certificate
        """
        if not self._self_signed_ca_private_key:
            raise ValueError("CA Private key not stored")
        if not self._self_signed_ca_private_key_password:
            raise ValueError("CA private key password not stored")
        if not self._self_signed_ca_certificate:
            raise ValueError("CA Certificate not stored")
        certificate = generate_certificate(
            ca=self._self_signed_ca_certificate.encode(),
            ca_key=self._self_signed_ca_private_key.encode(),
            ca_key_password=self._self_signed_ca_private_key_password.encode(),
            csr=certificate_signing_request.encode(),
            validity=self._certificate_validity,
        )
        logger.info("Generated self-signed certificates")
        return certificate.decode()

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        logger.info("Received Certificate Creation Request")
        if not self.unit.is_leader():
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if self._self_signed_certificates:
            if not self._self_signed_root_certificates_are_stored:
                self.unit.status = WaitingStatus("Root Certificates are not yet set")
                event.defer()
                return
            certificate = self._generate_self_signed_certificates(
                event.certificate_signing_request
            )
            ca_chain = [self._self_signed_ca_certificate, certificate]
            self.tls_certificates.set_relation_certificate(
                certificate_signing_request=event.certificate_signing_request,
                certificate=certificate,
                ca=self._self_signed_ca_certificate,
                chain=ca_chain,
                relation_id=event.relation_id,
            )
        else:
            if not self._config_certificates_are_stored:
                self.unit.status = BlockedStatus(
                    "Configuration options are missing - "
                    "Certificates can't be passed through relation"
                )
                event.defer()
                return
            self.tls_certificates.set_relation_certificate(
                certificate_signing_request=event.certificate_signing_request,
                certificate=self._config_certificate,
                ca=self._config_ca_certificate,
                chain=self._config_ca_chain,
                relation_id=event.relation_id,
            )

    def _on_generate_self_signed_certificate_action(self, event: ActionEvent) -> None:
        """Generates TLS Certificate.

        Generates a private key and certificate for an external service.
        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self.unit.is_leader():
            event.fail(message="Action cannot be run on non-leader unit")
            return

        if not self._self_signed_certificates:
            event.fail(message="Action not supported as charm is not configured to be self-signed")
            return

        if not self._self_signed_root_certificates_are_stored:
            event.fail(message="Root certificates not yet set")
            return

        sans = None
        if event.params["sans"]:
            sans = event.params["sans"].split(" ")

        private_key = generate_private_key()
        csr = generate_csr(
            private_key=private_key,
            subject=event.params["common-name"],
            sans=sans,
        )
        certificate = self._generate_self_signed_certificates(csr.decode())
        ca_chain = [self._self_signed_ca_certificate, certificate]
        event.set_results(
            {
                "private-key": private_key.decode(),
                "certificate": certificate,
                "ca-chain": ca_chain,
                "issuing-ca": self._self_signed_ca_certificate,
            }
        )

    def _on_get_all_certificate_requests_action(self, event: ActionEvent) -> None:
        """Returns all certificate requests.

        Args:
            event: Juju event.

        Returns:
            None
        """
        event.set_results(
            {"Result": self.tls_certificates.get_requirer_units_csrs_with_no_certs()}
        )

    def _on_get_certificate_request_action(self, event: ActionEvent) -> None:
        """Returns certificate request for a specific relation.

        Args:
            event: Juju event.

        Returns:
            None
        """
        event.set_results(
            {
                "Result": self.tls_certificates.get_requirer_csrs_by_unit(
                    relation_id=event.params["relation-id"]
                )
            }
        )

    def _on_provide_certificate_action(self, event: ActionEvent) -> None:
        """Provides certificate to a specific requirer unit.

        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self.unit.is_leader():
            event.fail(message="Action cannot be run on non-leader unit.")
            return

        if not self._action_certificates_are_valid(event):
            event.fail(message="Action input is not valid.")
            return

        ca_chain_list = parse_ca_chain(base64.b64decode(event.params["ca-chain"]).decode())
        csr = base64.b64decode(event.params["certificate-signing-request"]).decode("utf-8").strip()
        certificate = base64.b64decode(event.params["certificate"]).decode("utf-8").strip()
        ca_cert = base64.b64decode(event.params["ca-certificate"]).decode("utf-8").strip()

        try:
            self.tls_certificates.set_relation_certificate(
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca_cert,
                chain=ca_chain_list,
                relation_id=event.params["relation-id"],
                unit_name=event.params.get("unit-name", None),
            )
        except RuntimeError:
            event.fail(message="Relation does not exist with the provided id.")
            return
        event.set_results({"Result": "Certificates successfully provided."})

    def _action_certificates_are_valid(self, event: ActionEvent) -> bool:
        """Validates certificates provided in action.

        Args:
            event: Juju event.

        Returns:
            bool: Wether certificates are valid.
        """
        try:
            certificate_bytes = base64.b64decode(event.params["certificate"])
            ca_certificate_bytes = base64.b64decode(event.params["ca-certificate"])
            csr_bytes = base64.b64decode(event.params["certificate-signing-request"])
            ca_chain_bytes = base64.b64decode(event.params["ca-chain"])
        except (binascii.Error, TypeError) as e:
            logger.error("Invalid input: %s", e)
            return False

        if not certificate_is_valid(certificate_bytes):
            return False
        if not certificate_is_valid(ca_certificate_bytes):
            return False
        if not certificate_is_valid(csr_bytes):
            return False

        ca_chain_list = parse_ca_chain(ca_chain_bytes.decode())
        for ca in ca_chain_list:
            if not certificate_is_valid(ca.encode()):
                return False

        return True

    def get_missing_configuration_options(self) -> List[str]:
        """Returns the list of missing configuration options.

        Returns:
            list: List of config option names.
        """
        missing_config_options = []
        required_config_options = [
            "certificate",
            "ca-certificate",
        ]
        for config in required_config_options:
            if not self.model.config.get(config, None):
                missing_config_options.append(config)
        return missing_config_options

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
