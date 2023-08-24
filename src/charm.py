#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import base64
import binascii
import logging

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV2,
)
from ops.charm import ActionEvent, CharmBase, ConfigChangedEvent
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus

from helpers import certificate_is_valid, certificate_request_is_valid, parse_ca_chain

logger = logging.getLogger(__name__)

CERTIFICATES_RELATION = "certificates"


class TLSCertificatesOperatorCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observes config change and certificate request events."""
        super().__init__(*args)
        if not self.unit.is_leader():
            raise NotImplementedError("Scaling is not implemented for this charm")
        self.tls_certificates = TLSCertificatesProvidesV2(self, CERTIFICATES_RELATION)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.tls_certificates.on.certificate_creation_request,
            self._on_certificate_creation_request,
        )
        self.framework.observe(
            self.on.get_outstanding_certificate_requests_action,
            self._on_get_outstanding_certificate_requests_action,
        )
        self.framework.observe(
            self.on.get_certificate_request_action,
            self._on_get_certificate_request_action,
        )
        self.framework.observe(
            self.on.provide_certificate_action,
            self._on_provide_certificate_action,
        )

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Triggered when the Juju config is changed.

        The charm is will be in Active Status and ready to handle actions.

        Args:
            event (ConfigChangedEvent): Juju event.

        Returns:
            None
        """
        self.unit.status = WaitingStatus("Waiting for certificate creation request.")

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        """Triggered when a certificate creation request is received.

        Args:
            event (CertificateCreationRequestEvent): Juju event.

        Returns:
            None
        """
        self.unit.status = ActiveStatus("Ready to provide certificates.")

    def _on_get_outstanding_certificate_requests_action(self, event: ActionEvent) -> None:
        """Returns outstanding certificate requests.

        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self._relation_created("certificates"):
            event.fail(message="No certificates relation has been created yet.")
            return None

        event.set_results({"result": self.tls_certificates.get_requirer_csrs_with_no_certs()})

    def _on_get_certificate_request_action(self, event: ActionEvent) -> None:
        """Returns certificate request for a specific relation.

        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self._relation_created("certificates"):
            event.fail(message="No certificates relation has been created yet.")
            return None

        event.set_results(
            {
                "result": self.tls_certificates.get_requirer_csrs(
                    relation_id=event.params["relation_id"]
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
        if not self._relation_created("certificates"):
            event.fail(message="No certificates relation has been created yet.")
            return

        if not self._action_certificates_are_valid(event):
            event.fail(message="Action input is not valid.")
            return

        ca_chain_list = parse_ca_chain(base64.b64decode(event.params["ca_chain"]).decode())
        csr = base64.b64decode(event.params["certificate_signing_request"]).decode("utf-8").strip()
        certificate = base64.b64decode(event.params["certificate"]).decode("utf-8").strip()
        ca_cert = base64.b64decode(event.params["ca_certificate"]).decode("utf-8").strip()

        try:
            self.tls_certificates.set_relation_certificate(
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca_cert,
                chain=ca_chain_list,
                relation_id=event.params["relation_id"],
            )
        except RuntimeError:
            event.fail(message="Relation does not exist with the provided id.")
            return
        event.set_results({"result": "Certificates successfully provided."})

    def _action_certificates_are_valid(self, event: ActionEvent) -> bool:
        """Validates certificates provided in action.

        Args:
            event: Juju event.

        Returns:
            bool: Wether certificates are valid.
        """
        try:
            certificate_bytes = base64.b64decode(event.params["certificate"])
            ca_certificate_bytes = base64.b64decode(event.params["ca_certificate"])
            csr_bytes = base64.b64decode(event.params["certificate_signing_request"])
            ca_chain_bytes = base64.b64decode(event.params["ca_chain"])
        except (binascii.Error, TypeError) as e:
            logger.error("Invalid input: %s", e)
            return False

        if not certificate_is_valid(certificate_bytes):
            return False
        if not certificate_is_valid(ca_certificate_bytes):
            return False
        if not certificate_request_is_valid(csr_bytes):
            return False

        ca_chain_list = parse_ca_chain(ca_chain_bytes.decode())
        for ca in ca_chain_list:
            if not certificate_is_valid(ca.encode()):
                return False

        return True

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether given relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: True/False
        """
        try:
            if self.model.relations.get(relation_name, []):
                return True
            return False
        except KeyError:
            return False


if __name__ == "__main__":
    main(TLSCertificatesOperatorCharm)
