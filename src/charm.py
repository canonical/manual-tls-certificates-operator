#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import base64
import binascii
import logging
from typing import Dict, List

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    TLSCertificatesProvidesV2,
    csr_matches_certificate,
)
from ops.charm import ActionEvent, CharmBase, EventBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus

from helpers import (
    certificate_is_valid,
    certificate_signing_request_is_valid,
    parse_ca_chain,
)

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
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.tls_certificates.on.certificate_creation_request,
            self._set_active_status,
        )
        self.framework.observe(
            self.on.certificates_relation_departed,
            self._set_active_status,
        )
        self.framework.observe(
            self.on.get_outstanding_certificate_requests_action,
            self._on_get_outstanding_certificate_requests_action,
        )
        self.framework.observe(
            self.on.provide_certificate_action,
            self._on_provide_certificate_action,
        )

    def _on_install(self, event: InstallEvent) -> None:
        """Handles the install event.

        The charm will be in Active Status and ready to handle actions.

        Args:
            event (InstallEvent): Juju event.

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

        event.set_results(
            {
                "result": self.tls_certificates.get_requirer_csrs_with_no_certs(
                    relation_id=event.params.get("relation-id")
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

        if not self._action_certificates_are_valid(
            certificate=event.params["certificate"],
            ca_certificate=event.params["ca-certificate"],
            certificate_signing_request=event.params["certificate-signing-request"],
            ca_chain=event.params["ca-chain"],
        ):
            event.fail(message="Action input is not valid.")
            return

        ca_chain_list = parse_ca_chain(base64.b64decode(event.params["ca-chain"]).decode())
        csr = base64.b64decode(event.params["certificate-signing-request"]).decode("utf-8").strip()
        certificate = base64.b64decode(event.params["certificate"]).decode("utf-8").strip()
        ca_cert = base64.b64decode(event.params["ca-certificate"]).decode("utf-8").strip()

        if not self._csr_exists_in_requirer(csr=csr, relation_id=event.params["relation-id"]):
            event.fail(message="Certificate signing request was not found in requirer data.")
            return

        if not csr_matches_certificate(csr=csr, cert=certificate):
            event.fail(message="Certificate and CSR do not match.")
            return

        try:
            self.tls_certificates.set_relation_certificate(
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca_cert,
                chain=ca_chain_list,
                relation_id=event.params["relation-id"],
            )
        except RuntimeError:
            event.fail(message="Relation does not exist with the provided id.")
            return
        event.set_results({"result": "Certificates successfully provided."})
        self._set_active_status(event=event)

    def _csr_exists_in_requirer(self, csr: str, relation_id: int) -> bool:
        """Validates certificates provided in action.

        Args:
            csr (str): certificate signing request in their original str representation.
            relation_id (int): Relation id with the requirer.

        Returns:
            bool: Whether the csr exists on the requirer.
        """
        all_unit_csr_mappings = self.tls_certificates.get_requirer_csrs(relation_id)
        for csr_mappings in all_unit_csr_mappings:
            for csrs in csr_mappings["unit_csrs"]:
                if csr == csrs["certificate_signing_request"]:
                    return True
        return False

    def _action_certificates_are_valid(
        self,
        certificate: str,
        ca_certificate: str,
        certificate_signing_request: str,
        ca_chain: str,
    ) -> bool:
        """Validates certificates provided in action.

        Args:
            certificate (str): Certificate in base64 string format
            ca_certificate (str): CA Certificate in base64 string format
            certificate_signing_request (str):
                Certificate signing request in base64 string format
            ca_chain (str): CA Chain in base64 string format

        Returns:
            bool: Whether certificates are valid.
        """
        try:
            certificate_bytes = self._decode_base64(certificate, "certificate")
            ca_certificate_bytes = self._decode_base64(ca_certificate, "ca_certificate")
            csr_bytes = self._decode_base64(
                certificate_signing_request, "certificate_signing_request"
            )
            ca_chain_bytes = self._decode_base64(ca_chain, "ca_chain")
        except ValueError:
            return False

        if not certificate_is_valid(certificate_bytes):
            return False
        if not certificate_is_valid(ca_certificate_bytes):
            return False
        if not certificate_signing_request_is_valid(csr_bytes):
            return False

        ca_chain_list = parse_ca_chain(ca_chain_bytes.decode())
        for ca in ca_chain_list:
            if not certificate_is_valid(ca.encode()):
                return False

        return True

    def _get_outstanding_requests(self) -> List[Dict[str, str]]:
        """Returns number of outstanding certificate requests.

        Returns:
            List: List of outstanding certificate requests.
        """
        certificate_request_list: List[Dict[str, str]] = []
        for element in self.tls_certificates.get_requirer_csrs_with_no_certs():
            certificate_request_list += element["unit_csrs"]
        return certificate_request_list

    def _set_active_status(self, event: EventBase) -> None:
        """Sets active status with number of outstanding requests.

        Args:
            event (EventBase): Juju event.

        Returns:
            None
        """
        outstanding_requests_num = len(self._get_outstanding_requests())
        if outstanding_requests_num == 0:
            self.unit.status = ActiveStatus("No outstanding requests.")
            return None
        self.unit.status = ActiveStatus(
            f"{outstanding_requests_num} outstanding requests, "
            f"use juju actions to provide certificates"
        )

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether given relation was created.

        Args:
            relation_name (str): Relation name
        """
        return bool(self.model.relations.get(relation_name, []))

    def _decode_base64(self, data, label):
        try:
            return base64.b64decode(data)
        except (binascii.Error, TypeError) as e:
            logger.error("Invalid input for '%s': %s", label, e)
            raise ValueError()


if __name__ == "__main__":
    main(TLSCertificatesOperatorCharm)
