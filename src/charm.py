#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator through Juju configs.
"""

import base64
import binascii
import json
import logging
from typing import List, Optional

from charms.tempo_k8s.v1.charm_tracing import trace_charm
from charms.tempo_k8s.v2.tracing import TracingEndpointRequirer
from charms.tls_certificates_interface.v3.tls_certificates import (
    TLSCertificatesProvidesV3,
    csr_matches_certificate,
)
from helpers import (
    ca_chain_is_valid,
    certificate_is_valid,
    certificate_signing_request_is_valid,
    parse_ca_chain,
)
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)

CERTIFICATES_RELATION = "certificates"

@trace_charm(
    tracing_endpoint="tempo_otlp_http_endpoint",
    extra_types=(
        TLSCertificatesProvidesV3,
    ),
)
class ManualTLSCertificatesCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observe config change and certificate request events."""
        super().__init__(*args)
        self.tls_certificates = TLSCertificatesProvidesV3(self, CERTIFICATES_RELATION)
        self.tracing = TracingEndpointRequirer(self, protocols=["otlp_http"])
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        self.framework.observe(
            self.on.get_outstanding_certificate_requests_action,
            self._on_get_outstanding_certificate_requests_action,
        )
        self.framework.observe(
            self.on.provide_certificate_action,
            self._on_provide_certificate_action,
        )

    def _on_collect_unit_status(self, event: CollectStatusEvent):
         """Centralized status management for the charm."""
         outstanding_requests_num = len(
            self.tls_certificates.get_outstanding_certificate_requests()
        )
         if outstanding_requests_num == 0:
            event.add_status(ActiveStatus("No outstanding requests."))
            return
         event.add_status(ActiveStatus(
             f"{outstanding_requests_num} outstanding requests, "
            f"use juju actions to provide certificates"
         ))

    def _on_get_outstanding_certificate_requests_action(
        self,
        event: ActionEvent,
    ) -> None:
        """Return outstanding certificate requests.

        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self._relation_created("certificates"):
            event.fail(message="No certificates relation has been created yet.")
            return None

        outstanding_csrs = self.tls_certificates.get_outstanding_certificate_requests(
            relation_id=event.params.get("relation-id")
        )

        event.set_results(
            {
                "result": json.dumps([vars(csr) for csr in outstanding_csrs]),
            }
        )

    def _on_provide_certificate_action(self, event: ActionEvent) -> None:
        """Provide certificate to a specific requirer unit.

        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self._relation_created("certificates"):
            event.fail(message="No certificates relation has been created yet.")
            return
        ca_chain = event.params.get("ca-chain", None)
        if not ca_chain:
            ca_chain = event.params["ca-certificate"]
        if not self._action_certificates_are_valid(
            certificate=event.params["certificate"],
            ca_certificate=event.params["ca-certificate"],
            certificate_signing_request=event.params["certificate-signing-request"],
            ca_chain=ca_chain,
        ):
            event.fail(message="Action input is not valid.")
            return

        ca_chain_list = parse_ca_chain(base64.b64decode(ca_chain).decode())
        csr = (
            base64.b64decode(event.params["certificate-signing-request"])
            .decode("utf-8")
            .strip()
        )
        certificate = (
            base64.b64decode(event.params["certificate"]).decode("utf-8").strip()
        )
        ca_cert = (
            base64.b64decode(event.params["ca-certificate"]).decode("utf-8").strip()
        )

        if not csr_matches_certificate(csr=csr, cert=certificate):
            event.fail(message="Certificate and CSR do not match.")
            return

        relation_ids_with_given_csr = []
        for relation in self.model.relations.get("certificates", []):
            if self._csr_exists_in_requirer(csr=csr, relation_id=relation.id):
                relation_ids_with_given_csr.append(relation.id)

        given_relation_id = event.params.get("relation-id", None)
        err = self._relation_id_parameter_valid(
            relation_ids_with_given_csr, given_relation_id
        )
        if err:
            event.fail(message=err)
            return

        try:
            self.tls_certificates.set_relation_certificate(
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca_cert,
                chain=ca_chain_list,
                relation_id=(
                    given_relation_id
                    if given_relation_id
                    else relation_ids_with_given_csr[0]
                ),
            )
        except RuntimeError:
            event.fail(message="Relation does not exist with the provided id.")
            return
        event.set_results({"result": "Certificates successfully provided."})

    def _csr_exists_in_requirer(self, csr: str, relation_id: int) -> bool:
        """Validate certificates provided in action.

        Args:
            csr (str): certificate signing request in their original str representation.
            relation_id (int): Relation id with the requirer.

        Returns:
            bool: Whether the csr exists on the requirer.
        """
        for requirer_csr in self.tls_certificates.get_requirer_csrs(relation_id):
            if requirer_csr.csr == csr:
                return True
        return False

    def _relation_id_parameter_valid(
        self, requirer_relation_ids: List[int], relation_id: Optional[str]
    ) -> str:
        """Validate that a relation id is provided appropriately.

        A relation id must be provided in cases where there are multiple relations where the same
        CSR was found, and the relation id must be one of the id's that has the CSR. If only 1
        CSR was found in the requirers, there is no need to provide a relation id to the function.

        Args:
            requirer_relation_ids (List[str]): The relation ids with the given CSR in their databag
            relation_id (str): The relation id of the charm that will be given the cert

        Returns:
            str: Error message if any
        """
        if not requirer_relation_ids:
            return "CSR was not found in any requirer databags."

        if not relation_id and len(requirer_relation_ids) > 1:
            return "Multiple requirers with the same CSR found."

        if relation_id is not None and relation_id not in requirer_relation_ids:
            return "Requested relation id is not the correct id of any found CSR's."
        return ""

    def _action_certificates_are_valid(
        self,
        certificate: str,
        ca_certificate: str,
        certificate_signing_request: str,
        ca_chain: str,
    ) -> bool:
        """Validate certificates provided in action.

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
        if not ca_chain_is_valid(ca_chain_list):
            return False

        return True

    def _relation_created(self, relation_name: str) -> bool:
        """Return whether given relation was created.

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

    @property
    def tempo_otlp_http_endpoint(self) -> Optional[str]:
        """Tempo endpoint for charm tracing."""
        if self.tracing.is_ready():
            return self.tracing.get_endpoint('otlp_http')
        else:
            return None


if __name__ == "__main__":
    main(ManualTLSCertificatesCharm)
