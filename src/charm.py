#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator through Juju configs.
"""

import base64
import json
import logging
from typing import Any, List, Optional, Set

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    ProviderCertificate,
    TLSCertificatesError,
    TLSCertificatesProvidesV4,
)
from cryptography.hazmat.primitives import serialization
from ops import BlockedStatus
from ops.charm import (
    ActionEvent,
    CharmBase,
    CollectStatusEvent,
    ConfigChangedEvent,
    RelationJoinedEvent,
)
from ops.main import main
from ops.model import ActiveStatus

from helpers import parse_ca_chain, parse_pem_bundle

logger = logging.getLogger(__name__)

CERTIFICATES_RELATION = "certificates"
CERTIFICATE_TRANSFER_RELATION = "trust_certificate"


@trace_charm(
    tracing_endpoint="tempo_otlp_http_endpoint",
    extra_types=(TLSCertificatesProvidesV4,),
)
class ManualTLSCertificatesCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args: Any):
        """Observe config change and certificate request events."""
        super().__init__(*args)
        self.tracing = TracingEndpointRequirer(self, protocols=["otlp_http"])
        self.tls_certificates = TLSCertificatesProvidesV4(self, CERTIFICATES_RELATION)
        self.certificate_transfer = CertificateTransferProvides(
            self,
            CERTIFICATE_TRANSFER_RELATION,
        )
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.get_outstanding_certificate_requests_action,
            self._on_get_outstanding_certificate_requests_action,
        )
        self.framework.observe(
            self.on.provide_certificate_action,
            self._on_provide_certificate_action,
        )
        self.framework.observe(
            self.on.trust_certificate_relation_joined,
            self._on_trust_certificate_relation_joined,
        )

    @property
    def tempo_otlp_http_endpoint(self) -> Optional[str]:
        """Tempo endpoint for charm tracing."""
        if self.tracing.is_ready():
            return self.tracing.get_endpoint("otlp_http")
        else:
            return None

    def _on_collect_unit_status(self, event: CollectStatusEvent):
        """Centralized status management for the charm."""
        if self.model.relations.get(CERTIFICATE_TRANSFER_RELATION):
            try:
                self._get_trusted_certificate_bundle()
            except KeyError:
                event.add_status(ActiveStatus("No trusted certificate bundle configured"))
                return
            except ValueError:
                event.add_status(BlockedStatus("Invalid trusted certificate bundle configured"))
                return

        outstanding_requests_num = len(
            self.tls_certificates.get_outstanding_certificate_requests()
        )
        if outstanding_requests_num == 0:
            event.add_status(ActiveStatus("No outstanding requests."))
            return

        event.add_status(
            ActiveStatus(
                f"{outstanding_requests_num} outstanding requests, "
                f"use juju actions to provide certificates"
            )
        )

    def _on_config_changed(self, _: ConfigChangedEvent) -> None:
        """Update certificate_transfer relations when configuration changed.

        Args:
            event: Juju ConfigChangedEvent
        """
        if not self._relation_created(CERTIFICATE_TRANSFER_RELATION):
            return
        try:
            bundle = self._get_trusted_certificate_bundle()
            self.certificate_transfer.add_certificates(bundle)
        except (KeyError, ValueError) as e:
            logger.warning("Trust certificate relation cannot be fulfilled: %s", e)

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
                "result": json.dumps(
                    [
                        {
                            "csr": str(csr.certificate_signing_request),
                            "relation_id": csr.relation_id,
                        }
                        for csr in outstanding_csrs
                    ]
                ),
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
        try:
            ca_chain = [
                Certificate.from_string(
                    cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                )
                for cert in parse_ca_chain(decode_action_base64_input(event.params["ca-chain"]))
            ]
            certificate = Certificate.from_string(
                decode_action_base64_input(event.params["certificate"])
            )
            ca_certificate = Certificate.from_string(
                decode_action_base64_input(event.params["ca-certificate"])
            )
            csr = CertificateSigningRequest.from_string(
                decode_action_base64_input(event.params["certificate-signing-request"])
            )
        except KeyError:
            event.fail(message="One or more action parameters are missing.")
            return
        except ValueError:
            event.fail(message="Action input is not valid.")
            return

        if not csr.matches_certificate(certificate):
            event.fail(message="Certificate and CSR do not match.")
            return

        relation_ids_with_given_csr = []
        for relation in self.model.relations.get("certificates", []):
            if self._csr_exists_in_requirer(csr=csr, relation_id=relation.id):
                relation_ids_with_given_csr.append(relation.id)

        given_relation_id = event.params.get("relation-id", None)
        err = self._relation_id_parameter_valid(relation_ids_with_given_csr, given_relation_id)
        if err:
            event.fail(message=err)
            return

        try:
            self.tls_certificates.set_relation_certificate(
                provider_certificate=ProviderCertificate(
                    relation_id=(
                        given_relation_id if given_relation_id else relation_ids_with_given_csr[0]
                    ),
                    certificate=certificate,
                    certificate_signing_request=csr,
                    ca=ca_certificate,
                    chain=ca_chain,
                ),
            )
        except TLSCertificatesError:
            event.fail(message="Relation does not exist with the provided id.")
            return
        event.set_results({"result": "Certificates successfully provided."})

    def _on_trust_certificate_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Provide trust certificate if configured to new requirer.

        Args:
            event: Juju event.

        Returns:
            None
        """
        try:
            bundle = self._get_trusted_certificate_bundle()
            self.certificate_transfer.add_certificates(
                bundle,
                relation_id=event.relation.id,
            )
        except (KeyError, ValueError) as e:
            logger.warning("Trust certificate relation cannot be fulfilled: %s", e)

    def _get_trusted_certificate_bundle(self) -> Set[str]:
        """Provide trust certificate if configured to new requirer.

        Args:
            event: Juju event.

        Returns:
            set[Certificate]: Set of certificates in the bundle

        Raises:
            KeyError: if the configuration is not provided
            ValueError: if the configuration is invalid
        """
        bundle = self.model.config["trusted-certificate-bundle"]
        return {
            cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip()
            for cert in parse_pem_bundle(str(bundle))
        }

    def _csr_exists_in_requirer(self, csr: CertificateSigningRequest, relation_id: int) -> bool:
        """Validate certificates provided in action.

        Args:
            csr (CertificateSigningRequest): certificate signing request.
            relation_id (int): Relation id with the requirer.

        Returns:
            bool: Whether the csr exists on the requirer.
        """
        for requirer_csr in self.tls_certificates.get_certificate_requests(relation_id):
            if requirer_csr.certificate_signing_request == csr:
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

    def _relation_created(self, relation_name: str) -> bool:
        """Return whether given relation was created.

        Args:
            relation_name (str): Relation name
        """
        return bool(self.model.relations.get(relation_name, []))


def decode_action_base64_input(input: str) -> str:
    """Decode base64 string to Python string."""
    return base64.b64decode(input).decode("utf-8").strip()


if __name__ == "__main__":
    main(ManualTLSCertificatesCharm)
