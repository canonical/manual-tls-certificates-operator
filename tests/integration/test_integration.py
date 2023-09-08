# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import ast
import base64
import logging

import pytest
from juju.errors import JujuError

logger = logging.getLogger(__name__)

APPLICATION_NAME = "tls-certificates-operator"
TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"


class TestTLSCertificatesOperator:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def charm(self, ops_test):
        ops_test.destructive_mode = False
        charm = await ops_test.build_charm(".")
        return charm

    @staticmethod
    def get_certificate_from_file(filename: str) -> str:
        with open(filename, "r") as file:
            certificate = file.read()
        return certificate

    @pytest.fixture()
    async def cleanup(self, ops_test):
        try:
            await ops_test.model.remove_application(
                app_name=APPLICATION_NAME, block_until_done=True
            )
            await ops_test.model.remove_application(
                app_name=TLS_REQUIRER_CHARM_NAME, block_until_done=True
            )
        except JujuError:
            pass

    async def test_given_no_requirer_when_deploy_then_status_is_waiting(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        await ops_test.model.deploy(
            entity_url=charm,
            application_name=APPLICATION_NAME,
            series="jammy",
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    async def test_given_requirer_requests_certificate_creation_when_deploy_then_status_is_active(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        await ops_test.model.deploy(
            TLS_REQUIRER_CHARM_NAME,
            application_name=TLS_REQUIRER_CHARM_NAME,
            channel="edge",
        )
        await ops_test.model.deploy(
            entity_url=charm,
            application_name=APPLICATION_NAME,
            series="jammy",
        )
        await ops_test.model.wait_for_idle(
            apps=[TLS_REQUIRER_CHARM_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.add_relation(
            relation1=APPLICATION_NAME, relation2=TLS_REQUIRER_CHARM_NAME
        )

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_tls_requirer_is_deployed_and_related_when_provide_certificate_then_certificate_is_passed_correctly(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        await ops_test.model.deploy(
            TLS_REQUIRER_CHARM_NAME,
            application_name=TLS_REQUIRER_CHARM_NAME,
            channel="edge",
        )
        await ops_test.model.wait_for_idle(
            apps=[TLS_REQUIRER_CHARM_NAME],
            status="active",
            timeout=1000,
        )

        await ops_test.model.deploy(
            entity_url=charm,
            application_name=APPLICATION_NAME,
            series="jammy",
        )

        relation = await ops_test.model.add_relation(
            relation1=APPLICATION_NAME, relation2=TLS_REQUIRER_CHARM_NAME
        )

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))

        action_output = await run_get_outstanding_csrs_action(ops_test)

        action_result_list = ast.literal_eval(action_output["result"])
        csr = action_result_list[0]["unit_csrs"][0]["certificate_signing_request"]
        csr_bytes = base64.b64encode(csr.encode("utf-8"))

        await run_provide_certificate_action(
            ops_test,
            relation_id=relation.id,
            certificate=certificate_bytes.decode("utf-8"),
            ca_certificate=ca_certificate_bytes.decode("utf-8"),
            ca_chain=ca_chain_bytes.decode("utf-8"),
            csr=csr_bytes.decode("utf-8"),
        )

        await ops_test.model.wait_for_idle(
            apps=[TLS_REQUIRER_CHARM_NAME],
            status="active",
            timeout=1000,
        )

        action_output = await run_get_certificate_action(ops_test)
        assert action_output["certificate"] == certificate.strip("\n")
        assert action_output["ca-certificate"] == ca_certificate.strip("\n")
        formatted_chain = (
            action_output["chain"]
            .replace("[", "")
            .replace("]", "")
            .replace("'", "")
            .replace(", ", "\n")
            .replace("\\n", "\n")
        )
        assert formatted_chain == ca_chain.strip("\n")


async def run_get_certificate_action(ops_test) -> dict:
    """Runs `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    tls_requirer_unit = ops_test.model.units[f"{TLS_REQUIRER_CHARM_NAME}/0"]
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output


async def run_get_outstanding_csrs_action(ops_test) -> dict:
    """Runs `get-outstanding-certificate-requests` on the `tls-certificates-operator/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    tls_operator_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
    action = await tls_operator_unit.run_action(
        action_name="get-outstanding-certificate-requests",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output


async def run_provide_certificate_action(
    ops_test,
    relation_id: int,
    certificate: str,
    ca_certificate: str,
    ca_chain: str,
    csr: str,
) -> dict:
    """Runs `provide-certificate` on the `tls-certificates-operator/0` unit.

    Args:
        ops_test (OpsTest): OpsTest
        relation_id (int): Relation ID
        certificate (str): Certificate
        ca_certificate (str): CA Certificate
        ca_chain (str): CA Chain
        csr (str): CSR

    Returns:
        dict: Action output
    """
    tls_operator_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
    action = await tls_operator_unit.run_action(
        action_name="provide-certificate",
        **{
            "relation-id": relation_id,
            "certificate": certificate,
            "ca-certificate": ca_certificate,
            "ca-chain": ca_chain,
            "certificate-signing-request": csr,
        },
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output
