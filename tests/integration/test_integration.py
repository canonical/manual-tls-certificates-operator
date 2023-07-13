# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

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
        except JujuError:
            pass

    async def test_given_no_config_when_deploy_then_status_is_blocked(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        await ops_test.model.deploy(
            entity_url=charm,
            application_name=APPLICATION_NAME,
            series="jammy",
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)

    async def test_given_correct_config_when_deploy_then_status_is_active(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        config = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }

        await ops_test.model.deploy(
            entity_url=charm,
            application_name=APPLICATION_NAME,
            config=config,
            series="jammy",
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    async def test_given_correct_config_when_deploy_and_scale_then_status_is_active(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        certificate = self.get_certificate_from_file(filename="tests/certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/ca_certificate.pem")
        ca_chain = self.get_certificate_from_file(filename="tests/ca_chain.pem")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        ca_chain_bytes = base64.b64encode(ca_chain.encode("utf-8"))
        config = {
            "certificate": certificate_bytes.decode("utf-8"),
            "ca-chain": ca_chain_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }

        await ops_test.model.deploy(
            entity_url=charm,
            application_name=APPLICATION_NAME,
            config=config,
            series="jammy",
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

        await ops_test.model.applications[APPLICATION_NAME].scale(2)

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_units=2,
        )

        await ops_test.model.applications[APPLICATION_NAME].scale(1)

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    async def test_given_tls_requirer_is_deployed_and_related_then_certificate_is_created_and_passed_correctly(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        await ops_test.model.deploy(
            TLS_REQUIRER_CHARM_NAME,
            application_name=TLS_REQUIRER_CHARM_NAME,
            channel="edge",
        )
        await ops_test.model.add_relation(
            relation1=f"{APPLICATION_NAME}:certificates", relation2=f"{TLS_REQUIRER_CHARM_NAME}"
        )
        await ops_test.model.wait_for_idle(
            apps=[TLS_REQUIRER_CHARM_NAME],
            status="active",
            timeout=1000,
        )
        action_output = await run_get_certificate_action(ops_test)
        assert action_output["certificate"] == self.get_certificate_from_file(
            filename="tests/certificate.pem"
        )
        assert action_output["ca-certificate"] == self.get_certificate_from_file(
            filename="tests/ca_certificate.pem"
        )
        assert action_output["chain"] == self.get_certificate_from_file(
            filename="tests/ca_chain.pem"
        )


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
