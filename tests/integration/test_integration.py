# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import logging

import pytest
from juju.errors import JujuError

logger = logging.getLogger(__name__)

APPLICATION_NAME = "tls-certificates-operator"


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
