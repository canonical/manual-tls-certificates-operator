# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import logging
from pathlib import Path

import pytest
import yaml
from juju.errors import JujuError  # type: ignore[import]
from pytest_operator.plugin import OpsTest  # type: ignore[import]  # noqa: F401

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

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
        resources = {
            "placeholder-image": METADATA["resources"]["placeholder-image"]["upstream-source"],
        }
        await ops_test.model.deploy(
            entity_url=charm,
            resources=resources,
            application_name=APPLICATION_NAME,
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)

    async def test_given_correct_config_when_deploy_then_status_is_active(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        resources = {
            "placeholder-image": METADATA["resources"]["placeholder-image"]["upstream-source"],
        }
        certificate = self.get_certificate_from_file(filename="tests/test_certificate.pem")
        ca_certificate = self.get_certificate_from_file(filename="tests/test_ca_certificate.pem")
        private_key = self.get_certificate_from_file(filename="tests/test_private_key.key")
        certificate_bytes = base64.b64encode(certificate.encode("utf-8"))
        ca_certificate_bytes = base64.b64encode(ca_certificate.encode("utf-8"))
        private_key_bytes = base64.b64encode(private_key.encode("utf-8"))
        config = {
            "certificate": certificate_bytes.decode("utf-8"),
            "private-key": private_key_bytes.decode("utf-8"),
            "ca-certificate": ca_certificate_bytes.decode("utf-8"),
        }

        await ops_test.model.deploy(
            entity_url=charm, resources=resources, application_name=APPLICATION_NAME, config=config
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)
