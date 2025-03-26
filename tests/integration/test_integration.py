# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import datetime
import json
import logging
import platform
import time
from pathlib import Path
from typing import Dict

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from juju.model import Model
from juju.relation import Relation
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

ANY_CHARM_PATH = "./tests/integration/any_charm.py"
ANY_APP_NAME = "any-cert-transfer-requirer"
APPLICATION_NAME = "manual-tls-certificates"
ARCH = "arm64" if platform.machine() == "aarch64" else "amd64"
CERT_TRANSFER_LIB_PATH = "./lib/charms/certificate_transfer_interface/v1/certificate_transfer.py"
REQUIRER_CHARM_REVISION_ARM = 103
REQUIRER_CHARM_REVISION_AMD = 104
TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"
TRUSTED_PEM = "./tests/integration/trusted_certs.pem"


async def deploy_tls_requirer_charm(ops_test: OpsTest):
    assert ops_test.model
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER_CHARM_NAME,
        revision=REQUIRER_CHARM_REVISION_ARM if ARCH == "arm64" else REQUIRER_CHARM_REVISION_AMD,
        channel="stable",
        constraints={"arch": ARCH},
    )


async def get_leader_unit(model: Model, application_name: str) -> Unit:
    """Return the leader unit for the given application."""
    for unit in model.units.values():
        if unit.application == application_name and await unit.is_leader_from_status():
            return unit
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")


async def deploy_any_charm_as_cert_transfer_requirer(model: Model):
    """Deploy AnyCharm as a certificate_transfer requirer."""
    cert_transfer_lib = Path(CERT_TRANSFER_LIB_PATH).read_text()
    any_charm_src_overwrite = {
        "certificate_transfer.py": cert_transfer_lib,
        "any_charm.py": Path(ANY_CHARM_PATH).read_text(),
    }
    await model.deploy(
        "any-charm",
        application_name=ANY_APP_NAME,
        channel="beta",
        config={
            "src-overwrite": json.dumps(any_charm_src_overwrite),
            "python-packages": "ops==2.17.1\npytest-interface-tester",
        },
    )


class TestManualTLSCertificatesOperator:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def charm_path(self, request: pytest.FixtureRequest) -> Path:
        return Path(str(request.config.getoption("--charm_path"))).resolve()

    @staticmethod
    def get_certificate_and_ca_certificate_from_csr(csr: str) -> dict:
        """Create a Certificate and a CA certificate from a CSR.

        Args:
            csr (str): certificate signing request in their original str representation.

        Returns:
            dict: Containing the Certificate and CA certificate on their x509 object format.
        """
        csr_bytes = csr.encode("utf-8")
        csr_parsed = x509.load_pem_x509_csr(csr_bytes, default_backend())

        ca_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        ca_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Example CA"),
            ]
        )

        ca_subject = issuer = ca_name
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(issuer)
            .public_key(ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr_parsed.subject)
            .issuer_name(ca_subject)
            .public_key(csr_parsed.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )
        return {
            "certificate": cert,
            "ca_cert": ca_cert,
        }

    async def test_given_no_requirer_when_deploy_then_status_is_waiting(  # noqa: E501
        self, ops_test: OpsTest, charm_path: Path
    ):
        assert ops_test.model
        logger.info("Deploying charms for architecture: %s", ARCH)
        await ops_test.model.set_constraints({"arch": ARCH})
        await ops_test.model.deploy(
            entity_url=charm_path,
            application_name=APPLICATION_NAME,
            series="jammy",
            constraints={"arch": ARCH},
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    async def test_given_requirer_requests_certificate_creation_when_deploy_then_status_is_active(  # noqa: E501
        self, ops_test: OpsTest
    ):
        assert ops_test.model
        await deploy_tls_requirer_charm(ops_test)

        await ops_test.model.integrate(
            relation1=APPLICATION_NAME, relation2=TLS_REQUIRER_CHARM_NAME
        )

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_tls_requirer_is_deployed_with_3_units_and_related_when_provide_certificate_then_certificate_is_passed_correctly(  # noqa: E501
        self, ops_test: OpsTest
    ):
        assert ops_test.model
        await ops_test.model.applications[TLS_REQUIRER_CHARM_NAME].destroy_relation(
            local_relation="certificates",
            remote_relation=f"{APPLICATION_NAME}:certificates",
            block_until_done=True,
        )

        await ops_test.model.applications[APPLICATION_NAME].scale(3)

        relation = await ops_test.model.integrate(
            relation1=APPLICATION_NAME, relation2=TLS_REQUIRER_CHARM_NAME
        )
        assert isinstance(relation, Relation)

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_at_least_units=3,
        )
        await ops_test.model.wait_for_idle(
            apps=[TLS_REQUIRER_CHARM_NAME],
            status="active",
            timeout=1000,
        )

        await _wait_for_certificate_request(ops_test)

        get_outstanding_csrs_action_output = await run_get_outstanding_csrs_action(ops_test)

        get_outstanding_csrs_action_output = json.loads(
            get_outstanding_csrs_action_output["result"]
        )
        csr = get_outstanding_csrs_action_output[0]["csr"]

        csr_bytes = base64.b64encode(csr.encode("utf-8"))

        certs = self.get_certificate_and_ca_certificate_from_csr(csr)
        certificate_pem = certs["certificate"].public_bytes(serialization.Encoding.PEM)
        ca_certificate_pem = certs["ca_cert"].public_bytes(serialization.Encoding.PEM)
        certificate_bytes = base64.b64encode(certificate_pem)
        ca_certificate_bytes = base64.b64encode(ca_certificate_pem)
        ca_chain_pem = certificate_pem + ca_certificate_pem
        ca_chain_bytes = base64.b64encode(ca_chain_pem)

        await run_provide_certificate_action(
            ops_test,
            certificate=certificate_bytes.decode("utf-8"),
            ca_certificate=ca_certificate_bytes.decode("utf-8"),
            ca_chain=ca_chain_bytes.decode("utf-8"),
            csr=csr_bytes.decode("utf-8"),
        )

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, TLS_REQUIRER_CHARM_NAME],
            status="active",
            timeout=1000,
        )

        requirer_certificates = await wait_for_requirer_certificates(
            ops_test, unit_name=f"{TLS_REQUIRER_CHARM_NAME}/0"
        )

        assert requirer_certificates.get("certificate", "") == certificate_pem.decode(
            "utf-8"
        ).strip("\n")
        assert requirer_certificates.get("ca-certificate", "") == ca_certificate_pem.decode(
            "utf-8"
        ).strip("\n")

        await ops_test.model.applications[TLS_REQUIRER_CHARM_NAME].destroy_relation(
            local_relation="certificates",
            remote_relation=f"{APPLICATION_NAME}:certificates",
            block_until_done=True,
        )
        await ops_test.model.applications[APPLICATION_NAME].scale(1)

    async def test_given_certificate_transfer_requirer_related_when_config_changed_then_certificate_is_passed(  # noqa: E501
        self, ops_test: OpsTest
    ):
        assert ops_test.model

        await deploy_any_charm_as_cert_transfer_requirer(ops_test.model)
        relation = await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:trust_certificate", relation2=ANY_APP_NAME
        )
        assert isinstance(relation, Relation)

        await ops_test.model.wait_for_idle(
            apps=[ANY_APP_NAME],
            status="waiting",
            timeout=1000,
        )

        await ops_test.model.applications[APPLICATION_NAME].set_config(
            {
                "trusted-certificate-bundle": Path(TRUSTED_PEM).read_text(),
            }
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[ANY_APP_NAME],
            status="active",
            timeout=1000,
        )


async def run_get_certificate_action(ops_test: OpsTest, unit_name: str) -> dict:
    """Run `get-certificate` on the unit provided.

    Args:
        ops_test (OpsTest): OpsTest
        unit_name (str): Unit name

    Returns:
        dict: Action output
        str: Unit name
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[unit_name]
    action = await tls_requirer_unit.run_action(action_name="get-certificate")
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output


async def run_get_outstanding_csrs_action(ops_test: OpsTest) -> dict:
    """Run `get-outstanding-certificate-requests` on the `manual-tls-certificates/leader` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    manual_tls_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    action = await manual_tls_unit.run_action(
        action_name="get-outstanding-certificate-requests",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output


async def _wait_for_certificate_request(ops_test: OpsTest):
    """Wait for the certificate request to be created."""
    assert ops_test.model
    start_time = time.time()
    timeout = 60 * 5
    while time.time() < start_time + timeout:
        action_output = await run_get_outstanding_csrs_action(ops_test)
        action_output_result = json.loads(action_output["result"])
        csr = action_output_result[0].get("csr", None)
        if csr:
            return
        time.sleep(5)
    raise TimeoutError("Timeout waiting for certificate request.")


async def wait_for_requirer_certificates(ops_test: OpsTest, unit_name: str) -> Dict[str, str]:
    """Wait for the certificate to be provided to the `tls-requirer-requirer/0` unit.

    Returns the certificate output from the get-certificate action if successful.
    Otherwise, times out and raises a TimeoutError.
    """
    t0 = time.time()
    timeout = 300
    while time.time() - t0 < timeout:
        logger.info("Waiting for requirer certificates")
        time.sleep(5)
        action_output = await run_get_certificate_action(ops_test, unit_name=unit_name)
        try:
            certificates = json.loads(action_output.get("certificates", ""))[0]
        except json.JSONDecodeError:
            continue
        ca_certificate = certificates.get("ca-certificate", "")
        certificate = certificates.get("certificate", "")
        if not ca_certificate or not certificate:
            continue
        return certificates
    raise TimeoutError("Timed out waiting for certificate")


async def run_provide_certificate_action(
    ops_test: OpsTest,
    certificate: str,
    ca_certificate: str,
    ca_chain: str,
    csr: str,
) -> dict:
    """Run `provide-certificate` on the `manual-tls-certificates/leader` unit.

    Args:
        ops_test (OpsTest): OpsTest
        certificate (str): Certificate
        ca_certificate (str): CA Certificate
        ca_chain (str): CA Chain
        csr (str): CSR

    Returns:
        dict: Action output
    """
    assert ops_test.model
    manual_tls_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    action = await manual_tls_unit.run_action(
        action_name="provide-certificate",
        **{
            "certificate": certificate,
            "ca-certificate": ca_certificate,
            "ca-chain": ca_chain,
            "certificate-signing-request": csr,
        },
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output
