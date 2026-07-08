# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import datetime
import json
import logging
import platform
import time
from pathlib import Path

import jubilant
import pytest
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

APPLICATION_NAME = "manual-tls-certificates"
ARCH = "arm64" if platform.machine() == "aarch64" else "amd64"
CERT_TRANSFER_REQUIRER_V0_PATH = "./tests/integration/cert_transfer_requirer_v0.py"
CERT_TRANSFER_REQUIRER_V0_APP_NAME = "any-cert-transfer-requirer-v0"
CERT_TRANSFER_V0_LIB_URL = "https://raw.githubusercontent.com/canonical/certificate-transfer-interface/refs/heads/main/lib/charms/certificate_transfer_interface/v0/certificate_transfer.py"  # noqa: E501
CERT_TRANSFER_REQUIRER_V1_PATH = "./tests/integration/cert_transfer_requirer_v1.py"
CERT_TRANSFER_REQUIRER_V1_APP_NAME = "any-cert-transfer-requirer-v1"
REQUIRER_CHARM_REVISION_ARM = 103
REQUIRER_CHARM_REVISION_AMD = 104
TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"
TRUSTED_PEM = "./tests/integration/trusted_certs.pem"


def deploy_tls_requirer_charm(juju: jubilant.Juju) -> None:
    """Deploy the tls-certificates-requirer charm."""
    juju.deploy(
        TLS_REQUIRER_CHARM_NAME,
        revision=REQUIRER_CHARM_REVISION_ARM if ARCH == "arm64" else REQUIRER_CHARM_REVISION_AMD,
        channel="stable",
        constraints={"arch": ARCH},
    )


def deploy_any_charm_as_cert_transfer_requirer(juju: jubilant.Juju) -> None:
    """Deploy AnyCharm as a certificate_transfer requirer."""
    any_charm_src_overwrite = {
        "any_charm.py": Path(CERT_TRANSFER_REQUIRER_V1_PATH).read_text(),
    }
    juju.deploy(
        "any-charm",
        CERT_TRANSFER_REQUIRER_V1_APP_NAME,
        channel="beta",
        config={
            "src-overwrite": json.dumps(any_charm_src_overwrite),
            "python-packages": "\n".join(
                (
                    "ops==2.17.1",
                    "pytest-interface-tester",
                    "charmlibs-interfaces-certificate-transfer>=1.0.0",
                )
            ),
        },
    )


def deploy_any_charm_as_cert_transfer_requirer_v0(juju: jubilant.Juju) -> None:
    """Deploy AnyCharm as a certificate_transfer requirer (v0)."""
    cert_transfer_lib = requests.get(CERT_TRANSFER_V0_LIB_URL, timeout=10).text
    any_charm_src_overwrite = {
        "certificate_transfer.py": cert_transfer_lib,
        "any_charm.py": Path(CERT_TRANSFER_REQUIRER_V0_PATH).read_text(),
    }
    juju.deploy(
        "any-charm",
        CERT_TRANSFER_REQUIRER_V0_APP_NAME,
        channel="beta",
        config={
            "src-overwrite": json.dumps(any_charm_src_overwrite),
            "python-packages": "ops==2.17.1\npytest-interface-tester\njsonschema",
        },
    )


class TestManualTLSCertificatesOperator:
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

    @pytest.mark.juju_setup
    def test_given_no_requirer_when_deploy_then_status_is_waiting(  # noqa: E501
        self, juju: jubilant.Juju, charm: Path
    ):
        logger.info("Deploying charms for architecture: %s", ARCH)
        juju.model_constraints({"arch": ARCH})
        juju.deploy(
            charm,
            APPLICATION_NAME,
            base="ubuntu@24.04",
            constraints={"arch": ARCH},
        )

        juju.wait(
            lambda status: jubilant.all_active(status, APPLICATION_NAME),
            timeout=1000,
        )

    @pytest.mark.juju_setup
    def test_given_requirer_requests_certificate_creation_when_deploy_then_status_is_active(  # noqa: E501
        self, juju: jubilant.Juju
    ):
        deploy_tls_requirer_charm(juju)

        juju.integrate(APPLICATION_NAME, TLS_REQUIRER_CHARM_NAME)

        juju.wait(
            lambda status: jubilant.all_active(status, APPLICATION_NAME),
            timeout=1000,
        )

    def test_given_tls_requirer_is_deployed_with_3_units_and_related_when_provide_certificate_then_certificate_is_passed_correctly(  # noqa: E501
        self, juju: jubilant.Juju
    ):
        juju.remove_relation(
            f"{TLS_REQUIRER_CHARM_NAME}:certificates",
            f"{APPLICATION_NAME}:certificates",
        )
        # Wait for the dying relation to be fully removed before re-integrating.
        # This mirrors the block_until_done=True behaviour of the old API.
        juju.wait(
            lambda status: jubilant.all_active(status, APPLICATION_NAME),
            timeout=300,
        )

        juju.add_unit(APPLICATION_NAME, num_units=2)

        juju.integrate(APPLICATION_NAME, TLS_REQUIRER_CHARM_NAME)

        juju.wait(
            lambda status: (
                APPLICATION_NAME in status.apps
                and len(status.apps[APPLICATION_NAME].units) >= 3
                and jubilant.all_active(status, APPLICATION_NAME)
            ),
            timeout=1000,
        )
        juju.wait(
            lambda status: jubilant.all_active(status, TLS_REQUIRER_CHARM_NAME),
            timeout=1000,
        )

        _wait_for_certificate_request(juju)

        task = run_get_outstanding_csrs_action(juju)
        outstanding_csrs = json.loads(task.results.get("result", "[]"))
        csr = outstanding_csrs[0]["csr"]

        csr_bytes = base64.b64encode(csr.encode("utf-8"))

        certs = self.get_certificate_and_ca_certificate_from_csr(csr)
        certificate_pem = certs["certificate"].public_bytes(serialization.Encoding.PEM)
        ca_certificate_pem = certs["ca_cert"].public_bytes(serialization.Encoding.PEM)
        certificate_bytes = base64.b64encode(certificate_pem)
        ca_certificate_bytes = base64.b64encode(ca_certificate_pem)
        ca_chain_pem = certificate_pem + ca_certificate_pem
        ca_chain_bytes = base64.b64encode(ca_chain_pem)

        run_provide_certificate_action(
            juju,
            certificate=certificate_bytes.decode("utf-8"),
            ca_certificate=ca_certificate_bytes.decode("utf-8"),
            ca_chain=ca_chain_bytes.decode("utf-8"),
            csr=csr_bytes.decode("utf-8"),
        )

        juju.wait(
            lambda status: jubilant.all_active(status, APPLICATION_NAME, TLS_REQUIRER_CHARM_NAME),
            timeout=1000,
        )

        requirer_certificates = wait_for_requirer_certificates(
            juju, unit_name=f"{TLS_REQUIRER_CHARM_NAME}/0"
        )

        assert requirer_certificates.get("certificate", "") == certificate_pem.decode(
            "utf-8"
        ).strip("\n")
        assert requirer_certificates.get("ca-certificate", "") == ca_certificate_pem.decode(
            "utf-8"
        ).strip("\n")

        juju.remove_relation(
            f"{TLS_REQUIRER_CHARM_NAME}:certificates",
            f"{APPLICATION_NAME}:certificates",
        )
        juju.wait(
            lambda status: jubilant.all_active(status, APPLICATION_NAME),
            timeout=300,
        )
        juju.remove_unit(APPLICATION_NAME, num_units=2)
        juju.wait(
            lambda status: (
                APPLICATION_NAME in status.apps
                and len(status.apps[APPLICATION_NAME].units) == 1
                and jubilant.all_active(status, APPLICATION_NAME)
            ),
            timeout=1000,
        )

    def test_given_certificate_transfer_requirer_v1_related_when_config_changed_then_certificate_is_passed(  # noqa: E501
        self, juju: jubilant.Juju
    ):
        deploy_any_charm_as_cert_transfer_requirer(juju)
        juju.integrate(
            f"{APPLICATION_NAME}:trust_certificate",
            f"{CERT_TRANSFER_REQUIRER_V1_APP_NAME}:require-certificate-transfer",
        )

        juju.wait(
            lambda status: jubilant.all_waiting(status, CERT_TRANSFER_REQUIRER_V1_APP_NAME),
            timeout=1000,
        )

        juju.config(
            APPLICATION_NAME, {"trusted-certificate-bundle": Path(TRUSTED_PEM).read_text()}
        )

        juju.wait(
            lambda status: jubilant.all_active(status, APPLICATION_NAME),
            timeout=1000,
        )
        juju.wait(
            lambda status: jubilant.all_active(status, CERT_TRANSFER_REQUIRER_V1_APP_NAME),
            timeout=1000,
        )

    def test_given_certificate_transfer_requirer_v0_related_when_config_changed_then_certificate_is_passed(  # noqa: E501
        self, juju: jubilant.Juju
    ):
        deploy_any_charm_as_cert_transfer_requirer_v0(juju)
        juju.wait(
            lambda status: jubilant.all_waiting(status, CERT_TRANSFER_REQUIRER_V0_APP_NAME),
            timeout=1000,
        )

        juju.integrate(
            f"{APPLICATION_NAME}:trust_certificate",
            f"{CERT_TRANSFER_REQUIRER_V0_APP_NAME}:require-certificate-transfer",
        )

        juju.wait(
            lambda status: jubilant.all_active(status, APPLICATION_NAME),
            timeout=1000,
        )
        juju.wait(
            lambda status: jubilant.all_active(status, CERT_TRANSFER_REQUIRER_V0_APP_NAME),
            timeout=1000,
        )


def run_get_certificate_action(juju: jubilant.Juju, unit_name: str) -> jubilant.Task:
    """Run `get-certificate` on the unit provided.

    Args:
        juju: Jubilant Juju instance.
        unit_name: Unit name.

    Returns:
        Task containing the action result.
    """
    return juju.run(unit_name, "get-certificate", wait=240)


def run_get_outstanding_csrs_action(juju: jubilant.Juju) -> jubilant.Task:
    """Run `get-outstanding-certificate-requests` on the leader unit.

    Args:
        juju: Jubilant Juju instance.

    Returns:
        Task containing the action result.
    """
    return juju.run(
        f"{APPLICATION_NAME}/leader",
        "get-outstanding-certificate-requests",
        wait=240,
    )


def _wait_for_certificate_request(juju: jubilant.Juju) -> None:
    """Wait for the certificate request to be created."""
    start_time = time.time()
    timeout = 60 * 5
    while time.time() < start_time + timeout:
        task = run_get_outstanding_csrs_action(juju)
        result = json.loads(task.results.get("result", "[]"))
        if result and result[0].get("csr"):
            return
        time.sleep(5)
    raise TimeoutError("Timeout waiting for certificate request.")


def wait_for_requirer_certificates(juju: jubilant.Juju, unit_name: str) -> dict[str, str]:
    """Wait for the certificate to be provided to the given unit.

    Returns the certificate output from the get-certificate action if successful.
    Otherwise, times out and raises a TimeoutError.
    """
    t0 = time.time()
    timeout = 300
    while time.time() - t0 < timeout:
        logger.info("Waiting for requirer certificates")
        time.sleep(5)
        task = run_get_certificate_action(juju, unit_name=unit_name)
        try:
            certs_raw = task.results.get("certificates", "")
            if isinstance(certs_raw, list):
                certificates = certs_raw[0]
            else:
                certificates = json.loads(certs_raw)[0]
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            continue
        ca_certificate = certificates.get("ca-certificate", "")
        certificate = certificates.get("certificate", "")
        if not ca_certificate or not certificate:
            continue
        return certificates
    raise TimeoutError("Timed out waiting for certificate")


def run_provide_certificate_action(
    juju: jubilant.Juju,
    certificate: str,
    ca_certificate: str,
    ca_chain: str,
    csr: str,
) -> jubilant.Task:
    """Run `provide-certificate` on the leader unit.

    Args:
        juju: Jubilant Juju instance.
        certificate: Certificate (base64-encoded).
        ca_certificate: CA Certificate (base64-encoded).
        ca_chain: CA Chain (base64-encoded).
        csr: CSR (base64-encoded).

    Returns:
        Task containing the action result.
    """
    return juju.run(
        f"{APPLICATION_NAME}/leader",
        "provide-certificate",
        {
            "certificate": certificate,
            "ca-certificate": ca_certificate,
            "ca-chain": ca_chain,
            "certificate-signing-request": csr,
        },
        wait=240,
    )
