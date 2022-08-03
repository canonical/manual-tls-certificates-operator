#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Methods used to generate self-signed certificates."""

import datetime
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key(
    password: Optional[bytes] = None,
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> bytes:
    """Generates a private key.

    Args:
        password (bytes): Password for decrypting the private key
        key_size (int): Key size in bytes
        public_exponent: Public exponent.

    Returns:
        bytes: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption(),
    )
    return key_bytes


def generate_certificate(
    csr: bytes,
    ca: bytes,
    ca_key: bytes,
    validity: int = 365,
    alt_names: list = None,
) -> bytes:
    """Generates a certificate based on CSR.

    Args:
        csr: CSR Bytes
        ca: Set the CA certificate, must be PEM format
        ca_key: The CA key, must be PEM format; if not in CAfile
        validity: Validity
        alt_names: Alternative names (optional)

    Returns:
        bytes: Certificate
    """
    csr_object = x509.load_pem_x509_csr(csr)
    subject = csr_object.subject
    issuer = x509.load_pem_x509_certificate(ca).issuer
    private_key = serialization.load_pem_private_key(ca_key, password=None)

    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(csr_object.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity))
    )

    if alt_names:
        names = [x509.DNSName(n) for n in alt_names]
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName(names),
            critical=False,
        )
    certificate_builder._version = x509.Version.v1
    cert = certificate_builder.sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_ca(
    private_key: bytes,
    subject: str,
    private_key_password: Optional[bytes] = None,
    validity: int = 365,
    country: str = "US",
) -> bytes:
    """Generates a CA certificate.

    Args:
        private_key (bytes): Private key to use
        subject (str): Certificate subject
        private_key_password (bytes): Private key password
        validity (int): Certificate validity (in days)
        country (str): Country name

    Returns:
        bytes: Certificate CA (encoded in base64)
    """
    private_key_object = serialization.load_pem_private_key(
        private_key, password=private_key_password
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
        ]
    )
    subject_identifier_object = x509.SubjectKeyIdentifier.from_public_key(
        private_key_object.public_key()  # type: ignore[arg-type]
    )
    subject_identifier = key_identifier = subject_identifier_object.public_bytes()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key_object.public_key())  # type: ignore[arg-type]
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity))
        .add_extension(x509.SubjectKeyIdentifier(digest=subject_identifier), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key_object, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_csr(
    private_key: bytes,
    subject: str,
    private_key_password: Optional[bytes] = None,
    sans: Optional[List[str]] = None,
    additional_critical_extensions: Optional[List] = None,
) -> bytes:
    """Generates a CSR using private key and subject.

    Args:
        private_key (bytes): Private key
        private_key_password (bytes): Private key password
        subject (str): CSR Subject.
        sans (list): List of subject alternative names
        additional_critical_extensions (list): List if critical additional extension objects.
            Object must be a x509 ExtensionType.

    Returns:
        bytes: CSR
    """
    signing_key = serialization.load_pem_private_key(private_key, password=private_key_password)
    csr = x509.CertificateSigningRequestBuilder(
        subject_name=x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
            ]
        )
    )
    if sans:
        csr = csr.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]), critical=False
        )
    if additional_critical_extensions:
        for extension in additional_critical_extensions:
            csr = csr.add_extension(extension, critical=True)
    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
    return signed_certificate.public_bytes(serialization.Encoding.PEM)


def certificate_is_valid(certificate: bytes) -> bool:
    """Returns whether a certificate is valid.

    Args:
        certificate:

    Returns:
        bool: True/False
    """
    try:
        x509.load_pem_x509_certificate(certificate)
        return True
    except ValueError:
        return False


def private_key_is_valid(private_key: bytes) -> bool:
    """Returns whether a private key is valid.

    Returns:
        bool: True/False
    """
    try:
        serialization.load_pem_private_key(private_key, password=None)
        return True
    except ValueError:
        return False
