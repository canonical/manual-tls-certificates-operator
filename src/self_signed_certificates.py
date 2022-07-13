#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Methods used to generate self-signed certificates."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class SelfSignedCertificates:
    """Class that contains logic to generate and store self-signed certificates."""

    def __init__(self):
        """Initializes stored certificates to empty bytes."""
        self._private_key = bytes()
        self._ca_certificate = bytes()
        self._certificate = bytes()

    @property
    def private_key(self) -> bytes:
        """Returns the stored private key.

        Returns:
            bytes: Private key
        """
        return self._private_key

    @property
    def ca_certificate(self) -> bytes:
        """Returns the stored CA certificate.

        Returns:
            bytes: Stored CA certificate.
        """
        return self._ca_certificate

    @property
    def certificate(self) -> bytes:
        """Returns the stored certificate.

        Returns:
            bytes: Certificate
        """
        return self._certificate

    def generate(self, common_name: str) -> None:
        """Generates and stores certificates.

        Args:
            common_name (str): Certificate common name

        Returns:
            None
        """
        ca_private_key = self._generate_private_key()
        private_key = self._generate_private_key()
        ca_certificate = self._generate_ca(private_key=ca_private_key, subject=common_name)
        certificate_csr = self._generate_csr(
            private_key=private_key,
            subject=common_name,
        )
        certificate = self._generate_certificate(
            csr=certificate_csr,
            ca=ca_certificate,
            ca_key=ca_private_key,
        )

        self._private_key = private_key
        self._ca_certificate = ca_certificate
        self._certificate = certificate

    @staticmethod
    def _generate_certificate(
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

    @staticmethod
    def _generate_csr(private_key: bytes, subject: str, country: str = "US") -> bytes:
        """Generates a CSR.

        Args:
            private_key (bytes): Private key to use
            subject (str): Output the request's subject
            country (str): Country

        Returns:
            bytes: CSR (encoded in base64)
        """
        subject = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
            ]
        )
        signing_key = serialization.load_pem_private_key(private_key, password=None)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
        )
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
        return csr_bytes

    @staticmethod
    def _generate_ca(
        private_key: bytes,
        subject: str,
        validity: int = 365,
        country: str = "US",
    ) -> bytes:
        """Generates a CA certificate.

        Args:
            private_key (bytes): Private key to use
            subject (str): Certificate subject
            validity (int): Certificate validity (in days)
            country (str): Country name

        Returns:
            bytes: Certificate CA (encoded in base64)
        """
        private_key_object = serialization.load_pem_private_key(private_key, password=None)
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

    @staticmethod
    def _generate_private_key(key_size: int = 2048, public_exponent: int = 65537) -> bytes:
        """Generates private key.

        Args:
            key_size (int): Key size in bytes.
            public_exponent (int): Public exponent used to generate key.

        Returns:
            bytes: Private key (encoded in base64)
        """
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
        )
        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return key_bytes


class Certificate:
    """Class for methods associated with a given certificate."""

    def __init__(self, certificate_bytes: bytes):
        """Sets certificate_bytes based on provided input.

        Args:
            certificate_bytes (bytes): Certificate
        """
        self.certificate_bytes = certificate_bytes

    @property
    def is_valid(self) -> bool:
        """Returns whether certificate is valid.

        Returns:
            bool: True/False
        """
        try:
            x509.load_pem_x509_certificate(self.certificate_bytes)
            return True
        except ValueError:
            return False


class PrivateKey:
    """Class for methods associated with a given private key."""

    def __init__(self, private_key_bytes: bytes):
        """Sets private_key_bytes based on provided input.

        Args:
            private_key_bytes (bytes): Private key
        """
        self.private_key_bytes = private_key_bytes

    @property
    def is_valid(self) -> bool:
        """Returns whether a private key is valid.

        Returns:
            bool: True/False
        """
        try:
            serialization.load_pem_private_key(self.private_key_bytes, password=None)
            return True
        except ValueError:
            return False
