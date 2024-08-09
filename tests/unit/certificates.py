from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_private_key() -> str:
    """Generate a private key with the RSA algorithm.

    Returns:
        str: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_bytes.decode().strip()


def generate_csr(private_key: str, common_name: str) -> str:
    """Generate a CSR using private key and subject.

    Args:
        private_key (str): Private key
        common_name (str): Common name

    Returns:
        CertificateSigningRequest: str
    """
    signing_key = serialization.load_pem_private_key(private_key.encode(), password=None)
    subject_name = [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name(subject_name))
    _sans: List[x509.GeneralName] = []
    if _sans:
        csr = csr.add_extension(x509.SubjectAlternativeName(set(_sans)), critical=False)
    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[reportArgumentType]
    return signed_certificate.public_bytes(serialization.Encoding.PEM).decode().strip()
