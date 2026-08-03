import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from wif_bunker.config import WorkloadConfig


@pytest.fixture
def sample_config():
    config = WorkloadConfig()
    config.project_id = "test-proj-123"
    return config


@pytest.fixture
def sample_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def sample_csr_pem(sample_ec_key):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test-workload"),
                ]
            )
        )
        .sign(sample_ec_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture
def sample_rsa_config():
    config = WorkloadConfig()
    config.project_id = "test-proj-123"
    config.key_algorithm = "rsa2048"
    return config


@pytest.fixture
def sample_rsa_csr_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test-workload-rsa"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture
def sample_es384_config():
    config = WorkloadConfig()
    config.project_id = "test-proj-123"
    config.key_algorithm = "es384"
    return config


@pytest.fixture
def sample_es384_csr_pem():
    key = ec.generate_private_key(ec.SECP384R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test-workload-es384"),
                ]
            )
        )
        .sign(key, hashes.SHA384())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
