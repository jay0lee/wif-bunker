import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wif_bunker import WorkloadConfig


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
