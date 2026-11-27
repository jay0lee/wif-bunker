"""Shared pytest fixtures for WIF Bunker v2 tests."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from wif_bunker.config import BunkerConfig, WorkloadConfig


@pytest.fixture
def sample_config():
    config = WorkloadConfig()
    config.project_id = "test-proj-123"
    return config


@pytest.fixture
def sample_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def sample_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def sample_software_pem_file(tmp_path, sample_ec_key):
    pem_path = tmp_path / "test_ec_key.pem"
    pem_path.write_bytes(
        sample_ec_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return pem_path


@pytest.fixture
def sample_bunker_config(sample_software_pem_file):
    from wif_bunker.oidc import build_jwks_from_signer
    from wif_bunker.signers import load_signer

    signer_cfg = {"type": "software", "key_file": str(sample_software_pem_file)}
    signer = load_signer(signer_cfg)
    _jwks, jwk_entry = build_jwks_from_signer(signer)
    return BunkerConfig(
        project_id="test-proj-123",
        project_number="123456789012",
        pool_id="bunker-wif-pool",
        provider_id="bunker-oidc-prov-1234",
        audience="//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/bunker-wif-pool/providers/bunker-oidc-prov-1234",
        issuer_uri="https://wif-bunker.internal/bunker-oidc-prov-1234",
        subject="bunker-workload-1234",
        service_account_email="bunker-wif-sa@test-proj-123.iam.gserviceaccount.com",
        signer=signer_cfg,
        public_jwk=jwk_entry,
    )
