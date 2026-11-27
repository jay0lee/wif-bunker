"""Tests for wif_bunker.config (BunkerConfig & WorkloadConfig)."""

from __future__ import annotations

import stat
import sys

import pytest

from wif_bunker.config import SIGNER_TYPES, SUPPORTED_OIDC_ALGORITHMS, BunkerConfig, WorkloadConfig


def test_workload_config_defaults():
    config = WorkloadConfig()
    assert config.pool_id == "bunker-wif-pool"
    assert config.sa_name == "bunker-wif-sa"
    assert config.provider_id.startswith("bunker-oidc-prov-")
    assert config.issuer_uri == f"https://wif-bunker.internal/{config.provider_id}"
    assert config.subject == config.workload_cn
    assert config.yubikey_slot == "9c"
    assert config.windows_store_location == "current_user"


def test_workload_config_subject_setter():
    config = WorkloadConfig()
    config.subject = "custom-host-01"
    assert config.workload_cn == "custom-host-01"
    assert config.subject == "custom-host-01"


def test_constants():
    assert "ES256" in SUPPORTED_OIDC_ALGORITHMS
    assert "RS256" in SUPPORTED_OIDC_ALGORITHMS
    assert "linux-tpm" in SIGNER_TYPES
    assert "yubikey" in SIGNER_TYPES
    assert "software" in SIGNER_TYPES


def test_bunker_config_roundtrip(tmp_path):
    cfg = BunkerConfig(
        project_id="my-proj",
        project_number="999",
        pool_id="my-pool",
        provider_id="bunker-oidc-prov-1",
        audience="//iam.googleapis.com/projects/999/locations/global/workloadIdentityPools/my-pool/providers/bunker-oidc-prov-1",
        issuer_uri="https://wif-bunker.internal/bunker-oidc-prov-1",
        subject="my-sub",
        service_account_email="sa@my-proj.iam.gserviceaccount.com",
        signer={"type": "linux-tpm", "handle": "0x81000001"},
        public_jwk={"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "k1", "use": "sig"},
    )
    out = tmp_path / "bunker.json"
    cfg.save(out)
    if sys.platform != "win32":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600

    loaded = BunkerConfig.load(out)
    assert loaded == cfg


def test_bunker_config_load_errors(tmp_path):
    with pytest.raises(FileNotFoundError):
        BunkerConfig.load(tmp_path / "missing.json")

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        BunkerConfig.load(bad_json)

    not_obj = tmp_path / "list.json"
    not_obj.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="expected JSON object"):
        BunkerConfig.load(not_obj)

    missing_fields = tmp_path / "incomplete.json"
    missing_fields.write_text('{"project_id": "p"}', encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field"):
        BunkerConfig.load(missing_fields)
