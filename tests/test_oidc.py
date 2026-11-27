"""Tests for wif_bunker.oidc (JWKS, OIDC JWT signing, STS/IAM exchange, ADC configs)."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

from wif_bunker.oidc import (
    _parse_rfc3339_epoch,
    build_agent_adc_config,
    build_executable_adc_config,
    build_jwks_from_signer,
    exchange_jwt_for_sts_token,
    format_executable_response,
    generate_sa_access_token,
    mint_google_access_token,
    mint_oidc_jwt,
    verify_project_access,
)
from wif_bunker.signers import load_signer


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


class TestJwksAndJwtSigning:
    def test_es256_jwks_and_jwt_signature_verifies(self, sample_software_pem_file, sample_ec_key):
        signer = load_signer({"type": "software", "key_file": str(sample_software_pem_file)})
        jwks, jwk = build_jwks_from_signer(signer)

        assert jwks == {"keys": [jwk]}
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["alg"] == "ES256"
        assert jwk["use"] == "sig"
        assert jwk["kid"]

        jwt_str, exp = mint_oidc_jwt(
            signer,
            issuer_uri="https://wif-bunker.internal/prov-1",
            audience="//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/prov-1",
            subject="my-host",
            lifetime_seconds=120,
            kid=jwk["kid"],
        )

        hdr_b64, pay_b64, sig_b64 = jwt_str.split(".")
        header = json.loads(_b64url_decode(hdr_b64))
        claims = json.loads(_b64url_decode(pay_b64))
        sig_raw = _b64url_decode(sig_b64)

        assert header == {"alg": "ES256", "typ": "JWT", "kid": jwk["kid"]}
        assert claims["iss"] == "https://wif-bunker.internal/prov-1"
        assert claims["sub"] == "my-host"
        assert claims["aud"].startswith("https://iam.googleapis.com/")
        assert claims["exp"] == exp
        assert claims["exp"] - claims["iat"] == 120

        # Cryptographically verify IEEE P1363 R||S signature using the public key
        assert len(sig_raw) == 64
        r = int.from_bytes(sig_raw[:32], "big")
        s = int.from_bytes(sig_raw[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)
        signing_input = f"{hdr_b64}.{pay_b64}".encode("ascii")
        sample_ec_key.public_key().verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))

    def test_rs256_jwks_and_jwt_signature_verifies(self, tmp_path, sample_rsa_key):
        pem_path = tmp_path / "rsa.pem"
        pem_path.write_bytes(
            sample_rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        signer = load_signer({"type": "software", "key_file": str(pem_path)})
        jwks, jwk = build_jwks_from_signer(signer)
        assert jwk["alg"] == "RS256"
        assert jwk["kty"] == "RSA"
        assert jwks["keys"][0]["kid"] == jwk["kid"]

        jwt_str, _exp = mint_oidc_jwt(
            signer,
            issuer_uri="https://wif-bunker.internal/prov-rsa",
            audience="//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/r",
            subject="rsa-host",
            kid=jwk["kid"],
        )
        hdr_b64, pay_b64, sig_b64 = jwt_str.split(".")
        signing_input = f"{hdr_b64}.{pay_b64}".encode("ascii")
        sig = _b64url_decode(sig_b64)
        sample_rsa_key.public_key().verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())

    def test_unsupported_algorithm_raises(self):
        fake_signer = MagicMock()
        fake_signer.algorithm = "ES384"
        fake_signer.public_jwk = {"kty": "EC", "crv": "P-384"}
        with pytest.raises(ValueError, match="ES256, RS256"):
            build_jwks_from_signer(fake_signer)
        with pytest.raises(ValueError, match="Unsupported OIDC JWT algorithm"):
            mint_oidc_jwt(
                fake_signer,
                issuer_uri="https://wif-bunker.internal/p",
                audience="//iam.googleapis.com/p",
                subject="sub",
            )

    def test_missing_kid_raises(self):
        fake_signer = MagicMock()
        fake_signer.algorithm = "ES256"
        fake_signer.public_jwk = {"kty": "EC", "crv": "P-256"}
        fake_signer.key_id = None
        fake_signer.thumbprint = None
        with pytest.raises(ValueError, match="did not provide a key_id"):
            build_jwks_from_signer(fake_signer)


class TestTokenExchanges:
    def test_exchange_jwt_for_sts_token(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"access_token": "sts.tok", "expires_in": 3600}
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp

        token, expiry = exchange_jwt_for_sts_token(
            "a.b.c",
            audience="//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
            session=mock_session,
        )
        assert token == "sts.tok"
        assert expiry > 0
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["subject_token"] == "a.b.c"
        assert payload["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt"

    def test_generate_sa_access_token(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "accessToken": "ya29.sa.token",
            "expireTime": "2030-01-01T00:00:00Z",
        }
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp

        token, expiry = generate_sa_access_token(
            "sts.tok",
            sa_email="sa@proj.iam.gserviceaccount.com",
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
            session=mock_session,
        )
        assert token == "ya29.sa.token"
        assert expiry == 1893456000
        assert "sa@proj.iam.gserviceaccount.com:generateAccessToken" in mock_session.post.call_args.args[0]

    def test_generate_sa_access_token_without_expire_time_and_naive_rfc3339(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"accessToken": "ya29.fallback"}
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp

        token, expiry = generate_sa_access_token(
            "sts.tok",
            sa_email="sa@proj.iam.gserviceaccount.com",
            lifetime_seconds=1800,
            session=mock_session,
        )
        assert token == "ya29.fallback"
        assert expiry > 0
        assert _parse_rfc3339_epoch("2030-01-01T00:00:00") == 1893456000

    def test_verify_project_access(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"name": "My Proj"}
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp

        data = verify_project_access("ya29.tok", "my-proj", session=mock_session)
        assert data == {"name": "My Proj"}
        assert "my-proj" in mock_session.get.call_args.args[0]

    def test_mint_google_access_token_with_sa(self, sample_bunker_config):
        signer = load_signer(sample_bunker_config.signer)
        with (
            patch("wif_bunker.oidc.exchange_jwt_for_sts_token", return_value=("sts.tok", 1000)) as mock_sts,
            patch("wif_bunker.oidc.generate_sa_access_token", return_value=("sa.tok", 2000)) as mock_sa,
        ):
            token, expiry = mint_google_access_token(sample_bunker_config, signer)

        assert token == "sa.tok"
        assert expiry == 2000
        mock_sts.assert_called_once()
        mock_sa.assert_called_once()

    def test_mint_google_access_token_without_sa(self, sample_bunker_config):
        sample_bunker_config.service_account_email = None
        signer = load_signer(sample_bunker_config.signer)
        with (
            patch("wif_bunker.oidc.exchange_jwt_for_sts_token", return_value=("sts.direct", 3000)) as mock_sts,
            patch("wif_bunker.oidc.generate_sa_access_token") as mock_sa,
        ):
            token, expiry = mint_google_access_token(sample_bunker_config, signer)

        assert token == "sts.direct"
        assert expiry == 3000
        mock_sts.assert_called_once()
        mock_sa.assert_not_called()


class TestAdcConfigBuilders:
    def test_build_agent_adc_config(self, sample_bunker_config, tmp_path):
        secret_file = tmp_path / ".secret"
        cfg = build_agent_adc_config(sample_bunker_config, port=43210, secret_file=secret_file)
        assert cfg["type"] == "external_account"
        assert cfg["token_url"] == "http://127.0.0.1:43210/v1/token"
        assert cfg["credential_source"] == {"file": str(secret_file)}
        assert "service_account_impersonation_url" not in cfg
        assert "quota_project_id" not in cfg

    def test_build_executable_adc_config_with_sa_and_output_file(self, sample_bunker_config, tmp_path):
        bunker_path = tmp_path / "bunker.json"
        cache_path = tmp_path / "jwt_cache.json"
        cfg = build_executable_adc_config(
            sample_bunker_config,
            bunker_config_path=bunker_path,
            command_path="/usr/local/bin/wif-bunker",
            output_file=cache_path,
            jwt_lifetime_seconds=1800,
        )
        assert cfg["type"] == "external_account"
        assert cfg["token_url"] == "https://sts.googleapis.com/v1/token"
        assert "service_account_impersonation_url" in cfg
        assert "quota_project_id" not in cfg
        exe = cfg["credential_source"]["executable"]
        assert "sign-jwt" in exe["command"]
        assert "--lifetime 1800" in exe["command"]
        assert exe["output_file"] == str(cache_path.resolve())

    def test_build_executable_adc_config_python_module_command(self, sample_bunker_config, tmp_path):
        import shlex

        bunker_path = tmp_path / "bunker.json"
        cfg = build_executable_adc_config(
            sample_bunker_config,
            bunker_config_path=bunker_path,
            command_path='"/opt/python/bin/python3" -m wif_bunker',
        )
        tokens = shlex.split(cfg["credential_source"]["executable"]["command"])
        assert tokens[:4] == ["/opt/python/bin/python3", "-m", "wif_bunker", "sign-jwt"]
        assert tokens[4:] == ["--config", bunker_path.as_posix()]

    def test_format_executable_response(self):
        resp = format_executable_response("hdr.pay.sig", 1900000000)
        assert resp == {
            "version": 1,
            "success": True,
            "token_type": "urn:ietf:params:oauth:token-type:jwt",
            "id_token": "hdr.pay.sig",
            "expiration_time": 1900000000,
        }
