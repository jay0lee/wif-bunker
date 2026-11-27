"""OIDC WIF JWT minting, GCP STS token exchange, SA impersonation, and ADC config builders."""

from __future__ import annotations

import base64
import datetime
import json
import logging
import time
from pathlib import Path
from typing import Any

import requests

from wif_bunker.config import (
    DEFAULT_OIDC_JWT_LIFETIME_SECONDS,
    SUPPORTED_OIDC_ALGORITHMS,
    BunkerConfig,
)

logger = logging.getLogger(__name__)

_STS_TOKEN_URL = "https://sts.googleapis.com/v1/token"
_IAM_CREDENTIALS_URL_TEMPLATE = (
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken"
)
_DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def _b64url(data: bytes) -> str:
    """Unpadded base64url encoding per RFC 7515."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_jwks_from_signer(signer: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract a GCP-compatible RFC 7517 JWKS dict from a hardware signer.

    Returns:
        Tuple of ``(jwks_dict, jwk_entry)`` where ``jwks_dict`` is
        ``{"keys": [jwk_entry]}`` ready to upload as ``oidc.jwksJson``.

    Raises:
        ValueError: If the signer's algorithm is not supported by GCP OIDC WIF.
    """
    alg = getattr(signer, "algorithm", None)
    if alg not in SUPPORTED_OIDC_ALGORITHMS:
        raise ValueError(
            f"Signer algorithm '{alg}' is not supported by GCP OIDC Workload Identity Federation. "
            f"Supported algorithms: {', '.join(SUPPORTED_OIDC_ALGORITHMS)}."
        )

    pub_jwk = dict(signer.public_jwk)
    kid = getattr(signer, "key_id", None) or getattr(signer, "thumbprint", None)
    if not kid:
        raise ValueError("Signer did not provide a key_id or thumbprint for JWK 'kid'.")

    jwk_entry: dict[str, Any] = {
        **pub_jwk,
        "alg": alg,
        "use": "sig",
        "kid": str(kid),
    }
    return {"keys": [jwk_entry]}, jwk_entry


def mint_oidc_jwt(
    signer: Any,
    *,
    issuer_uri: str,
    audience: str,
    subject: str,
    lifetime_seconds: int = DEFAULT_OIDC_JWT_LIFETIME_SECONDS,
    kid: str | None = None,
) -> tuple[str, int]:
    """Create and sign a self-signed OIDC JWT using *signer*.

    The signer's ``sign(data: bytes) -> bytes`` method must return an RFC 7515
    JWS signature (raw ``R || S`` for ES256, PKCS#1 v1.5 for RS256), which is
    the exact contract implemented by all ``dpop-signers`` packages.

    Args:
        signer: Hardware/software signer implementing ``algorithm``, ``key_id``,
            and ``sign(bytes) -> bytes``.
        issuer_uri: OIDC issuer URL (must match provider's ``issuerUri``).
        audience: Target audience (typically ``https://iam.googleapis.com/...``
            or ``//iam.googleapis.com/...`` matching ``allowedAudiences``).
        subject: OIDC ``sub`` claim mapped to ``google.subject``.
        lifetime_seconds: JWT validity window in seconds (default: 60s).
        kid: Optional key ID override for JWT header.

    Returns:
        Tuple of ``(compact_jwt_string, expiry_unix_timestamp)``.
    """
    alg = getattr(signer, "algorithm", None)
    if alg not in SUPPORTED_OIDC_ALGORITHMS:
        raise ValueError(f"Unsupported OIDC JWT algorithm '{alg}'. Supported: {', '.join(SUPPORTED_OIDC_ALGORITHMS)}.")

    resolved_kid = kid or getattr(signer, "key_id", None) or getattr(signer, "thumbprint", None)
    now = int(time.time())
    exp = now + int(lifetime_seconds)

    header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if resolved_kid:
        header["kid"] = str(resolved_kid)

    # Normalize audience to match GCP OIDC provider default allowed audience:
    # GCP accepts https://iam.googleapis.com/... or //iam.googleapis.com/...
    aud = audience
    if aud.startswith("//"):
        aud = f"https:{aud}"

    payload: dict[str, Any] = {
        "iss": issuer_uri,
        "sub": subject,
        "aud": aud,
        "iat": now,
        "exp": exp,
    }

    header_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    sig_bytes = signer.sign(signing_input)
    sig_b64 = _b64url(sig_bytes)
    return f"{header_b64}.{payload_b64}.{sig_b64}", exp


def exchange_jwt_for_sts_token(
    jwt_str: str,
    *,
    audience: str,
    scopes: list[str] | None = None,
    session: requests.Session | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Exchange a signed OIDC JWT for a Google STS federated access token.

    Uses plain HTTPS against ``https://sts.googleapis.com/v1/token`` (no mTLS).

    Returns:
        Tuple of ``(sts_access_token, expiry_unix_timestamp)``.
    """
    req_scopes = scopes or _DEFAULT_SCOPES
    sts_audience = audience if audience.startswith("//") else audience.replace("https://", "//", 1)
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "audience": sts_audience,
        "scope": " ".join(req_scopes),
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": jwt_str,
    }
    client = session or requests
    resp = client.post(_STS_TOKEN_URL, json=body, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    access_token = data["access_token"]
    expires_in = int(data.get("expires_in", 3600))
    return access_token, int(time.time()) + expires_in


def _parse_rfc3339_epoch(expire_time: str) -> int:
    """Parse an RFC 3339 timestamp string (e.g. '2026-11-26T12:00:00Z') to Unix epoch."""
    normalized = expire_time.replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.UTC)
    return int(dt.timestamp())


def generate_sa_access_token(
    sts_token: str,
    *,
    sa_email: str,
    scopes: list[str] | None = None,
    lifetime_seconds: int = 3600,
    session: requests.Session | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Impersonate *sa_email* via ``iamcredentials:generateAccessToken``.

    Returns:
        Tuple of ``(sa_access_token, expiry_unix_timestamp)``.
    """
    url = _IAM_CREDENTIALS_URL_TEMPLATE.format(sa_email=sa_email)
    body = {
        "scope": scopes or _DEFAULT_SCOPES,
        "lifetime": f"{int(lifetime_seconds)}s",
    }
    headers = {
        "Authorization": f"Bearer {sts_token}",
        "Content-Type": "application/json",
    }
    client = session or requests
    resp = client.post(url, json=body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    access_token = data["accessToken"]
    if "expireTime" in data:
        expiry = _parse_rfc3339_epoch(data["expireTime"])
    else:
        expiry = int(time.time()) + int(lifetime_seconds)
    return access_token, expiry


def mint_google_access_token(
    bunker_cfg: BunkerConfig,
    signer: Any,
    *,
    scopes: list[str] | None = None,
    jwt_lifetime_seconds: int = DEFAULT_OIDC_JWT_LIFETIME_SECONDS,
    session: requests.Session | None = None,
) -> tuple[str, int]:
    """Perform the full hardware-signed OIDC WIF → Google access token exchange.

    1. Mint a short-lived self-signed OIDC JWT via *signer*.
    2. Exchange it at ``https://sts.googleapis.com/v1/token``.
    3. If ``bunker_cfg.service_account_email`` is configured, exchange the STS
       token for an impersonated SA access token scoped to *scopes*.

    Returns:
        Tuple of ``(access_token, expiry_unix_timestamp)``.
    """
    target_scopes = scopes or _DEFAULT_SCOPES
    kid = bunker_cfg.public_jwk.get("kid")
    jwt_str, _jwt_exp = mint_oidc_jwt(
        signer,
        issuer_uri=bunker_cfg.issuer_uri,
        audience=bunker_cfg.audience,
        subject=bunker_cfg.subject,
        lifetime_seconds=jwt_lifetime_seconds,
        kid=kid,
    )

    # For SA impersonation, STS only needs cloud-platform scope to call IAM Credentials.
    sts_scopes = _DEFAULT_SCOPES if bunker_cfg.service_account_email else target_scopes
    sts_token, sts_exp = exchange_jwt_for_sts_token(
        jwt_str,
        audience=bunker_cfg.audience,
        scopes=sts_scopes,
        session=session,
    )

    if bunker_cfg.service_account_email:
        return generate_sa_access_token(
            sts_token,
            sa_email=bunker_cfg.service_account_email,
            scopes=target_scopes,
            session=session,
        )

    return sts_token, sts_exp


def verify_project_access(
    token: str,
    project_id: str,
    *,
    session: requests.Session | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """Verify *token* can read *project_id* via Cloud Resource Manager."""
    client = session or requests
    resp = client.get(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def build_agent_adc_config(
    bunker_cfg: BunkerConfig,
    *,
    port: int,
    secret_file: Path | str,
    host: str = "127.0.0.1",
) -> dict[str, Any]:
    """Build a standard ``external_account`` ADC JSON pointing to ``wif-bunker agent``.

    The agent handles STS exchange, SA impersonation, and 1-hour RAM caching,
    returning the final Google Bearer token directly from ``token_url``.
    """
    return {
        "type": "external_account",
        "audience": bunker_cfg.audience,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": f"http://{host}:{port}/v1/token",
        "credential_source": {
            "file": str(secret_file),
        },
    }


def build_executable_adc_config(
    bunker_cfg: BunkerConfig,
    *,
    bunker_config_path: Path | str,
    command_path: str,
    output_file: Path | str | None = None,
    timeout_millis: int = 30000,
) -> dict[str, Any]:
    """Build a standard ``external_account`` ADC JSON using ``credential_source.executable``.

    Requires ``GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`` in client processes.
    No background daemon is needed; Google ADC libraries natively cache the
    signed OIDC JWT in *output_file* until ``expiration_time``.
    """
    bunker_cmd_path = Path(bunker_config_path).as_posix()
    if command_path.startswith('"') or " -m " in command_path:
        cmd_prefix = command_path
    elif "/" in command_path or "\\" in command_path:
        cmd_prefix = f'"{Path(command_path).as_posix()}"'
    else:
        cmd_prefix = f'"{command_path}"'

    cmd = f'{cmd_prefix} sign-jwt --config "{bunker_cmd_path}"'
    if output_file is not None:
        cmd += f' --output-file "{Path(output_file).as_posix()}"'

    executable_cfg: dict[str, Any] = {
        "command": cmd,
        "timeout_millis": int(timeout_millis),
    }
    if output_file is not None:
        executable_cfg["output_file"] = str(output_file)

    adc: dict[str, Any] = {
        "type": "external_account",
        "audience": bunker_cfg.audience,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": _STS_TOKEN_URL,
        "credential_source": {
            "executable": executable_cfg,
        },
    }
    if bunker_cfg.service_account_email:
        adc["service_account_impersonation_url"] = _IAM_CREDENTIALS_URL_TEMPLATE.format(
            sa_email=bunker_cfg.service_account_email,
        )
    return adc


def format_executable_response(jwt_str: str, expiration_time: int) -> dict[str, Any]:
    """Format a signed OIDC JWT as a Google Cloud Pluggable Auth v1 JSON payload."""
    return {
        "version": 1,
        "success": True,
        "token_type": "urn:ietf:params:oauth:token-type:jwt",
        "id_token": jwt_str,
        "expiration_time": int(expiration_time),
    }
