"""Configuration dataclasses and constants for WIF Bunker (OIDC WIF)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wif_bunker.utils import MAX_BACKOFF_SECONDS, write_secure_file

# --- Tuning Constants ---
API_RETRY_TIMEOUT_SECONDS = 900  # 15 minutes max total retry time
LRO_TIMEOUT_SECONDS = 300

# Default lifetimes
DEFAULT_OIDC_JWT_LIFETIME_SECONDS = 60  # Short-lived in-RAM assertion for agent mode
DEFAULT_EXECUTABLE_JWT_LIFETIME_SECONDS = 3600  # 1-hour assertion for executable mode (1 HW sign/hr)
DEFAULT_AGENT_REFRESH_MARGIN_SECONDS = 300  # Refresh 5 min before 1-hour expiry

# Algorithms supported by GCP Workload Identity Federation OIDC static JWKS
SUPPORTED_OIDC_ALGORITHMS = ("ES256", "RS256")

# Supported pluggable hardware/software signer backends
SIGNER_TYPES = (
    "linux-tpm",
    "windows-certstore",
    "macos-secureenclave",
    "yubikey",
    "pkcs11",
    "fido2-previewsign",
    "software",
)

__all__ = [
    "API_RETRY_TIMEOUT_SECONDS",
    "DEFAULT_AGENT_REFRESH_MARGIN_SECONDS",
    "DEFAULT_EXECUTABLE_JWT_LIFETIME_SECONDS",
    "DEFAULT_OIDC_JWT_LIFETIME_SECONDS",
    "LRO_TIMEOUT_SECONDS",
    "MAX_BACKOFF_SECONDS",
    "SIGNER_TYPES",
    "SUPPORTED_OIDC_ALGORITHMS",
    "BunkerConfig",
    "WorkloadConfig",
]


@dataclass
class BunkerConfig:
    """Persistent local configuration written to ``bunker.json`` (0600).

    Contains NO private key material — only the GCP WIF resource coordinates,
    public JWK metadata, and parameters telling the chosen signer how to locate
    the pre-existing hardware key.
    """

    project_id: str
    project_number: str
    pool_id: str
    provider_id: str
    audience: str
    issuer_uri: str
    subject: str
    signer: dict[str, Any]
    public_jwk: dict[str, Any]
    service_account_email: str | None = None
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        data: dict[str, Any] = {
            "version": self.version,
            "project_id": self.project_id,
            "project_number": self.project_number,
            "pool_id": self.pool_id,
            "provider_id": self.provider_id,
            "audience": self.audience,
            "issuer_uri": self.issuer_uri,
            "subject": self.subject,
            "service_account_email": self.service_account_email,
            "signer": self.signer,
            "public_jwk": self.public_jwk,
        }
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BunkerConfig:
        """Deserialize from a dictionary loaded from ``bunker.json``."""
        required = (
            "project_id",
            "project_number",
            "pool_id",
            "provider_id",
            "audience",
            "issuer_uri",
            "subject",
            "signer",
            "public_jwk",
        )
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"Invalid bunker.json: missing required field(s): {', '.join(missing)}")
        return cls(
            version=int(data.get("version", 1)),
            project_id=str(data["project_id"]),
            project_number=str(data["project_number"]),
            pool_id=str(data["pool_id"]),
            provider_id=str(data["provider_id"]),
            audience=str(data["audience"]),
            issuer_uri=str(data["issuer_uri"]),
            subject=str(data["subject"]),
            service_account_email=data.get("service_account_email"),
            signer=dict(data["signer"]),
            public_jwk=dict(data["public_jwk"]),
        )

    def save(self, path: Path | str) -> Path:
        """Write configuration to *path* with strict 0600 permissions."""
        out_path = Path(path)
        write_secure_file(out_path, json.dumps(self.to_dict(), indent=2) + "\n")
        return out_path

    @classmethod
    def load(cls, path: Path | str) -> BunkerConfig:
        """Load configuration from *path*."""
        in_path = Path(path)
        if not in_path.exists():
            raise FileNotFoundError(f"WIF Bunker config file not found: {in_path}")
        try:
            raw = json.loads(in_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {in_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"Invalid bunker.json in {in_path}: expected JSON object")
        return cls.from_dict(raw)


@dataclass
class WorkloadConfig:
    """Runtime configuration for setup and attestation commands."""

    sa_name: str = "bunker-wif-sa"
    pool_id: str = "bunker-wif-pool"
    provider_id: str = field(init=False)
    suffix: str = field(default_factory=lambda: str(int(time.time())))
    project_id: str = field(init=False)
    workload_cn: str = field(init=False)  # Also used as OIDC JWT `sub` and attestation label
    issuer_uri: str = field(init=False)

    # Signer selection & locator parameters
    signer_type: str | None = None
    signer_params: dict[str, Any] = field(default_factory=dict)

    # Attestation-specific optional targets
    use_yubikey: bool = False
    yubikey_serial: int | None = None
    yubikey_slot: str = "9c"
    linux_tpm_handle: int | None = None
    windows_store_location: str = "current_user"

    def __post_init__(self) -> None:
        self.project_id = f"bunker-wif-{self.suffix}"
        self.provider_id = f"bunker-oidc-prov-{self.suffix}"
        self.workload_cn = f"bunker-workload-{self.suffix}"
        self.issuer_uri = f"https://wif-bunker.internal/{self.provider_id}"

    @property
    def subject(self) -> str:
        """OIDC JWT subject claim (`sub`)."""
        return self.workload_cn

    @subject.setter
    def subject(self, value: str) -> None:
        self.workload_cn = value
