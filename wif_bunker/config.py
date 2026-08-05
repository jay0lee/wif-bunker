"""Configuration dataclasses, constants, and key algorithm definitions."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# --- Tuning Constants ---
MAX_BACKOFF_SECONDS = 60
LRO_TIMEOUT_SECONDS = 300


# WIF maximum certificate lifetime (Google enforced).
_WIF_MAX_CERT_LIFETIME_DAYS = 390
_DEFAULT_CERT_LIFETIME_DAYS = 90

# --- Key Algorithm Definitions ---
# Maps user-facing algorithm names to platform-specific parameters.
# Each entry: (description, supported_platforms)
_KEY_ALGORITHMS: dict[str, dict] = {
    "es256": {
        "desc": "ECDSA P-256 (default, fastest)",
        "platforms": {"darwin", "win32", "linux", "yubikey"},
        "macos_sc_auth": "p-256-ne",  # sc_auth -k flag
        "windows_certreq": "ECDSA_P256",  # certreq INF KeyAlgorithm (legacy)
        "ncrypt_algo": "ECDSA_P256",  # NCryptCreatePersistedKey algorithm
        "ncrypt_key_length": None,  # ECC key length is implicit in algorithm
        "ncrypt_cng_class": "ECDsaCng",  # .NET class for CopyWithPrivateKey
        "linux_tpm2": "ecc256",  # tpm2_ptool --algorithm
    },
    "es384": {
        "desc": "ECDSA P-384",
        "platforms": {"darwin", "win32", "linux", "yubikey"},
        "macos_sc_auth": "p-384-ne",
        "windows_certreq": "ECDSA_P384",
        "ncrypt_algo": "ECDSA_P384",
        "ncrypt_key_length": None,
        "ncrypt_cng_class": "ECDsaCng",
        "linux_tpm2": "ecc384",
    },
    "rsa2048": {
        "desc": "RSA 2048-bit",
        "platforms": {"win32", "linux", "yubikey"},
        "windows_certreq": "RSA",
        "windows_key_length": 2048,
        "ncrypt_algo": "RSA",
        "ncrypt_key_length": 2048,
        "ncrypt_cng_class": "RSACng",
        "linux_tpm2": "rsa2048",
    },
    "rsa3072": {
        "desc": "RSA 3072-bit",
        "platforms": {"win32", "linux"},
        "windows_certreq": "RSA",
        "windows_key_length": 3072,
        "ncrypt_algo": "RSA",
        "ncrypt_key_length": 3072,
        "ncrypt_cng_class": "RSACng",
        "linux_tpm2": "rsa3072",
    },
    "rsa4096": {
        "desc": "RSA 4096-bit (slowest, YubiKey firmware 5.7+)",
        "platforms": {"win32", "linux", "yubikey"},
        "windows_certreq": "RSA",
        "windows_key_length": 4096,
        "ncrypt_algo": "RSA",
        "ncrypt_key_length": 4096,
        "ncrypt_cng_class": "RSACng",
        "linux_tpm2": "rsa4096",
    },
}


# --- Config file names written by wif-bunker ---
_CONFIG_FILES = ("adc.json", "certificate_config.json", "workload_cert.pem", "trust_chain.pem")


def _generate_tpm_pin(length: int = 24) -> str:
    """Generate a random alphanumeric PIN for TPM PKCS#11 tokens.

    Default 24 chars — never human-typed, stored in 0o600 config files.
    """
    import secrets  # pylint: disable=import-outside-toplevel
    import string  # pylint: disable=import-outside-toplevel

    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# --- Runtime Configuration ---
@dataclass
class WorkloadConfig:
    """Runtime configuration generated at execution time, not import time."""

    sa_name: str = "bunker-wif-sa"
    pool_id: str = "bunker-wif-pool"
    provider_id: str = field(init=False)  # unique per run
    linux_tpm_pin: str = field(default_factory=lambda: _generate_tpm_pin())
    key_algorithm: str = "es256"
    cert_lifetime_days: int = _DEFAULT_CERT_LIFETIME_DAYS
    soft_key: bool = False  # Use software keys (CI testing, no TPM required)
    use_yubikey: bool = False  # Use YubiKey PIV instead of platform TPM/SE
    yubikey_serial: int | None = None  # Specific YubiKey serial (if multiple)
    yubikey_slot: str = "9a"  # PIV slot: 9a, 9c, 9d, 9e
    yubikey_touch_policy: str = "never"  # never, cached, always
    suffix: str = field(default_factory=lambda: str(int(time.time())))
    project_id: str = field(init=False)
    workload_cn: str = field(init=False)
    ca_cn: str = field(init=False)

    def __post_init__(self) -> None:
        self.project_id = f"bunker-wif-{self.suffix}"
        self.provider_id = f"bunker-x509-prov-{self.suffix}"
        self.workload_cn = f"bunker-workload-{self.suffix}"
        self.ca_cn = f"bunker-ca-{self.suffix}"

    @property
    def key_algo_config(self) -> dict:
        """Returns the platform-specific parameters for the configured algorithm."""
        return _KEY_ALGORITHMS[self.key_algorithm]


@dataclass
class CertificateBundle:
    """Result of hardware-backed cert generation."""

    trust_anchor_pem: str  # CA cert PEM — uploaded to GCP as trust anchor
    workload_cert_pem: str  # Workload cert PEM — needed on-disk for google-auth
    issuer_cn: str  # CA's CN — used in ECP config for cert selection
    serial_number_hex: str  # Workload cert serial (hex) — for WIF condition
    sha256_fingerprint: str  # Workload cert SHA-256 fingerprint (base64)
