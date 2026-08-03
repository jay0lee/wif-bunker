#!/usr/bin/env python3
"""
WIF Bunker — Hardware-backed X.509 Workload Identity Federation (ADC)
100% Hardware-Backed (TPM 2.0 / Secure Enclave) Zero-Disk Implementation
"""

from __future__ import annotations

__version__ = "dev"  # Replaced by build process with datetime version

import argparse
import base64
import concurrent.futures
import ctypes
import datetime
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, ClassVar

import requests
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from google.auth import default as google_auth_default
from google.auth.exceptions import OAuthError, RefreshError
from google.auth.transport.requests import (
    Request as GoogleAuthRequest,
)
from google.auth.transport.requests import (
    _MutualTlsOffloadAdapter,
)

from get_ecp import get_default_ecp_dir, get_ecp_binary_names, get_ecp_platform_info

logger = logging.getLogger(__name__)


class _CleanFormatter(logging.Formatter):
    """INFO prints bare message; other levels keep their prefix."""

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno == logging.INFO:
            return record.getMessage()
        return f"{record.levelname}: {record.getMessage()}"


def _supports_unicode() -> bool:
    """Detect whether the output terminal can render Unicode symbols."""
    if sys.platform == "win32":
        # Windows cmd.exe / GHA runner often lacks UTF-8 support
        # unless the code page is explicitly set to 65001.
        try:
            enc = sys.stdout.encoding or ""
            if "utf" in enc.lower():
                return True
        except Exception:
            pass
        return os.environ.get("WT_SESSION") is not None  # Windows Terminal
    return True  # macOS/Linux terminals support UTF-8


# Symbols that degrade gracefully on non-Unicode terminals.
_UNICODE = _supports_unicode()
SYM_OK = "\u2705" if _UNICODE else "[OK]"  # ✅
SYM_WARN = "\u26a0" if _UNICODE else "[!]"  # ⚠
SYM_FAIL = "\u274c" if _UNICODE else "[X]"  # ❌
SYM_ARROW = "\u2192" if _UNICODE else "->"  # →

# --- Tuning Constants ---
MAX_BACKOFF_SECONDS = 60
LRO_TIMEOUT_SECONDS = 300


# WIF maximum certificate lifetime (Google enforced).
_WIF_MAX_CERT_LIFETIME_DAYS = 390

# --- Key Algorithm Definitions ---
# Maps user-facing algorithm names to platform-specific parameters.
# Each entry: (description, supported_platforms)
_KEY_ALGORITHMS: dict[str, dict] = {
    "es256": {
        "desc": "ECDSA P-256 (default, fastest)",
        "platforms": {"darwin", "win32", "linux"},
        "macos_sc_auth": "p-256-ne",  # sc_auth -k flag
        "windows_certreq": "ECDSA_P256",  # certreq INF KeyAlgorithm
        "linux_tpm2": "ecc256",  # tpm2_ptool --algorithm
    },
    "es384": {
        "desc": "ECDSA P-384",
        "platforms": {"darwin", "win32", "linux"},
        "macos_sc_auth": "p-384-ne",
        "windows_certreq": "ECDSA_P384",
        "linux_tpm2": "ecc384",
    },
    "rsa2048": {
        "desc": "RSA 2048-bit",
        "platforms": {"win32", "linux"},
        "windows_certreq": "RSA",
        "windows_key_length": 2048,
        "linux_tpm2": "rsa2048",
    },
    "rsa3072": {
        "desc": "RSA 3072-bit",
        "platforms": {"win32", "linux"},
        "windows_certreq": "RSA",
        "windows_key_length": 3072,
        "linux_tpm2": "rsa3072",
    },
    "rsa4096": {
        "desc": "RSA 4096-bit (slowest)",
        "platforms": {"win32", "linux"},
        "windows_certreq": "RSA",
        "windows_key_length": 4096,
        "linux_tpm2": "rsa4096",
    },
}


# --- Subprocess Helpers ---
def _require_command(name: str, *, package: str = "", install_hint: str = "") -> str:
    """Verify an external command is available on PATH.

    Returns the resolved path.  Raises RuntimeError with install
    instructions if the command is not found.
    """
    path = shutil.which(name)
    if path:
        return path
    msg = f"Required command '{name}' not found on PATH."
    if package:
        msg += f"\n  Package: {package}"
    if install_hint:
        msg += f"\n  Install: {install_hint}"
    raise RuntimeError(msg)


def _check_tpm_linux() -> None:
    """Pre-validate TPM availability on Linux.

    Checks for hardware TPM device, tpm2-abrmd service, or software TPM.
    Raises RuntimeError with actionable guidance if no TPM is accessible.
    """
    # 1. Hardware TPM device node
    tpm_device = Path("/dev/tpmrm0")
    if tpm_device.exists():
        return  # Hardware TPM available

    # 2. Check if tpm2-abrmd service is running (systemd)
    try:
        abrmd = subprocess.run(
            ["systemctl", "is-active", "--quiet", "tpm2-abrmd"],
            capture_output=True,
            timeout=5,
        )
        if abrmd.returncode == 0:
            return  # tpm2-abrmd is running and managing a TPM
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # systemctl not available or timed out

    # 3. Check for software TPM (swtpm) via TCTI env or port probe
    if os.environ.get("TPM2TOOLS_TCTI"):
        return  # User has explicitly configured a TCTI (e.g. swtpm)
    try:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect(("127.0.0.1", 2321))
            return  # swtpm is listening on the default port
    except (OSError, ConnectionRefusedError):
        pass

    raise RuntimeError(
        "No TPM device or service found.\n"
        "\n"
        "  wif_bunker requires a TPM 2.0 for hardware-backed keys.\n"
        "\n"
        "  Options:\n"
        "    1. Hardware TPM — ensure the tpm2-abrmd service is running:\n"
        "         sudo systemctl start tpm2-abrmd\n"
        "\n"
        "    2. Software TPM (development/testing) — install and start swtpm:\n"
        "         sudo apt install swtpm swtpm-tools\n"
        "         mkdir -p /tmp/swtpm\n"
        "         swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 "
        "--server type=tcp,port=2321 --ctrl type=tcp,port=2322 &\n"
        "         export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'\n"
        "\n"
        "    3. Use --soft-key for software-only keys (no TPM required).\n"
        "       NOTE: --soft-key does NOT provide hardware TPM protection.\n"
        "       Keys are stored in software and are exportable. Use only for\n"
        "       development and testing, never for production workloads."
    )


# --- Runtime Configuration ---
@dataclass
class WorkloadConfig:
    """Runtime configuration generated at execution time, not import time."""

    sa_name: str = "bunker-wif-sa"
    pool_id: str = "bunker-wif-pool"
    provider_id: str = field(init=False)  # unique per run
    linux_tpm_pin: str = "bunker123"
    key_algorithm: str = "es256"
    soft_key: bool = False  # Use software keys (CI testing, no TPM required)
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


# --- Pythonic Retry & File Helpers ---
def with_retries(
    max_attempts: int = 25,
    expected_errors: tuple[int, ...] = (403, 404),
    custom_error_text: str | None = None,
    retryable_exceptions: tuple[type[Exception], ...] = (),
    retry_msg: str = "Waiting for propagation",
) -> Callable:
    """Decorator that retries on expected HTTP errors with capped exponential backoff.

    Also retries on any exception type listed in *retryable_exceptions*.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions:
                    if attempt < max_attempts - 1:
                        sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
                        logger.info(
                            "    %s (%d/%d), %ds...",
                            retry_msg,
                            attempt + 1,
                            max_attempts,
                            sleep_time,
                        )
                        time.sleep(sleep_time)
                        continue
                    raise
                except requests.exceptions.HTTPError as e:
                    status = e.response.status_code
                    body = e.response.text
                    is_expected_status = status in expected_errors
                    is_custom_error = custom_error_text and custom_error_text in body
                    if (is_expected_status or is_custom_error) and attempt < max_attempts - 1:
                        sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
                        logger.info(
                            "    %s (%d/%d), %ds...",
                            retry_msg,
                            attempt + 1,
                            max_attempts,
                            sleep_time,
                        )
                        time.sleep(sleep_time)
                        continue
                    # Final attempt or unexpected error — log full detail.
                    logger.error(
                        "HTTP %d from %s FAILED after %d attempts — %s",
                        status,
                        func.__name__,
                        attempt + 1,
                        body,
                    )
                    raise

        return wrapper

    return decorator


def write_secure_file(filepath: Path | str, content: str) -> None:
    """Writes a file to disk enforcing strictly locked down 0600 permissions."""
    filepath = Path(filepath)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    with os.fdopen(os.open(filepath, flags, mode), "w") as f:
        f.write(content)


# --- GCP Infrastructure Session Manager ---
class GCPClient:
    """Thread-safe GCP API client.

    Supports two authentication modes:
    - **3-legged OAuth** (default): Opens a browser for user consent.
    - **ADC** (``use_adc=True``): Uses Application Default Credentials,
      e.g. from ``google-github-actions/auth`` or ``gcloud auth``.
    """

    # Default OAuth client for this tool.  Users can override with
    # --client-secrets-file pointing to their own Desktop OAuth client.
    _DEFAULT_CLIENT_ID = "284409941921-t4ukaudpiagsbl51t3adqtkgb30gu93o.apps.googleusercontent.com"
    _DEFAULT_CLIENT_SECRET = "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"
    _OAUTH_SCOPES: ClassVar[list[str]] = [
        # Project CRUD + project-level IAM policy
        "https://www.googleapis.com/auth/cloudplatformprojects",
        # Service accounts, WIF pools & providers
        "https://www.googleapis.com/auth/iam",
        # API enablement (batchEnable)
        "https://www.googleapis.com/auth/service.management",
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
    ]

    def __init__(
        self,
        *,
        use_adc: bool = False,
        client_secrets_file: str | None = None,
    ) -> None:
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._token_lock = threading.Lock()

        if use_adc:
            self._credentials, _ = google_auth_default(
                scopes=self._OAUTH_SCOPES,
            )
            self._auth_request = GoogleAuthRequest()
            self._credentials.refresh(self._auth_request)
            self._token = None
            # Log the identity we're authenticated as.
            identity = getattr(self._credentials, "service_account_email", None) or getattr(
                self._credentials, "signer_email", None
            )
            if not identity:
                # For user credentials, check tokeninfo.
                try:
                    info = self.session.get(
                        "https://oauth2.googleapis.com/tokeninfo",
                        params={"access_token": self._credentials.token},
                    ).json()
                    identity = info.get("email", "unknown")
                except Exception:
                    identity = "unknown"
            logger.info("Authenticated via Application Default Credentials as: %s", identity)
        else:
            self._credentials = None
            self._token = self._oauth_user_token(client_secrets_file)

    def _oauth_user_token(self, client_secrets_file: str | None) -> str:
        """3-legged OAuth flow — returns a short-lived access token.

        1. Starts a local redirect server on a random port.
        2. Opens the browser to Google's consent page.
        3. If the redirect works, captures the code automatically.
        4. If it fails (SSH, firewall), the user pastes the redirect URL.
        5. Exchanges the code for an access token with access_type=online
           (no refresh token stored).
        """
        import http.server
        import secrets
        import urllib.parse
        import webbrowser

        # Load OAuth client config.
        if client_secrets_file:
            with open(client_secrets_file) as f:
                client_config = json.load(f)
            installed = client_config.get("installed", client_config.get("web", {}))
            client_id = installed["client_id"]
            client_secret = installed.get("client_secret", "")
        else:
            client_id = self._DEFAULT_CLIENT_ID
            client_secret = self._DEFAULT_CLIENT_SECRET

        # CSRF protection + PKCE (RFC 7636).
        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)  # 43-128 chars
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        auth_code = None

        # Start a local redirect server on a random port.
        class _RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self_handler):
                nonlocal auth_code
                qs = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self_handler.path).query,
                )
                if qs.get("state", [None])[0] == state:
                    auth_code = qs.get("code", [None])[0]
                self_handler.send_response(200)
                self_handler.send_header("Content-Type", "text/html")
                self_handler.end_headers()
                self_handler.wfile.write(
                    b"<h2>Authorization complete.</h2><p>You may close this window and return to the terminal.</p>"
                )

            def log_message(self_handler, *args):
                pass  # Suppress request logging.

        server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        port = server.server_address[1]
        redirect_uri = f"http://localhost:{port}"

        # Build the authorization URL with PKCE.
        auth_params = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(self._OAUTH_SCOPES),
                "state": state,
                "access_type": "online",  # No refresh token.
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{auth_params}"

        # Google Workspace orgs may block untrusted OAuth apps (OWL).
        # Prompt the admin to allowlist the client ID before proceeding.
        logger.info("=" * 70)
        logger.info("If you are using a Google Workspace account, you may need to")
        logger.info("allowlist WIF Bunker's OAuth client before you can authorize.")
        logger.info("")
        logger.info("  1. Open the Admin Console API Controls page:")
        logger.info("     https://admin.google.com/ac/owl")
        logger.info("  2. Click 'Add app' → 'OAuth App Name Or Client ID'")
        logger.info("  3. Search for client ID:")
        logger.info("     %s", client_id)
        logger.info("  4. Select 'WIF Bunker' and set access to 'Trusted'")
        logger.info("")
        logger.info("Consumer Gmail accounts can skip this step.")
        logger.info("=" * 70)
        input("Press Enter to open the browser for authorization...")
        logger.info("")
        logger.info("Opening browser for authorization...")
        logger.info("If the browser doesn't open, visit this URL:")
        logger.info("  %s", auth_url)
        logger.info("")
        logger.info(
            "If you see a 'page not found' error after authorizing,\n"
            "    copy the FULL URL from the address bar and paste it here.\n"
            "    You can also paste just the authorization code."
        )

        # Try to open the browser.
        try:
            webbrowser.open(auth_url)
        except Exception:
            pass  # User will use the printed URL.

        # Wait for the auth code from either source:
        #   1. Local server catches the redirect automatically
        #   2. User pastes the redirect URL into stdin
        # Two daemon threads race; whichever gets the code first wins.
        code_event = threading.Event()

        def _serve_until_code():
            nonlocal auth_code
            server.timeout = 1
            while not code_event.is_set():
                server.handle_request()

        def _read_stdin_for_code():
            nonlocal auth_code
            while not code_event.is_set():
                try:
                    pasted = input().strip()
                except (EOFError, OSError):
                    return
                if pasted and not code_event.is_set():
                    # Accept either a full redirect URL or a raw code.
                    if "code=" in pasted:
                        qs = urllib.parse.parse_qs(
                            urllib.parse.urlparse(pasted).query,
                        )
                        code_list = qs.get("code")
                        if code_list:
                            auth_code = code_list[0]
                            code_event.set()
                            return
                    elif pasted.startswith("4/"):
                        # Raw Google auth codes start with "4/"
                        auth_code = pasted
                        code_event.set()
                        return

        # Patch the handler to signal the event when code is captured.
        orig_do_GET = _RedirectHandler.do_GET

        def _signaling_do_GET(self_handler):
            orig_do_GET(self_handler)
            if auth_code:
                code_event.set()

        _RedirectHandler.do_GET = _signaling_do_GET

        server_thread = threading.Thread(target=_serve_until_code, daemon=True)
        stdin_thread = threading.Thread(target=_read_stdin_for_code, daemon=True)
        server_thread.start()
        stdin_thread.start()

        code_event.wait()  # Blocks until either thread captures the code.
        server.server_close()

        if not auth_code:
            raise RuntimeError("Failed to obtain authorization code.")

        # Exchange the code for an access token (no refresh token).
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": auth_code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        access_token = token_data["access_token"]
        logger.info("    Authenticated successfully (token expires in %ss).", token_data.get("expires_in", "?"))
        return access_token

    def __enter__(self) -> GCPClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.session.close()

    @with_retries(max_attempts=10, expected_errors=(403, 404))
    def api_call(
        self,
        method: str,
        url: str,
        json_payload: dict | None = None,
    ) -> dict | None:
        if self._credentials:
            # ADC mode — auto-refresh and apply credentials.
            self._credentials.refresh(self._auth_request)
            headers = {}
            self._credentials.apply(headers)
        else:
            # OAuth mode — use the static short-lived token.
            headers = {"Authorization": f"Bearer {self._token}"}
        res = self.session.request(method, url, json=json_payload, headers=headers)
        res.raise_for_status()
        return res.json() if res.content else None

    def wait_for_lro(
        self,
        api_domain: str,
        op_name: str,
        timeout: int = LRO_TIMEOUT_SECONDS,
    ) -> dict:
        """Polls a Long-Running Operation until done, with a hard timeout."""
        url = f"https://{api_domain}/v1/{op_name}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            op_data = self.api_call("GET", url)
            if op_data and op_data.get("done"):
                return op_data
            time.sleep(2)
        raise TimeoutError(f"LRO {op_name} did not complete within {timeout}s")

    def wait_for_wif_resource(self, url: str, max_attempts: int = 12) -> dict:
        """Polls a WIF resource until it reaches ACTIVE state."""
        for attempt in range(max_attempts):
            data = self.api_call("GET", url)
            if data and data.get("state") == "ACTIVE":
                return data
            sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
            logger.debug(
                "WIF resource not ACTIVE yet (attempt %d/%d), sleeping %ds",
                attempt + 1,
                max_attempts,
                sleep_time,
            )
            time.sleep(sleep_time)
        raise TimeoutError(f"WIF resource at {url} did not become ACTIVE within {max_attempts} attempts")


# --- Ephemeral CA & Workload Certificate Signing ---
def _create_ca_and_sign(
    hw_public_key_pem: str,
    config: WorkloadConfig,
) -> tuple[CertificateBundle, str]:
    """Creates an ephemeral CA and signs a workload cert for a hardware key.

    Accepts either a PEM CSR (from sc_auth create-ctk-csr) or a PEM
    self-signed certificate (from certtool / PowerShell).  In both cases
    the hardware-backed public key is extracted and embedded in a new
    workload certificate signed by the ephemeral CA.

    Args:
        hw_public_key_pem: PEM-encoded CSR or self-signed certificate
            containing the hardware-backed public key.
        config: Workload configuration.

    Returns:
        (CertificateBundle, workload_cert_pem) — the bundle for GCP plus
        the CA-signed workload cert PEM to install in the OS keystore.
    """
    # Extract the public key from either a CSR or a self-signed cert
    pem_bytes = hw_public_key_pem.encode()
    if b"CERTIFICATE REQUEST" in pem_bytes:
        csr = cx509.load_pem_x509_csr(pem_bytes)
        workload_pub_key = csr.public_key()
    else:
        cert = cx509.load_pem_x509_certificate(pem_bytes)
        workload_pub_key = cert.public_key()

    # --- Generate ephemeral CA (in-memory only, never written to disk) ---
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, config.ca_cn),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "WIF Bunker"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        cx509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=_WIF_MAX_CERT_LIFETIME_DAYS))
        .add_extension(
            cx509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            cx509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    logger.info("    Ephemeral CA generated: CN=%s", config.ca_cn)

    # --- Sign workload cert with the CA ---
    workload_name = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, config.workload_cn),
        ]
    )
    workload_cert = (
        cx509.CertificateBuilder()
        .subject_name(workload_name)
        .issuer_name(ca_name)
        .public_key(workload_pub_key)
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=_WIF_MAX_CERT_LIFETIME_DAYS))
        .add_extension(
            cx509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            cx509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    logger.info(
        "    Workload cert signed by CA: CN=%s %s issued by CN=%s",
        config.workload_cn,
        SYM_ARROW,
        config.ca_cn,
    )

    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    workload_cert_pem = workload_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    logger.debug("Trust anchor PEM repr: %s", repr(ca_cert_pem[:120]))

    # Compute cert-pinning values for the WIF attributeCondition.
    # Per Google docs:
    #   assertion.serialNumberHex — uppercase hex string
    #   assertion.sha256Fingerprint — standard Base64 encoded
    workload_der = workload_cert.public_bytes(serialization.Encoding.DER)
    sha256_fp = base64.b64encode(hashlib.sha256(workload_der).digest()).decode().rstrip("=")
    serial_hex = format(workload_cert.serial_number, "X")

    logger.info("    Workload cert serial (hex): %s", serial_hex)
    logger.info("    Workload cert SHA-256 fingerprint: %s", sha256_fp)

    bundle = CertificateBundle(
        trust_anchor_pem=ca_cert_pem,
        workload_cert_pem=workload_cert_pem,
        issuer_cn=config.ca_cn,
        serial_number_hex=serial_hex,
        sha256_fingerprint=sha256_fp,
    )
    return bundle, workload_cert_pem


# --- Platform-Specific Hardware Keystore Generators ---


def _generate_cert_windows(config: WorkloadConfig) -> CertificateBundle:
    """Generates a TPM 2.0-backed certificate via certreq + Microsoft Platform Crypto Provider.

    Flow (mirrors macOS Secure Enclave approach):
      1. Clean up stale bunker-workload-* certs from previous runs
      2. certreq -new request.inf request.csr  → TPM key + CSR (no self-signed cert)
      3. Ephemeral CA signs the CSR            → CA-signed workload cert
      4. certreq -accept issued.cer            → associates CA cert with TPM key
    """
    # Pre-validate required commands.
    _require_command(
        "certreq", install_hint="Built-in Windows command — should be at C:\\Windows\\System32\\certreq.exe"
    )
    _require_command(
        "certutil", install_hint="Built-in Windows command — should be at C:\\Windows\\System32\\certutil.exe"
    )
    _require_command("powershell", install_hint="Built-in Windows command — ensure PowerShell is on PATH")

    _tmpdir = tempfile.TemporaryDirectory(prefix="bunker_")
    work_dir = Path(_tmpdir.name)

    try:
        # 0. Clean up stale bunker-workload certs from previous runs.
        ps_cleanup = (
            "Get-ChildItem Cert:\\CurrentUser\\My | "
            "Where-Object { $_.Subject -like 'CN=bunker-workload-*' } | "
            "Remove-Item -Force"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cleanup],
            capture_output=True,
            text=True,
        )
        logger.info("    Cleaned up stale bunker-workload certs from CurrentUser store.")

        # 1. Write certreq INF.
        algo = config.key_algo_config
        if config.soft_key:
            provider = "Microsoft Software Key Storage Provider"
            logger.warning(
                "    %s  --soft-key: using software keys (NOT TPM-backed). "
                "For production use, remove --soft-key to use the TPM.",
                SYM_WARN,
            )
        else:
            provider = "Microsoft Platform Crypto Provider"
        inf_path = work_dir / "request.inf"
        inf_lines = [
            "[Version]",
            'Signature="$Windows NT$"',
            "",
            "[NewRequest]",
            f'Subject = "CN={config.workload_cn}"',
            f"KeyAlgorithm = {algo['windows_certreq']}",
            "HashAlgorithm = SHA256",
            f'ProviderName = "{provider}"',
            "Exportable = FALSE",
            "MachineKeySet = FALSE",
            "RequestType = PKCS10",
            "KeyUsage = 0x80",  # CERT_DIGITAL_SIGNATURE_KEY_USAGE
        ]
        if "windows_key_length" in algo:
            inf_lines.append(f"KeyLength = {algo['windows_key_length']}")
        inf_path.write_text("\n".join(inf_lines) + "\n")

        # 2. Generate TPM key pair + CSR via certreq.
        csr_path = work_dir / "request.csr"
        result = subprocess.run(
            ["certreq", "-new", "-f", str(inf_path), str(csr_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        if not csr_path.exists():
            raise FileNotFoundError(
                f"CSR not found at {csr_path} after certreq -new. stdout: {result.stdout}, stderr: {result.stderr}"
            )
        csr_pem = csr_path.read_text().strip()
        logger.info("    TPM key created and CSR generated: %s", config.workload_cn)

        # 3. Ephemeral CA signs the CSR → CA-signed workload cert.
        bundle, workload_pem = _create_ca_and_sign(csr_pem, config)

        # 4. Install CA cert into trusted root store so certreq -accept
        #    can validate the chain.  This triggers a Windows security
        #    dialog — the user must click Yes.  We verify afterward.
        logger.warning("")
        logger.warning("    ╔══════════════════════════════════════════════════════════╗")
        logger.warning("    ║  ATTENTION: A Windows Security dialog will appear.      ║")
        logger.warning("    ║  You MUST click YES to install the ephemeral CA cert.    ║")
        logger.warning("    ║                                                          ║")
        logger.warning("    ║  ⚠  The dialog may appear BEHIND this window.            ║")
        logger.warning("    ║     Check your taskbar for a 'Security Warning' prompt.  ║")
        logger.warning("    ╚══════════════════════════════════════════════════════════╝")
        logger.warning("")
        ca_cert_obj = cx509.load_pem_x509_certificate(bundle.trust_anchor_pem.encode())
        ca_der_path = work_dir / "ca.der"
        ca_der_path.write_bytes(ca_cert_obj.public_bytes(serialization.Encoding.DER))
        ps_install_ca = (
            f"$cert = Import-Certificate "
            f"-FilePath '{ca_der_path}' "
            f"-CertStoreLocation 'Cert:\\CurrentUser\\Root'; "
            f"Write-Output $cert.Thumbprint"
        )
        ca_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_install_ca],
            capture_output=True,
            text=True,
            check=True,
        )
        ca_thumbprint = ca_result.stdout.strip()

        # Verify the CA was actually accepted.
        ps_verify_ca = (
            f"(Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object {{ $_.Thumbprint -eq '{ca_thumbprint}' }}).Count"
        )
        verify_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_verify_ca],
            capture_output=True,
            text=True,
        )
        if verify_result.stdout.strip() != "1":
            raise RuntimeError(
                "Ephemeral CA was not added to the trusted root store. "
                "You must click YES on the Windows security dialog to proceed."
            )
        logger.info("    Ephemeral CA added to trusted root store.")

        # 5. certreq -accept associates the cert with the existing TPM key
        #    in Cert:\CurrentUser\My, replacing the pending request.
        issued_cert_path = work_dir / "issued.cer"
        issued_cert_path.write_text(workload_pem)
        subprocess.run(
            ["certreq", "-accept", str(issued_cert_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("    CA-signed cert associated with TPM key in CurrentUser store.")

        # 6. Remove the ephemeral CA from trusted root store.
        #    On Windows, this triggers a Security Warning dialog
        #    requiring user confirmation (same as import).
        logger.warning("")
        logger.warning("    ╔══════════════════════════════════════════════════════════╗")
        logger.warning("    ║  ATTENTION: Another Windows Security dialog will appear. ║")
        logger.warning("    ║  Click YES to remove the ephemeral CA (cleanup step).    ║")
        logger.warning("    ║                                                          ║")
        logger.warning("    ║  ⚠  Check your taskbar if you don't see it.              ║")
        logger.warning("    ╚══════════════════════════════════════════════════════════╝")
        logger.warning("")
        logger.info("    Removing ephemeral CA from trusted root store...")
        subprocess.run(
            ["certutil", "-user", "-delstore", "Root", ca_thumbprint],
            capture_output=True,
            text=True,
        )
        verify_result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"@(Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object Thumbprint -eq '{ca_thumbprint}').Count",
            ],
            capture_output=True,
            text=True,
        )
        if verify_result.stdout.strip() == "0":
            logger.info("    Ephemeral CA removed from trusted root store.")
        else:
            logger.warning(
                "    Ephemeral CA may still be in Cert:\\CurrentUser\\Root "
                "(thumbprint: %s). Remove it manually if needed.",
                ca_thumbprint,
            )

        return bundle

    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        cmd_name = e.cmd[0] if isinstance(e.cmd, list) else str(e.cmd)
        if "NTE_DEVICE_NOT_FOUND" in stderr:
            raise RuntimeError(
                f"No TPM device found (command: {cmd_name}).\n"
                "Windows could not find a TPM on this system.\n"
                "\n"
                "  Use --soft-key for software-only keys (no TPM required).\n"
                "  NOTE: --soft-key does NOT provide hardware TPM protection."
            ) from e
        if "NTE_NOT_SUPPORTED" in stderr:
            raise RuntimeError(
                f"TPM does not support the requested algorithm (command: {cmd_name}).\n"
                "  Try a different --key-algorithm (e.g. es256 or rsa2048)."
            ) from e
        raise RuntimeError(
            f"Windows certificate generation failed (command: {cmd_name}, "
            f"exit code: {e.returncode}).\n"
            f"  stdout: {(e.stdout or '')[:300]}\n"
            f"  stderr: {stderr[:500]}"
        ) from e
    finally:
        _tmpdir.cleanup()


def _macos_login_keychain() -> str:
    """Returns the path to the macOS login keychain."""
    return str(Path.home() / "Library/Keychains/login.keychain-db")


def _generate_cert_macos(config: WorkloadConfig) -> CertificateBundle:
    """Generates a Secure Enclave-backed certificate via CryptoTokenKit (macOS 15+).

    Flow:
      1. Delete stale CTK identities from previous runs
      2. sc_auth create-ctk-identity → SE key + throwaway self-signed cert
      3. sc_auth identities          → look up the key's SHA-1 hash
      4. sc_auth create-ctk-csr      → proper CSR signed by the SE key
      5. Ephemeral CA signs the CSR  → CA-signed workload cert
      6. sc_auth import-ctk-certificate → replace self-signed cert with CA-signed
    """
    # Pre-validate required commands.
    _require_command("security", install_hint="Built-in macOS command — should always be at /usr/bin/security")
    _require_command("sc_auth", install_hint="Built-in macOS command — requires macOS 10.15+. Check /usr/bin/sc_auth")

    mac_ver_str = platform.mac_ver()[0]
    if mac_ver_str:
        major_ver = int(mac_ver_str.split(".")[0])
        if major_ver < 15:
            raise RuntimeError(
                f"Hardware-backed mTLS via CryptoTokenKit requires macOS 15+. Current version: {mac_ver_str}"
            )

    _tmpdir = tempfile.TemporaryDirectory(prefix="bunker_")
    work_dir = Path(_tmpdir.name)

    try:
        # 0. Clean up stale CTK identities and login keychain certs
        #    from previous runs. Each run creates a new SE key; old
        #    ones are orphaned.
        id_result = subprocess.run(
            ["sc_auth", "identities"],
            check=True,
            capture_output=True,
            text=True,
        )
        for line in id_result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].startswith("bunker-"):
                old_hash = parts[0].strip()
                subprocess.run(
                    ["sc_auth", "delete-ctk-identity", "-h", old_hash],
                    capture_output=True,
                )
                logger.info("    Cleaned up stale CTK identity: %s", parts[1])

        # Also remove stale bunker-workload certs from the login keychain.
        login_kc = _macos_login_keychain()
        find_result = subprocess.run(
            ["security", "find-certificate", "-c", "bunker-workload", "-a", "-Z", login_kc],
            capture_output=True,
            text=True,
        )
        for line in find_result.stdout.splitlines():
            if "SHA-1" in line:
                sha1 = line.split()[-1]
                subprocess.run(
                    ["security", "delete-certificate", "-Z", sha1, login_kc],
                    capture_output=True,
                )

        # 1. Generate Secure Enclave key (+ throwaway self-signed cert)
        subprocess.run(
            [
                "sc_auth",
                "create-ctk-identity",
                "-l",
                config.workload_cn,
                "-N",
                config.workload_cn,
                "-k",
                config.key_algo_config["macos_sc_auth"],
                "-t",
                "none",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("    Secure Enclave key created: %s", config.workload_cn)

        # 2. Look up the key's SHA-1 hash from sc_auth identities.
        #    Retry briefly — the CTK token may need a moment to register
        #    the new identity after creation and stale identity deletion.
        key_hash: str | None = None
        for _attempt in range(5):
            id_result = subprocess.run(
                ["sc_auth", "identities"],
                check=True,
                capture_output=True,
                text=True,
            )
            for line in id_result.stdout.splitlines():
                if config.workload_cn in line:
                    key_hash = line.split()[0]
            if key_hash:
                break
            time.sleep(1)
        if not key_hash:
            raise RuntimeError(
                f"Could not find key hash for '{config.workload_cn}' in sc_auth identities output:\n{id_result.stdout}"
            )
        logger.info("    SE key hash: %s", key_hash)

        # 3. Generate a CSR from the SE key (sc_auth appends .csr to filename)
        csr_basename = str(work_dir / "workload_csr")
        subprocess.run(
            [
                "sc_auth",
                "create-ctk-csr",
                "-h",
                key_hash,
                "-N",
                config.workload_cn,
                "-f",
                csr_basename,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        csr_path = Path(f"{csr_basename}.csr")
        if not csr_path.exists():
            raise FileNotFoundError(f"CSR not found at {csr_path} after sc_auth create-ctk-csr")
        csr_pem = csr_path.read_text().strip()
        logger.info("    CSR generated from SE key.")

        # 4. Ephemeral CA signs the CSR → CA-signed workload cert
        bundle, workload_pem = _create_ca_and_sign(csr_pem, config)

        # 5. Replace the throwaway self-signed cert on the CTK identity
        #    with the CA-signed cert.  This links the cert to the SE key
        #    as a proper identity (visible in "My Certificates").
        workload_cert_path = work_dir / "workload_signed.pem"
        workload_cert_path.write_text(workload_pem)
        subprocess.run(
            [
                "sc_auth",
                "import-ctk-certificate",
                "-f",
                str(workload_cert_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("    CA-signed cert linked to SE key via import-ctk-certificate.")

        # 6. Also import the cert into the login keychain so that ECP's
        #    GetCertPemForPython / SignForPython can find it via
        #    SecItemCopyMatching.  macOS auto-associates login keychain
        #    certs with SE keys that share the same public key hash,
        #    forming a usable SecIdentity for mTLS signing.
        login_kc = _macos_login_keychain()
        subprocess.run(
            [
                "security",
                "import",
                str(workload_cert_path),
                "-k",
                login_kc,
                "-T",
                "/usr/bin/security",
            ],
            capture_output=True,
            text=True,  # Don't check — may warn "already exists"
        )
        logger.info("    Cert also imported into login keychain for ECP.")

        return bundle

    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        cmd_name = e.cmd[0] if isinstance(e.cmd, list) else str(e.cmd)
        if "-25293" in stderr or "errSecAuthFailed" in stderr:
            raise RuntimeError(
                f"Secure Enclave key generation denied (command: {cmd_name}).\n"
                "macOS blocked access to the Secure Enclave.\n"
                "\n"
                "  Possible causes:\n"
                "    - Running in a VM without SE support\n"
                "    - User denied the biometric/passcode prompt\n"
                "\n"
                "  Use --soft-key for software-only keys (no SE required).\n"
                "  NOTE: --soft-key does NOT provide hardware protection."
            ) from e
        raise RuntimeError(
            f"macOS certificate generation failed (command: {cmd_name}, "
            f"exit code: {e.returncode}).\n"
            f"  stderr: {stderr[:500]}"
        ) from e
    finally:
        _tmpdir.cleanup()


def _generate_cert_linux(config: WorkloadConfig) -> CertificateBundle:
    """Generates a TPM 2.0-backed certificate via PKCS#11 toolchain (Ubuntu 24+)."""
    # Pre-validate required commands.
    _require_command("tpm2_ptool", package="tpm2-pkcs11-tools", install_hint="sudo apt install tpm2-pkcs11-tools")
    _require_command("p11tool", package="gnutls-bin", install_hint="sudo apt install gnutls-bin")
    _require_command("pkcs11-tool", package="opensc", install_hint="sudo apt install opensc")
    # Also need certtool from gnutls-bin for CSR generation.
    _require_command("certtool", package="gnutls-bin", install_hint="sudo apt install gnutls-bin")

    # Check TPM availability (unless using software keys).
    if not config.soft_key:
        _check_tpm_linux()

    tpm_store = Path.home() / ".tpm2_pkcs11"
    os.environ["TPM2_PKCS11_STORE"] = str(tpm_store)
    tpm_store.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Initialize TPM PKCS#11 token and generate hardware-backed key
        init_result = subprocess.run(
            ["tpm2_ptool", "init"],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("    tpm2_ptool init: %s", init_result.stdout.strip())

        # Remove existing token if present (reuse flow).
        subprocess.run(
            ["tpm2_ptool", "rmtoken", "--label=bunker-wif"],
            capture_output=True,
            text=True,
        )  # Ignore errors — token may not exist yet.

        token_result = subprocess.run(
            [
                "tpm2_ptool",
                "addtoken",
                "--pid=1",
                f"--sopin={config.linux_tpm_pin}",
                f"--userpin={config.linux_tpm_pin}",
                "--label=bunker-wif",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("    tpm2_ptool addtoken: %s", token_result.stdout.strip())

        key_result = subprocess.run(
            [
                "tpm2_ptool",
                "addkey",
                f"--algorithm={config.key_algo_config['linux_tpm2']}",
                "--label=bunker-wif",
                f"--key-label={config.workload_cn}",
                f"--userpin={config.linux_tpm_pin}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("    tpm2_ptool addkey: %s", key_result.stdout.strip())

        # Verify the token is visible via p11-kit before calling certtool
        try:
            p11_result = subprocess.run(
                ["p11tool", "--list-tokens"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            logger.debug("    p11tool --list-tokens:\n%s", p11_result.stdout)
            if "bunker-wif" not in p11_result.stdout:
                logger.warning("    Token 'bunker-wif' not visible to p11tool!")
                # Try listing via pkcs11-tool as fallback diagnostic
                try:
                    pkcs11_result = subprocess.run(
                        ["pkcs11-tool", "--module", "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so", "-T"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    logger.debug("    pkcs11-tool -T:\n%s", pkcs11_result.stdout)
                except Exception:
                    pass
        except Exception as p11_err:
            logger.debug("    p11tool check failed: %s", p11_err)

        # 2. Generate a temporary self-signed cert to extract the public key
        cert_cfg = f'cn = "{config.workload_cn}"\nexpiration_days = 365\ntls_www_client\n'
        write_secure_file("cert.cfg", cert_cfg)

        # Set GNUTLS_PIN so certtool can access the token without
        # relying solely on pin-value in the PKCS#11 URI.
        os.environ["GNUTLS_PIN"] = config.linux_tpm_pin

        pkcs11_uri = (
            f"pkcs11:token=bunker-wif;object={config.workload_cn};type=private;pin-value={config.linux_tpm_pin}"
        )
        subprocess.run(
            [
                "certtool",
                "--generate-self-signed",
                "--load-privkey",
                pkcs11_uri,
                "--template",
                "cert.cfg",
                "--outfile",
                "bunker-workload-selfsigned.pem",
            ],
            check=True,
            capture_output=True,
        )

        se_pem = Path("bunker-workload-selfsigned.pem").read_text().strip()

        # 3. Create CA-signed workload cert
        bundle, workload_pem = _create_ca_and_sign(se_pem, config)

        # 4. Write the CA-signed cert and import into PKCS#11 store
        #    addcert needs --key-id (CKA_ID from addkey) and prompts for PIN.
        Path("bunker-workload-public.pem").write_text(workload_pem)

        # Extract CKA_ID from addkey output
        key_id = None
        for line in key_result.stdout.splitlines():
            if "CKA_ID" in line and key_id is None:
                key_id = line.split("'")[1] if "'" in line else line.split()[-1]
        if not key_id:
            raise RuntimeError("Could not extract CKA_ID from tpm2_ptool addkey output: " + key_result.stdout)
        logger.debug("    Using CKA_ID: %s", key_id)

        subprocess.run(
            [
                "tpm2_ptool",
                "addcert",
                "--label=bunker-wif",
                f"--key-id={key_id}",
                "bunker-workload-public.pem",
            ],
            input=config.linux_tpm_pin + "\n",
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("    CA-signed workload cert imported into TPM PKCS#11 store.")

        return bundle

    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        cmd_name = e.cmd[0] if isinstance(e.cmd, list) else str(e.cmd)
        # Parse known error patterns for actionable guidance.
        if "Could not load tcti" in stderr or "No standard TCTI" in stderr:
            raise RuntimeError(
                f"TPM communication failed (command: {cmd_name}).\n"
                "The TPM tools are installed but cannot connect to a TPM device.\n"
                "\n"
                "  Options:\n"
                "    1. Start the TPM resource manager:\n"
                "         sudo systemctl start tpm2-abrmd\n"
                "\n"
                "    2. For development, start a software TPM:\n"
                "         swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 "
                "--server type=tcp,port=2321 --ctrl type=tcp,port=2322 &\n"
                "         export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'\n"
                "\n"
                "    3. Use --soft-key for software-only keys (no TPM required).\n"
                "       NOTE: --soft-key does NOT provide hardware TPM protection.\n"
                "       Keys are stored in software and are exportable."
            ) from e
        if "timed out" in stderr and "Tabrmd" in stderr:
            raise RuntimeError(
                f"tpm2-abrmd service timed out (command: {cmd_name}).\n"
                "The TPM resource manager service is installed but not responding.\n"
                "\n"
                "  Try: sudo systemctl restart tpm2-abrmd\n"
                "\n"
                "  If using a software TPM, set the TCTI environment variable:\n"
                "    export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'"
            ) from e
        if "/dev/tpmrm0" in stderr or "/dev/tpm0" in stderr:
            raise RuntimeError(
                f"No TPM device found (command: {cmd_name}).\n"
                "The system does not have /dev/tpmrm0 or /dev/tpm0.\n"
                "\n"
                "  Use --soft-key for software-only keys (no TPM required).\n"
                "  NOTE: --soft-key does NOT provide hardware TPM protection."
            ) from e
        # Fallback: include the raw error with the failing command.
        raise RuntimeError(
            f"Linux TPM operation failed (command: {cmd_name}, "
            f"exit code: {e.returncode}).\n"
            f"  stderr: {stderr[:500]}\n"
            "\n"
            "  Ensure tpm2-pkcs11-tools and gnutls-bin are installed:\n"
            "    sudo apt install tpm2-pkcs11-tools gnutls-bin opensc"
        ) from e


# --- ECP Binary Resolution ---


def _find_ecp_binaries() -> tuple[Path, Path, Path]:
    """Locates pre-installed ECP binaries.

    Search order:
      1. Bundled alongside the wif-bunker binary (<binary_dir>/ecp/)
      2. Default platform location (~/.config/bunker-ecp or %LOCALAPPDATA%\\Google\\ECP)

    Returns:
        (ecp_binary, ecp_client_lib, tls_offload_lib) paths.

    Raises:
        FileNotFoundError: if ECP binaries are not found in any location.
    """
    ecp_bin_name, libecp_name, tls_offload_name = get_ecp_binary_names()

    # Determine the directory containing the wif-bunker binary.
    if getattr(sys, "frozen", False):
        binary_dir = Path(sys.executable).parent
    else:
        binary_dir = Path(__file__).parent

    # Search locations in priority order.
    search_dirs = [
        binary_dir / "ecp",  # Bundled alongside binary
        get_default_ecp_dir(),  # Platform default
    ]

    for ecp_dir in search_dirs:
        ecp_bin = ecp_dir / ecp_bin_name
        client = ecp_dir / libecp_name
        offload = ecp_dir / tls_offload_name
        if ecp_bin.exists() and client.exists() and offload.exists():
            logger.info("    Using ECP binaries from %s", ecp_dir)
            _add_ecp_to_path(ecp_dir)
            return ecp_bin, client, offload

    raise FileNotFoundError(
        "ECP binaries not found. Install them with:\n"
        "    python get_ecp.py\n"
        "\n"
        f"Searched: {[str(d) for d in search_dirs]}"
    )


def _add_ecp_to_path(ecp_dir: Path) -> None:
    """Ensures the ECP binary directory is discoverable for DLL loading."""
    ecp_dir_str = str(ecp_dir)

    # os.add_dll_directory() is the ONLY mechanism that works on
    # Python 3.8+ for DLL dependency resolution on Windows.
    if sys.platform == "win32" and ecp_dir.is_dir():
        os.add_dll_directory(ecp_dir_str)

    # Also add to PATH for the current process.
    current_path = os.environ.get("PATH", "")
    if ecp_dir_str not in current_path:
        os.environ["PATH"] = ecp_dir_str + os.pathsep + current_path


_KEYSTORE_GENERATORS: dict[str, Callable[[WorkloadConfig], CertificateBundle]] = {
    "win32": _generate_cert_windows,
    "darwin": _generate_cert_macos,
    "linux": _generate_cert_linux,
}


def generate_os_keystore_cert(config: WorkloadConfig) -> CertificateBundle:
    """Dispatches to the platform-specific hardware keystore generator.

    Each generator:
      1. Creates a hardware-backed key (SE/TPM)
      2. Generates an ephemeral CA (software, in-memory)
      3. Signs a workload cert with the CA (same public key as the HW key)
      4. Installs the CA-signed cert back into the OS keystore
      5. Returns the CA cert PEM (trust anchor) + CA CN (for ECP config)
    """
    logger.info("Instructing OS to generate non-exportable hardware-backed certificate...")
    for platform_prefix, generator in _KEYSTORE_GENERATORS.items():
        if sys.platform.startswith(platform_prefix):
            return generator(config)
    raise OSError(f"Unsupported Operating System: {sys.platform}")


# --- Core Workflow ---
def main() -> None:
    parser = argparse.ArgumentParser(
        description="WIF Bunker — Hardware-backed X.509 Workload Identity Federation",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--debug", action="store_true")
    project_group = parser.add_mutually_exclusive_group()
    project_group.add_argument(
        "--use-project",
        metavar="PROJECT_ID",
        help="Reuse an existing GCP project (skip creation & API enablement)",
    )
    project_group.add_argument(
        "--create-project",
        metavar="PROJECT_ID",
        help="Create a new GCP project with this ID",
    )
    sa_group = parser.add_mutually_exclusive_group()
    sa_group.add_argument(
        "--use-service-account",
        metavar="SA_EMAIL",
        help="Reuse an existing service account email (skip SA creation)",
    )
    sa_group.add_argument(
        "--create-service-account",
        metavar="SA_NAME",
        help="Create service account with this name",
    )
    sa_group.add_argument(
        "--no-service-account",
        action="store_true",
        help=(
            "Skip service account creation — WIF credentials authenticate "
            "directly without SA impersonation.  IAM roles must be granted "
            "to the WIF principal directly."
        ),
    )
    pool_group = parser.add_mutually_exclusive_group()
    pool_group.add_argument(
        "--use-pool",
        metavar="POOL_ID",
        help="Reuse an existing WIF pool ID (skip pool creation)",
    )
    pool_group.add_argument(
        "--create-pool",
        metavar="POOL_ID",
        help="Create WIF pool with this ID",
    )
    algo_choices = list(_KEY_ALGORITHMS.keys())
    algo_help_lines = [f"{k}: {v['desc']}" for k, v in _KEY_ALGORITHMS.items()]
    parser.add_argument(
        "--key-algorithm",
        choices=algo_choices,
        default="es256",
        metavar="ALGO",
        help=(
            "Key algorithm for the hardware-backed certificate. "
            "Choices: " + ", ".join(algo_help_lines) + ". "
            "macOS supports es256/es384 only. Default: es256."
        ),
    )
    parser.add_argument(
        "--client-secrets-file",
        metavar="FILE",
        help=(
            "Path to a Google OAuth client_secrets.json file "
            "(Desktop app type).  Create one at: "
            "https://console.cloud.google.com/apis/credentials"
        ),
    )
    parser.add_argument(
        "--soft-key",
        action="store_true",
        help=(
            "Use software keys instead of hardware-backed keys (for CI testing without a TPM).  NOT for production use."
        ),
    )
    parser.add_argument(
        "--use-adc",
        action="store_true",
        help=(
            "Use Application Default Credentials instead of browser-based "
            "OAuth.  For CI/CD environments where "
            "GOOGLE_APPLICATION_CREDENTIALS is already set "
            "(e.g. via google-github-actions/auth)."
        ),
    )
    parser.add_argument(
        "--folder",
        metavar="FOLDER_ID",
        help=(
            "GCP folder ID to create the project in.  "
            "Only used when creating a new project (e.g. with --create-project)."
        ),
    )

    args = parser.parse_args()

    if args.use_adc and args.client_secrets_file:
        parser.error("--use-adc and --client-secrets-file are mutually exclusive")

    handler = logging.StreamHandler()
    handler.setFormatter(_CleanFormatter())
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        handlers=[handler],
    )

    config = WorkloadConfig()
    # Override config from CLI flags
    if args.use_project:
        config.project_id = args.use_project
    elif args.create_project:
        config.project_id = args.create_project
    if args.use_pool:
        config.pool_id = args.use_pool
    elif args.create_pool:
        config.pool_id = args.create_pool
    if args.soft_key:
        config.soft_key = True

    if args.key_algorithm:
        algo_info = _KEY_ALGORITHMS[args.key_algorithm]
        # Validate algorithm is supported on this platform.
        platform_ok = any(sys.platform.startswith(p) for p in algo_info["platforms"])
        if not platform_ok:
            supported = [
                k for k, v in _KEY_ALGORITHMS.items() if any(sys.platform.startswith(p) for p in v["platforms"])
            ]
            parser.error(
                f"Algorithm '{args.key_algorithm}' is not supported on "
                f"{sys.platform}. Supported: {', '.join(supported)}"
            )
        config.key_algorithm = args.key_algorithm

    with GCPClient(
        use_adc=args.use_adc,
        client_secrets_file=args.client_secrets_file,
    ) as client:
        crm_base = "cloudresourcemanager.googleapis.com"
        su_base = "serviceusage.googleapis.com"
        iam_base = "iam.googleapis.com"

        # --- Step 1: Create GCP Project (or reuse) ---
        if args.use_project:
            logger.info("=== 1) Using existing project: %s ===", config.project_id)
            project_number = client.api_call(
                "GET",
                f"https://{crm_base}/v1/projects/{config.project_id}",
            )["projectNumber"]
            logger.info("    Project number: %s", project_number)
        else:
            logger.info("=== 1) Creating GCP Project (%s) ===", config.project_id)
            create_payload = {
                "projectId": config.project_id,
                "name": "WIF Bunker",
            }
            if args.folder:
                create_payload["parent"] = {
                    "type": "folder",
                    "id": args.folder,
                }
                logger.info("    Parent folder: %s", args.folder)
            op = client.api_call(
                "POST",
                f"https://{crm_base}/v1/projects",
                create_payload,
            )
            client.wait_for_lro(crm_base, op["name"])
            project_number = client.api_call(
                "GET",
                f"https://{crm_base}/v1/projects/{config.project_id}",
            )["projectNumber"]

            # --- Step 2: Enable APIs ---
            logger.info("=== 2) Configuring APIs ===")
            required_apis = [
                "iam.googleapis.com",
                "sts.googleapis.com",
                "iamcredentials.googleapis.com",
                "cloudresourcemanager.googleapis.com",
            ]
            op = client.api_call(
                "POST",
                f"https://{su_base}/v1/projects/{project_number}/services:batchEnable",
                {"serviceIds": required_apis},
            )
            client.wait_for_lro(su_base, op["name"])

        # --- Step 3: Generate Hardware-Backed Certificate ---
        logger.info("=== 3) Generating Hardware-Backed Certificate ===")
        cert_bundle = generate_os_keystore_cert(config)

        # --- Step 4: SA + WIF Creation (or reuse) ---
        use_sa = not args.no_service_account
        sa_email = args.use_service_account  # None if not provided
        if args.create_service_account:
            config.sa_name = args.create_service_account
        reuse_pool = bool(args.use_pool)

        logger.info("=== 4) Initializing SA & WIF Infrastructure ===")

        pool_res_url = (
            f"https://{iam_base}/v1/projects/{project_number}/locations/global/workloadIdentityPools/{config.pool_id}"
        )
        provider_res_url = f"{pool_res_url}/providers/{config.provider_id}"

        def create_sa_task() -> str:
            logger.info("[Thread] Creating Service Account...")
            try:
                result = client.api_call(
                    "POST",
                    f"https://{iam_base}/v1/projects/{config.project_id}/serviceAccounts",
                    {
                        "accountId": config.sa_name,
                        "serviceAccount": {"displayName": "WIF Bunker SA"},
                    },
                )
                return result["email"]
            except Exception as e:
                if "409" in str(e) or "ALREADY_EXISTS" in str(e):
                    email = f"{config.sa_name}@{config.project_id}.iam.gserviceaccount.com"
                    logger.info("    SA already exists: %s", email)
                    return email
                raise

        def create_pool_task() -> None:
            logger.info("[Thread] Creating WIF Pool...")
            try:
                pool_op = client.api_call(
                    "POST",
                    f"https://{iam_base}/v1/projects/{project_number}"
                    f"/locations/global/workloadIdentityPools"
                    f"?workloadIdentityPoolId={config.pool_id}",
                    {"displayName": "WIF Bunker Pool", "disabled": False},
                )
                client.wait_for_lro(iam_base, pool_op["name"])
            except Exception as e:
                if "409" in str(e) or "ALREADY_EXISTS" in str(e):
                    logger.info("    Pool already exists: %s", config.pool_id)
                else:
                    raise
            client.wait_for_wif_resource(pool_res_url)

        def create_provider_task() -> None:
            # Clean up stale providers from previous runs to avoid
            # hitting the 200-provider-per-pool limit.
            if reuse_pool:
                try:
                    provs = client.api_call(
                        "GET",
                        f"{pool_res_url}/providers",
                    ).get("workloadIdentityPoolProviders", [])
                    for p in provs:
                        pname = p["name"].split("/")[-1]
                        if pname.startswith("bunker-x509-prov-") and pname != config.provider_id:
                            logger.info("    Deleting stale provider: %s", pname)
                            try:
                                del_op = client.api_call("DELETE", f"{pool_res_url}/providers/{pname}")
                                client.wait_for_lro(iam_base, del_op["name"])
                            except Exception:
                                pass
                except Exception:
                    pass  # List failed — not critical

            # Create X.509 provider with CA cert as trust anchor.
            # attributeCondition pins the provider to the EXACT leaf cert
            # via SHA-256 fingerprint.  The fingerprint covers the entire
            # DER-encoded cert (subject, key, serial, etc.) so even a
            # compromised CA key cannot produce a second accepted cert.
            cert_pin_condition = f'assertion.sha256Fingerprint == "{cert_bundle.sha256_fingerprint}"'
            logger.info("    Cert pin condition: %s", cert_pin_condition)
            provider_payload = {
                "displayName": "WIF Bunker X.509 Provider",
                "x509": {
                    "trustStore": {
                        "trustAnchors": [
                            {"pemCertificate": cert_bundle.trust_anchor_pem},
                        ],
                    },
                },
                "attributeMapping": {"google.subject": "assertion.subject.dn.cn"},
                "attributeCondition": cert_pin_condition,
            }

            if reuse_pool:
                logger.info("[Thread] Reusing WIF pool: %s", config.pool_id)

            logger.info("[Thread] Creating WIF X.509 Provider: %s", config.provider_id)
            prov_op = client.api_call(
                "POST",
                f"{pool_res_url}/providers?workloadIdentityPoolProviderId={config.provider_id}",
                provider_payload,
            )
            client.wait_for_lro(iam_base, prov_op["name"])
            client.wait_for_wif_resource(provider_res_url)

        # Submit needed tasks in parallel.
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            if use_sa and not sa_email:
                futures.append(("sa", executor.submit(create_sa_task)))
            if not reuse_pool:
                futures.append(("pool", executor.submit(create_pool_task)))
            for tag, fut in futures:
                result = fut.result()
                if tag == "sa":
                    sa_email = result

        # Provider must be created after pool exists.
        create_provider_task()

        # --- Step 5: IAM Bindings ---
        logger.info("=== 5) Applying IAM Bindings ===")
        wif_principal = (
            f"principal://iam.googleapis.com/projects/{project_number}"
            f"/locations/global/workloadIdentityPools/{config.pool_id}"
            f"/subject/{config.workload_cn}"
        )

        if use_sa:
            # SA-level binding: allow WIF principal to impersonate the SA.
            sa_iam_url = f"https://{iam_base}/v1/projects/{config.project_id}/serviceAccounts/{sa_email}:setIamPolicy"
            sa_policy = client.api_call(
                "POST",
                sa_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
            )
            sa_policy.setdefault("bindings", []).append(
                {"role": "roles/iam.workloadIdentityUser", "members": [wif_principal]},
            )
            client.api_call("POST", sa_iam_url, {"policy": sa_policy})

        # Project-level binding: grant to SA (impersonation mode) or
        # directly to the WIF principal (no-SA mode).
        proj_iam_url = f"https://{crm_base}/v1/projects/{config.project_id}:setIamPolicy"
        proj_policy = client.api_call(
            "POST",
            proj_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
        )
        if use_sa:
            proj_member = f"serviceAccount:{sa_email}"
        else:
            proj_member = wif_principal
        proj_policy.setdefault("bindings", []).append(
            {"role": "roles/browser", "members": [proj_member]},
        )
        client.api_call("POST", proj_iam_url, {"policy": proj_policy})

        # --- Step 6: ECP & ADC Config Generation ---
        logger.info("=== 6) Generating ECP Certificate Config & ADC ===")

        try:
            ecp_binary, ecp_client_lib, tls_offload_lib = _find_ecp_binaries()
        except FileNotFoundError as ecp_err:
            github_os, arch, _, _ = get_ecp_platform_info()
            logger.warning(
                "    ECP binaries not available for %s/%s — skipping ECP config and auth demo (steps 6-7).",
                github_os,
                arch,
            )
            logger.warning("    %s", ecp_err)
            logger.info("=== Steps 1-5 completed successfully. ===")
            logger.info("WIF Bunker setup is complete. ECP auth demo requires a platform with ECP support.")
            return

        # Build ECP certificate_config.json — the format google-auth's
        # _custom_tls_signer.py expects.  The "libs" section tells it where
        # to find the C-shared libraries that perform hardware-backed signing.
        # The "cert_configs" section tells ECP which keystore + issuer to use
        # when locating the client certificate for the mTLS handshake.
        if sys.platform == "win32":
            cert_configs: dict = {
                "windows_store": {
                    "store": "MY",
                    "provider": "current_user",
                    "issuer": cert_bundle.issuer_cn,
                },
            }
        elif sys.platform == "darwin":
            cert_configs = {
                "macos_keychain": {
                    "issuer": cert_bundle.issuer_cn,
                },
            }
        else:
            # Find the PKCS#11 module path dynamically.
            pkcs11_module = None
            for candidate in [
                "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
                "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
                "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
                "/usr/lib/aarch64-linux-gnu/libtpm2_pkcs11.so.1",
                "/usr/lib/pkcs11/libtpm2_pkcs11.so",
            ]:
                if Path(candidate).exists():
                    pkcs11_module = candidate
                    break
            if not pkcs11_module:
                raise FileNotFoundError("Could not find libtpm2_pkcs11.so. Install libtpm2-pkcs11-1.")

            # Discover the PKCS#11 slot ID for our token.
            # ECP requires a numeric slot — doesn't support token_label.
            slot_id = None
            try:
                slot_result = subprocess.run(
                    ["pkcs11-tool", "--module", pkcs11_module, "--list-token-slots"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                logger.debug("    pkcs11-tool slots:\n%s", slot_result.stdout)
                # Parse output like:
                #   Slot 0 (0x1): bunker-wif
                #     token label : bunker-wif
                # The label may appear on the Slot line itself.

                last_slot_hex = None
                for line in slot_result.stdout.splitlines():
                    slot_match = re.search(r"Slot\s+\d+\s+\(0x([0-9a-fA-F]+)\)", line)
                    if slot_match:
                        last_slot_hex = slot_match.group(1)
                    if "bunker-wif" in line and last_slot_hex:
                        slot_id = last_slot_hex
                        break
            except Exception as e:
                logger.debug("    pkcs11-tool slot discovery failed: %s", e)

            # Fallback: try slot 1 (slot 0 is typically p11-kit trust)
            if slot_id is None:
                slot_id = "1"
                logger.warning("    Could not discover PKCS#11 slot ID, defaulting to slot %s", slot_id)

            logger.info("    Using PKCS#11 slot: 0x%s", slot_id)

            cert_configs = {
                "pkcs11": {
                    "module": pkcs11_module,
                    "slot": slot_id,
                    "label": config.workload_cn,
                    "user_pin": config.linux_tpm_pin,
                },
            }

        # Write PEM files to disk.
        workload_cert_path = Path.cwd() / "workload_cert.pem"
        trust_chain_path = Path.cwd() / "trust_chain.pem"
        write_secure_file(workload_cert_path, cert_bundle.workload_cert_pem)
        write_secure_file(trust_chain_path, cert_bundle.trust_anchor_pem)
        logger.info("    Workload cert PEM written: %s", workload_cert_path)
        logger.info("    Trust chain PEM written:   %s", trust_chain_path)

        # The "workload" section provides cert_path only (no key_path)
        # because the private key is in the Secure Enclave / TPM.
        # - cert_path: google-auth reads this for the STS subject token
        # - key_path absent: the forked google-auth (jay0lee) tolerates
        #   missing key_path and skips cert=(cert, key) injection
        # - ECP handles mTLS signing via configure_mtls_channel()
        cert_configs["workload"] = {"cert_path": str(workload_cert_path)}
        certificate_config = {
            "version": 1,
            "cert_configs": cert_configs,
            "libs": {
                "ecp": str(ecp_binary),
                "ecp_client": str(ecp_client_lib),
                "tls_offload": str(tls_offload_lib),
            },
        }
        cert_config_path = Path.cwd() / "certificate_config.json"
        write_secure_file(
            cert_config_path,
            json.dumps(certificate_config, indent=2),
        )
        logger.info("    ECP certificate_config.json written: %s", cert_config_path)

        # ADC config — points google-auth at the STS mTLS endpoint and
        # references the ECP certificate config for the mTLS channel.
        adc_config = {
            "type": "external_account",
            "audience": (
                f"//iam.googleapis.com/projects/{project_number}"
                f"/locations/global/workloadIdentityPools/{config.pool_id}"
                f"/providers/{config.provider_id}"
            ),
            "subject_token_type": "urn:ietf:params:oauth:token-type:mtls",
            "token_url": "https://sts.mtls.googleapis.com/v1/token",
            "credential_source": {
                "certificate": {
                    "use_default_certificate_config": "true",
                    "trust_chain_path": str(trust_chain_path),
                },
            },
        }
        if use_sa:
            adc_config["service_account_impersonation_url"] = (
                f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken"
            )
        adc_path = Path.cwd() / "adc.json"
        write_secure_file(adc_path, json.dumps(adc_config, indent=2))

        logger.info("=" * 70)
        logger.info("ECP & ADC Configuration Complete!")
        logger.info("Set these environment variables to use ADC:")
        env_vars = {
            "GOOGLE_APPLICATION_CREDENTIALS": str(adc_path),
            "GOOGLE_API_USE_CLIENT_CERTIFICATE": "true",
            "GOOGLE_API_CERTIFICATE_CONFIG": str(cert_config_path),
        }
        if sys.platform == "win32":
            logger.info("  PowerShell:")
            for k, v in env_vars.items():
                logger.info('    $env:%s="%s"', k, v)
            logger.info("  cmd.exe:")
            for k, v in env_vars.items():
                logger.info("    set %s=%s", k, v)
        else:
            for k, v in env_vars.items():
                logger.info("  export %s=%s", k, v)
        logger.info("=" * 70)
        reuse_parts = [
            f"python3 {sys.argv[0]}",
            f"--use-project {config.project_id}",
            f"--use-pool {config.pool_id}",
        ]
        if use_sa and sa_email:
            reuse_parts.append(f"--use-service-account {sa_email}")
        elif not use_sa:
            reuse_parts.append("--no-service-account")
        logger.info("To re-run with existing infrastructure:")
        logger.info("  %s", " ".join(reuse_parts))

        # --- Step 7: Full ADC Auth Flow Demo (ECP-backed mTLS) ---

        def _run_ecp_diagnostics(config_path, log):
            """Deep ECP diagnostics (only called with --debug when cert_len=0)."""
            log.warning("    Running ECP diagnostics (--debug)...")
            try:
                with open(config_path) as _f:
                    _cfg_text = _f.read()
                log.warning("    certificate_config.json:\n%s", _cfg_text)
            except Exception as _e:
                log.warning("    Could not read config: %s", _e)
                return

            # Check if ECP signer binary has Secure Enclave support
            try:
                _ecp_bin = Path(json.loads(_cfg_text)["libs"]["ecp"])
                if _ecp_bin.exists():
                    _bin_data = _ecp_bin.read_bytes()
                    log.warning("    ECP binary: %s (%d KB)", _ecp_bin, len(_bin_data) // 1024)
                    if sys.platform == "darwin":
                        log.warning(
                            "    Contains SecCertificateCopyData (patched): %s", b"SecCertificateCopyData" in _bin_data
                        )
                        log.warning("    Contains SecItemExport (unpatched): %s", b"SecItemExport" in _bin_data)
                else:
                    log.warning("    ECP binary NOT FOUND: %s", _ecp_bin)
            except Exception as _e:
                log.warning("    Binary check error: %s", _e)

            # Run signer binary directly to capture its stderr
            try:
                _ecp_bin_path = str(Path(json.loads(_cfg_text)["libs"]["ecp"]))
                _result = subprocess.run(
                    [_ecp_bin_path, str(config_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                log.warning("    ECP signer stderr: %s", _result.stderr[:500] if _result.stderr else "(empty)")
            except subprocess.TimeoutExpired:
                log.warning("    ECP signer listening for RPC (OK)")
            except Exception as _e:
                log.warning("    ECP signer error: %s", _e)

            # Check keychain identities (macOS)
            if sys.platform == "darwin":
                try:
                    _id_result = subprocess.run(
                        ["security", "find-identity", "-v", "-p", "ssl-client"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    log.warning("    Keychain SSL-client identities:\n%s", _id_result.stdout)
                except Exception as _e:
                    log.warning("    find-identity error: %s", _e)

        # Set environment so google-auth discovers our configs.
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(adc_path)
        os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "true"
        os.environ["GOOGLE_API_CERTIFICATE_CONFIG"] = str(cert_config_path)

        if args.debug:
            os.environ["ENABLE_ENTERPRISE_CERTIFICATE_LOGS"] = "1"

        # Pre-load ECP DLLs on Windows.
        if sys.platform == "win32":
            for lib in (ecp_client_lib, tls_offload_lib):
                try:
                    ctypes.WinDLL(str(lib))
                except OSError:
                    pass

        # ── ECP Certificate Retrieval ──
        # Quick validation that ECP can find and return the cert before
        # attempting the full mTLS handshake.
        logger.info("=== 7a) ECP Certificate Retrieval ===")

        try:
            _ecp_lib = ctypes.CDLL(str(ecp_client_lib))
            _ecp_lib.GetCertPemForPython.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_int,
            ]
            _ecp_lib.GetCertPemForPython.restype = ctypes.c_int

            # First call with buf=NULL to get required size.
            _cert_len = _ecp_lib.GetCertPemForPython(
                str(cert_config_path).encode(),
                None,
                0,
            )
            if _cert_len <= 0:
                logger.error("    FAIL: ECP returned cert_len=%d", _cert_len)
                if args.debug:
                    _run_ecp_diagnostics(cert_config_path, logger)
                raise RuntimeError("ECP cert retrieval failed (cert_len=0)")

            # Second call to retrieve the actual PEM.
            _cert_buf = ctypes.create_string_buffer(_cert_len + 1)
            _ecp_lib.GetCertPemForPython(
                str(cert_config_path).encode(),
                _cert_buf,
                _cert_len + 1,
            )
            _cert_pem_bytes = _cert_buf.value
            _cert_pem = _cert_pem_bytes.decode("utf-8", errors="replace")
            logger.info("    PASS: ECP returned %d bytes of cert PEM", _cert_len)

            # Parse and show cert details.
            try:
                _parsed = cx509.load_pem_x509_certificate(_cert_pem_bytes)
                _pub_key = _parsed.public_key()
                _key_type = type(_pub_key).__name__
                logger.info("    Cert subject:   %s", _parsed.subject)
                logger.info("    Cert issuer:    %s", _parsed.issuer)
                logger.info("    Key algorithm:  %s", _key_type)
                logger.info("    Cert serial:    %s", format(_parsed.serial_number, "X"))
            except Exception as _parse_err:
                logger.warning("    Could not parse cert: %s", _parse_err)

            logger.debug("    ECP cert PEM:\n%s", _cert_pem)

        except Exception:
            logger.exception("ECP cert retrieval failed")
            sys.exit(1)

        # ── ADC Verification (always runs) ──
        # End-to-end proof: TPM key → ECP → mTLS → Google STS → API call.
        logger.info("=== 7) ADC Verification ===")

        try:
            mtls_session = requests.Session()
            mtls_adapter = _MutualTlsOffloadAdapter(str(cert_config_path))
            mtls_session.mount("https://", mtls_adapter)
            mtls_request = GoogleAuthRequest(session=mtls_session)

            # Allow IAM bindings to propagate before attempting auth.
            logger.info("    Waiting 15s for IAM propagation...")
            time.sleep(15)

            @with_retries(
                max_attempts=10,
                retryable_exceptions=(RefreshError, OAuthError, TypeError),
                retry_msg="Waiting for STS propagation",
            )
            def _verify_adc():
                adc_creds, _ = google_auth_default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                    request=mtls_request,
                )
                adc_creds.refresh(mtls_request)
                api_headers = {}
                adc_creds.apply(api_headers)
                target_api_res = mtls_session.get(
                    f"https://{crm_base}/v1/projects/{config.project_id}",
                    headers=api_headers,
                )
                target_api_res.raise_for_status()
                return target_api_res.json()

            proj_result = _verify_adc()
            logger.info(f"{SYM_OK} API Call Successful! The OS signed the handshake via ECP.")
            if use_sa:
                logger.info("   Authenticated SA: %s", sa_email)
            logger.info("   Target Project:   %s", proj_result.get("name"))

            # ── "Who am I?" via the 403 trick ──
            # Request a non-existent project. GCP's IAM returns a 403
            # whose error message contains the exact principal string.
            try:
                adc_creds, _ = google_auth_default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                    request=mtls_request,
                )
                adc_creds.refresh(mtls_request)
                whoami_headers = {}
                adc_creds.apply(whoami_headers)
                whoami_res = mtls_session.get(
                    f"https://{crm_base}/v1/projects/wif-bunker-whoami-00000",
                    headers=whoami_headers,
                )
                if whoami_res.status_code == 403:
                    error_msg = whoami_res.json().get("error", {}).get("message", "")
                    match = re.search(r"principal://\S+", error_msg)
                    if match:
                        principal = match.group(0).rstrip(".")
                        logger.info("   Principal:        %s", principal)
                    else:
                        logger.debug("   Could not parse principal from 403: %s", error_msg)
            except Exception:
                logger.debug("   Principal identity check skipped", exc_info=True)
        except Exception:
            logger.exception("ADC verification failed")
            logger.error(
                "%s Re-run with --debug for detailed ECP and TLS offload diagnostics.",
                SYM_FAIL,
            )
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.HTTPError as e:
        # Clean exit on HTTP errors — show API response, no traceback.
        status = e.response.status_code if e.response is not None else "?"
        body = e.response.text if e.response is not None else str(e)
        logger.error(
            "%s GCP API call failed (HTTP %s).\n%s",
            SYM_FAIL,
            status,
            body,
        )
        sys.exit(1)
    except RuntimeError as e:
        logger.error("%s %s", SYM_FAIL, e)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nInterrupted.")
        sys.exit(130)
