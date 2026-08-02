#!/usr/bin/env python3
"""
WIF Bunker — Hardware-backed X.509 Workload Identity Federation (ADC)
100% Hardware-Backed (TPM 2.0 / Secure Enclave) Zero-Disk Implementation
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import os
import sys
import time
import json
import shutil
import argparse
import logging
import platform
import subprocess
import threading
import concurrent.futures
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Callable

import requests
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from google.auth.exceptions import RefreshError, OAuthError

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
SYM_OK = "\u2705" if _UNICODE else "[OK]"       # ✅
SYM_WARN = "\u26a0" if _UNICODE else "[!]"      # ⚠
SYM_FAIL = "\u274c" if _UNICODE else "[X]"       # ❌
SYM_ARROW = "\u2192" if _UNICODE else "->"       # →

# --- Tuning Constants ---
MAX_BACKOFF_SECONDS = 60
LRO_TIMEOUT_SECONDS = 300


# --- Key Algorithm Definitions ---
# Maps user-facing algorithm names to platform-specific parameters.
# Each entry: (description, supported_platforms)
_KEY_ALGORITHMS: dict[str, dict] = {
    "es256": {
        "desc": "ECDSA P-256 (default, fastest)",
        "platforms": {"darwin", "win32", "linux"},
        "macos_sc_auth": "p-256-ne",        # sc_auth -k flag
        "windows_certreq": "ECDSA_P256",     # certreq INF KeyAlgorithm
        "linux_tpm2": "ecc256",              # tpm2_ptool --algorithm
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
    max_attempts: int = 10,
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
                        sleep_time = min(2 ** attempt, MAX_BACKOFF_SECONDS)
                        logger.info(
                            "    %s (%d/%d), %ds...",
                            retry_msg, attempt + 1, max_attempts, sleep_time,
                        )
                        time.sleep(sleep_time)
                        continue
                    raise
                except requests.exceptions.HTTPError as e:
                    status = e.response.status_code
                    body = e.response.text
                    is_expected_status = status in expected_errors
                    is_custom_error = (
                        custom_error_text and custom_error_text in body
                    )
                    if (
                        (is_expected_status or is_custom_error)
                        and attempt < max_attempts - 1
                    ):
                        sleep_time = min(2 ** attempt, MAX_BACKOFF_SECONDS)
                        logger.info(
                            "    %s (%d/%d), %ds...",
                            retry_msg, attempt + 1, max_attempts, sleep_time,
                        )
                        time.sleep(sleep_time)
                        continue
                    # Final attempt or unexpected error — log full detail.
                    logger.error(
                        "HTTP %d from %s FAILED after %d attempts — %s",
                        status, func.__name__, attempt + 1, body,
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
    _OAUTH_SCOPES = [
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
            import google.auth
            import google.auth.transport.requests
            self._credentials, _ = google.auth.default(
                scopes=self._OAUTH_SCOPES,
            )
            self._auth_request = google.auth.transport.requests.Request()
            self._credentials.refresh(self._auth_request)
            self._token = None
            # Log the identity we're authenticated as.
            identity = getattr(self._credentials, "service_account_email", None) \
                or getattr(self._credentials, "signer_email", None)
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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.session.close()
        return False

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
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
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
                    b"<h2>Authorization complete.</h2>"
                    b"<p>You may close this window and return to the terminal.</p>"
                )

            def log_message(self_handler, *args):
                pass  # Suppress request logging.

        server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        port = server.server_address[1]
        redirect_uri = f"http://localhost:{port}"

        # Build the authorization URL with PKCE.
        auth_params = urllib.parse.urlencode({
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self._OAUTH_SCOPES),
            "state": state,
            "access_type": "online",  # No refresh token.
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        })
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
        logger.info("    Authenticated successfully (token expires in %ss).",
                     token_data.get("expires_in", "?"))
        return access_token

    def __enter__(self) -> GCPClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.session.close()

    @with_retries(max_attempts=10, expected_errors=(403, 404))
    def api_call(
        self, method: str, url: str, json_payload: dict | None = None,
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
        raise TimeoutError(
            f"LRO {op_name} did not complete within {timeout}s"
        )

    def wait_for_wif_resource(self, url: str, max_attempts: int = 12) -> dict:
        """Polls a WIF resource until it reaches ACTIVE state."""
        for attempt in range(max_attempts):
            data = self.api_call("GET", url)
            if data and data.get("state") == "ACTIVE":
                return data
            sleep_time = min(2 ** attempt, MAX_BACKOFF_SECONDS)
            logger.debug(
                "WIF resource not ACTIVE yet (attempt %d/%d), sleeping %ds",
                attempt + 1, max_attempts, sleep_time,
            )
            time.sleep(sleep_time)
        raise TimeoutError(
            f"WIF resource at {url} did not become ACTIVE "
            f"within {max_attempts} attempts"
        )


# --- Ephemeral CA & Workload Certificate Signing ---
def _create_ca_and_sign(
    hw_public_key_pem: str, config: WorkloadConfig,
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
    ca_name = cx509.Name([
        cx509.NameAttribute(NameOID.COMMON_NAME, config.ca_cn),
        cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "WIF Bunker"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        cx509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=390))  # WIF max
        .add_extension(
            cx509.BasicConstraints(ca=True, path_length=0), critical=True,
        )
        .add_extension(
            cx509.KeyUsage(
                digital_signature=False, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    logger.info("    Ephemeral CA generated: CN=%s", config.ca_cn)

    # --- Sign workload cert with the CA ---
    workload_name = cx509.Name([
        cx509.NameAttribute(NameOID.COMMON_NAME, config.workload_cn),
    ])
    workload_cert = (
        cx509.CertificateBuilder()
        .subject_name(workload_name)
        .issuer_name(ca_name)
        .public_key(workload_pub_key)
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=390))  # WIF max
        .add_extension(
            cx509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            cx509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    logger.info(
        "    Workload cert signed by CA: CN=%s %s issued by CN=%s",
        config.workload_cn, SYM_ARROW, config.ca_cn,
    )

    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    workload_cert_pem = workload_cert.public_bytes(
        serialization.Encoding.PEM
    ).decode().strip()
    logger.debug("Trust anchor PEM repr: %s", repr(ca_cert_pem[:120]))

    # Compute cert-pinning values for the WIF attributeCondition.
    # Per Google docs:
    #   assertion.serialNumberHex — uppercase hex string
    #   assertion.sha256Fingerprint — standard Base64 encoded
    workload_der = workload_cert.public_bytes(serialization.Encoding.DER)
    sha256_fp = base64.b64encode(
        hashlib.sha256(workload_der).digest()
    ).decode().rstrip("=")
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
    work_dir = Path.cwd() / f"ctk_work_{config.suffix}"
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 0. Clean up stale bunker-workload certs from previous runs.
        ps_cleanup = (
            "Get-ChildItem Cert:\\CurrentUser\\My | "
            "Where-Object { $_.Subject -like 'CN=bunker-workload-*' } | "
            "Remove-Item -Force"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cleanup],
            capture_output=True, text=True,
        )
        logger.info("    Cleaned up stale bunker-workload certs from CurrentUser store.")

        # 1. Write certreq INF.
        algo = config.key_algo_config
        if config.soft_key:
            provider = "Microsoft Software Key Storage Provider"
            logger.warning(
                f"    {SYM_WARN}  --soft-key: using software keys (NOT TPM-backed). "
                "For production use, remove --soft-key to use the TPM."
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
            capture_output=True, text=True, check=True,
        )
        if not csr_path.exists():
            raise FileNotFoundError(
                f"CSR not found at {csr_path} after certreq -new. "
                f"stdout: {result.stdout}, stderr: {result.stderr}"
            )
        csr_pem = csr_path.read_text().strip()
        logger.info("    TPM key created and CSR generated: %s", config.workload_cn)

        # 3. Ephemeral CA signs the CSR → CA-signed workload cert.
        bundle, workload_pem = _create_ca_and_sign(csr_pem, config)

        # 4. Install CA cert into trusted root store so certreq -accept
        #    can validate the chain.  This triggers a Windows security
        #    dialog — the user must click Yes.  We verify afterward.
        ca_cert_obj = cx509.load_pem_x509_certificate(
            bundle.trust_anchor_pem.encode()
        )
        ca_der_path = work_dir / "ca.der"
        ca_der_path.write_bytes(
            ca_cert_obj.public_bytes(serialization.Encoding.DER)
        )
        ps_install_ca = (
            f"$cert = Import-Certificate "
            f"-FilePath '{ca_der_path}' "
            f"-CertStoreLocation 'Cert:\\CurrentUser\\Root'; "
            f"Write-Output $cert.Thumbprint"
        )
        ca_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_install_ca],
            capture_output=True, text=True, check=True,
        )
        ca_thumbprint = ca_result.stdout.strip()

        # Verify the CA was actually accepted.
        ps_verify_ca = (
            f"(Get-ChildItem Cert:\\CurrentUser\\Root | "
            f"Where-Object {{ $_.Thumbprint -eq '{ca_thumbprint}' }}).Count"
        )
        verify_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_verify_ca],
            capture_output=True, text=True,
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
            capture_output=True, text=True, check=True,
        )
        logger.info(
            "    CA-signed cert associated with TPM key in CurrentUser store."
        )

        # 6. Remove the ephemeral CA from trusted root store.
        #    On Windows, this triggers a Security Warning dialog
        #    requiring user confirmation (same as import).
        logger.info("    Removing ephemeral CA from trusted root store...")
        subprocess.run(
            ["certutil", "-user", "-delstore", "Root", ca_thumbprint],
            capture_output=True, text=True,
        )
        verify_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"@(Get-ChildItem Cert:\\CurrentUser\\Root | "
             f"Where-Object Thumbprint -eq '{ca_thumbprint}').Count"],
            capture_output=True, text=True,
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
        raise RuntimeError(
            f"Windows TPM certificate generation failed: "
            f"{e.cmd} → exit {e.returncode}\n"
            f"stdout: {e.stdout}\nstderr: {e.stderr}"
        ) from e


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
    mac_ver_str = platform.mac_ver()[0]
    if mac_ver_str:
        major_ver = int(mac_ver_str.split(".")[0])
        if major_ver < 15:
            raise RuntimeError(
                f"Hardware-backed mTLS via CryptoTokenKit requires macOS 15+. "
                f"Current version: {mac_ver_str}"
            )

    work_dir = Path.cwd() / f"ctk_work_{config.suffix}"
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 0. Clean up stale CTK identities and login keychain certs
        #    from previous runs. Each run creates a new SE key; old
        #    ones are orphaned.
        id_result = subprocess.run(
            ["sc_auth", "identities"],
            check=True, capture_output=True, text=True,
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
            ["security", "find-certificate", "-c", "bunker-workload", "-a", "-Z",
             login_kc],
            capture_output=True, text=True,
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
                "sc_auth", "create-ctk-identity",
                "-l", config.workload_cn,
                "-N", config.workload_cn,
                "-k", config.key_algo_config["macos_sc_auth"],
                "-t", "none",
            ],
            check=True, capture_output=True, text=True,
        )
        logger.info("    Secure Enclave key created: %s", config.workload_cn)

        # 2. Look up the key's SHA-1 hash from sc_auth identities.
        #    Retry briefly — the CTK token may need a moment to register
        #    the new identity after creation and stale identity deletion.
        key_hash: str | None = None
        for attempt in range(5):
            id_result = subprocess.run(
                ["sc_auth", "identities"],
                check=True, capture_output=True, text=True,
            )
            for line in id_result.stdout.splitlines():
                if config.workload_cn in line:
                    key_hash = line.split()[0]
            if key_hash:
                break
            time.sleep(1)
        if not key_hash:
            raise RuntimeError(
                f"Could not find key hash for '{config.workload_cn}' "
                f"in sc_auth identities output:\n{id_result.stdout}"
            )
        logger.info("    SE key hash: %s", key_hash)

        # 3. Generate a CSR from the SE key (sc_auth appends .csr to filename)
        csr_basename = str(work_dir / "workload_csr")
        subprocess.run(
            [
                "sc_auth", "create-ctk-csr",
                "-h", key_hash,
                "-N", config.workload_cn,
                "-f", csr_basename,
            ],
            check=True, capture_output=True, text=True,
        )
        csr_path = Path(f"{csr_basename}.csr")
        if not csr_path.exists():
            raise FileNotFoundError(
                f"CSR not found at {csr_path} after sc_auth create-ctk-csr"
            )
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
                "sc_auth", "import-ctk-certificate",
                "-f", str(workload_cert_path),
            ],
            check=True, capture_output=True, text=True,
        )
        logger.info(
            "    CA-signed cert linked to SE key via import-ctk-certificate."
        )

        # 6. Also import the cert into the login keychain so that ECP's
        #    GetCertPemForPython / SignForPython can find it via
        #    SecItemCopyMatching.  macOS auto-associates login keychain
        #    certs with SE keys that share the same public key hash,
        #    forming a usable SecIdentity for mTLS signing.
        login_kc = _macos_login_keychain()
        subprocess.run(
            [
                "security", "import", str(workload_cert_path),
                "-k", login_kc,
                "-T", "/usr/bin/security",
            ],
            capture_output=True, text=True,  # Don't check — may warn "already exists"
        )
        logger.info("    Cert also imported into login keychain for ECP.")

        return bundle

    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"macOS Secure Enclave generation failed: "
            f"{e.stderr or 'Unknown error'}"
        ) from e
    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


def _generate_cert_linux(config: WorkloadConfig) -> CertificateBundle:
    """Generates a TPM 2.0-backed certificate via PKCS#11 toolchain (Ubuntu 24+)."""
    tpm_store = Path.home() / ".tpm2_pkcs11"
    os.environ["TPM2_PKCS11_STORE"] = str(tpm_store)
    tpm_store.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Initialize TPM PKCS#11 token and generate hardware-backed key
        init_result = subprocess.run(
            ["tpm2_ptool", "init"], check=True, capture_output=True, text=True,
        )
        logger.debug("    tpm2_ptool init: %s", init_result.stdout.strip())

        token_result = subprocess.run(
            [
                "tpm2_ptool", "addtoken", "--pid=1",
                f"--sopin={config.linux_tpm_pin}",
                f"--userpin={config.linux_tpm_pin}",
                "--label=bunker-wif",
            ],
            check=True, capture_output=True, text=True,
        )
        logger.debug("    tpm2_ptool addtoken: %s", token_result.stdout.strip())

        key_result = subprocess.run(
            [
                "tpm2_ptool", "addkey", f"--algorithm={config.key_algo_config['linux_tpm2']}",
                "--label=bunker-wif",
                f"--key-label={config.workload_cn}",
                f"--userpin={config.linux_tpm_pin}",
            ],
            check=True, capture_output=True, text=True,
        )
        logger.debug("    tpm2_ptool addkey: %s", key_result.stdout.strip())

        # Verify the token is visible via p11-kit before calling certtool
        try:
            p11_result = subprocess.run(
                ["p11tool", "--list-tokens"],
                capture_output=True, text=True, timeout=10,
            )
            logger.debug("    p11tool --list-tokens:\n%s", p11_result.stdout)
            if "bunker-wif" not in p11_result.stdout:
                logger.warning("    Token 'bunker-wif' not visible to p11tool!")
                # Try listing via pkcs11-tool as fallback diagnostic
                try:
                    pkcs11_result = subprocess.run(
                        ["pkcs11-tool", "--module",
                         "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
                         "-T"],
                        capture_output=True, text=True, timeout=10,
                    )
                    logger.debug("    pkcs11-tool -T:\n%s", pkcs11_result.stdout)
                except Exception:
                    pass
        except Exception as p11_err:
            logger.debug("    p11tool check failed: %s", p11_err)

        # 2. Generate a temporary self-signed cert to extract the public key
        cert_cfg = (
            f'cn = "{config.workload_cn}"\n'
            f"expiration_days = 365\n"
            f"tls_www_client\n"
        )
        write_secure_file("cert.cfg", cert_cfg)

        # Set GNUTLS_PIN so certtool can access the token without
        # relying solely on pin-value in the PKCS#11 URI.
        os.environ["GNUTLS_PIN"] = config.linux_tpm_pin

        pkcs11_uri = (
            f"pkcs11:token=bunker-wif;object={config.workload_cn};"
            f"type=private;pin-value={config.linux_tpm_pin}"
        )
        subprocess.run(
            [
                "certtool", "--generate-self-signed",
                "--load-privkey", pkcs11_uri,
                "--template", "cert.cfg",
                "--outfile", "bunker-workload-selfsigned.pem",
            ],
            check=True, capture_output=True,
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
            raise RuntimeError(
                "Could not extract CKA_ID from tpm2_ptool addkey output: "
                + key_result.stdout
            )
        logger.debug("    Using CKA_ID: %s", key_id)

        subprocess.run(
            [
                "tpm2_ptool", "addcert",
                "--label=bunker-wif",
                f"--key-id={key_id}",
                "bunker-workload-public.pem",
            ],
            input=config.linux_tpm_pin + "\n",
            check=True, capture_output=True, text=True,
        )
        logger.info(
            "    CA-signed workload cert imported into TPM PKCS#11 store."
        )

        return bundle

    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Linux TPM initialization failed. Ensure tpm2-pkcs11-tools and "
            f"gnutls-bin are installed.\nError: {e.stderr or 'Unknown error'}"
        ) from e

# --- ECP Binary Resolution ---
_ECP_GITHUB_REPO = "googleapis/enterprise-certificate-proxy"


def _get_ecp_platform_info() -> tuple[str, str, str, str]:
    """Returns (github_os, arch, lib_ext, archive_ext) for the current platform."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine

    if sys.platform == "win32":
        return "windows", arch, ".dll", ".zip"
    elif sys.platform == "darwin":
        return "darwin", arch, ".dylib", ".tar.gz"
    else:
        return "linux", arch, ".so", ".tar.gz"


def _download_ecp_from_github(ecp_dir: Path) -> None:
    """Downloads the latest ECP binaries from GitHub releases."""
    import io
    import tarfile
    import zipfile

    github_os, arch, _, archive_ext = _get_ecp_platform_info()

    # Fetch latest release metadata.
    logger.info("    Fetching latest ECP release from GitHub...")
    resp = requests.get(
        f"https://api.github.com/repos/{_ECP_GITHUB_REPO}/releases/latest",
        headers={"Accept": "application/vnd.github+json"},
        timeout=30,
    )
    resp.raise_for_status()
    assets = resp.json()["assets"]
    tag = resp.json()["tag_name"]
    logger.info("    Latest ECP release: %s", tag)

    # Find matching assets for our platform.
    # Pattern: ecp_NNN_{os}_{arch}.{ext} and ecp_NNN_{os}_{arch}_tls_offload.{ext}
    platform_suffix = f"_{github_os}_{arch}"
    main_asset = None
    tls_asset = None
    for asset in assets:
        name = asset["name"]
        if "tls_offload" in name and platform_suffix in name:
            tls_asset = asset
        elif platform_suffix in name and "tls_offload" not in name:
            main_asset = asset

    if not main_asset or not tls_asset:
        raise FileNotFoundError(
            f"Could not find ECP release assets for {github_os}/{arch}. "
            f"Available: {[a['name'] for a in assets]}"
        )

    ecp_dir.mkdir(parents=True, exist_ok=True)

    for asset in (main_asset, tls_asset):
        logger.info("    Downloading %s ...", asset["name"])
        dl_resp = requests.get(
            asset["browser_download_url"], timeout=120, stream=True,
        )
        dl_resp.raise_for_status()
        content = dl_resp.content

        if archive_ext == ".zip":
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                zf.extractall(ecp_dir)
        else:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tf:
                tf.extractall(ecp_dir)

    # Make binaries executable on Unix.
    if sys.platform != "win32":
        for f in ecp_dir.iterdir():
            if f.is_file() and not f.suffix:
                f.chmod(f.stat().st_mode | 0o755)

    logger.info("    ECP binaries downloaded to %s", ecp_dir)


def _ensure_ecp_binaries() -> tuple[Path, Path, Path]:
    """Locates ECP binaries, downloading from GitHub if not found.

    Search order:
      1. gcloud SDK's enterprise-certificate-proxy component (in-place)
      2. Persistent install directory (from a previous GitHub download)
      3. Auto-download from GitHub releases

    Returns:
        (ecp_binary, ecp_client_lib, tls_offload_lib) paths.
    """
    _, _, lib_ext, _ = _get_ecp_platform_info()
    exe_ext = ".exe" if sys.platform == "win32" else ""

    ecp_install_dir = _get_ecp_install_dir()

    # Expected filenames — GitHub releases may omit the "lib" prefix on some
    # files (e.g. tls_offload.dll), while gcloud SDK always has it.
    ecp_bin_name = f"ecp{exe_ext}"
    libecp_names = [f"libecp{lib_ext}"]
    tls_offload_names = [f"libtls_offload{lib_ext}", f"tls_offload{lib_ext}"]

    def _find_lib(directory: Path, candidates: list[str]) -> Path | None:
        """Return the first existing file from a list of candidate names."""
        for name in candidates:
            p = directory / name
            if p.exists():
                return p
        return None

    ecp_bin = client = offload = None

    # 1. Check gcloud SDK (use files in-place — ecp.exe in bin/,
    #    libecp + libtls_offload in platform/enterprise_cert/).
    gcloud_path = shutil.which("gcloud")
    if gcloud_path:
        gcloud_sdk_root = Path(gcloud_path).resolve().parent.parent
        gcloud_ecp_dir = gcloud_sdk_root / "platform" / "enterprise_cert"
        if gcloud_ecp_dir.is_dir():
            gcloud_ecp_bin = gcloud_sdk_root / "bin" / ecp_bin_name
            gcloud_client = _find_lib(gcloud_ecp_dir, libecp_names)
            gcloud_offload = _find_lib(gcloud_ecp_dir, tls_offload_names)
            if gcloud_ecp_bin.exists() and gcloud_client and gcloud_offload:
                logger.info("    Using gcloud SDK ECP binaries from %s", gcloud_ecp_dir)
                ecp_bin, client, offload = gcloud_ecp_bin, gcloud_client, gcloud_offload

    # 2. Check persistent install directory (from a previous download).
    if not ecp_bin and ecp_install_dir.is_dir():
        ecp_bin = ecp_install_dir / ecp_bin_name
        client = _find_lib(ecp_install_dir, libecp_names)
        offload = _find_lib(ecp_install_dir, tls_offload_names)
        if ecp_bin.exists() and client and offload:
            logger.info("    Using ECP binaries from %s", ecp_install_dir)
        else:
            ecp_bin = client = offload = None

    # 3. Download from GitHub as last resort.
    if not ecp_bin:
        logger.info("    ECP binaries not found — downloading from GitHub...")
        _download_ecp_from_github(ecp_install_dir)
        ecp_bin = ecp_install_dir / ecp_bin_name
        client = _find_lib(ecp_install_dir, libecp_names)
        offload = _find_lib(ecp_install_dir, tls_offload_names)
        if not ecp_bin.exists() or not client or not offload:
            actual = [f.name for f in ecp_install_dir.iterdir()] if ecp_install_dir.is_dir() else []
            raise FileNotFoundError(
                f"ECP download succeeded but expected files not found. "
                f"Actual files: {actual}"
            )

    # Prefer local patched binaries if available (macOS SE development).
    patched_ecp = Path.cwd() / "ecp_patched"
    patched_libecp = Path.cwd() / f"libecp_patched{lib_ext}"
    if patched_ecp.exists():
        ecp_bin = patched_ecp
    if patched_libecp.exists():
        client = patched_libecp

    # Register all directories containing ECP files for DLL resolution.
    # ecp_bin may be in a different dir than the DLLs (e.g. gcloud's
    # bin/ vs platform/enterprise_cert/).
    ecp_dirs = {str(p.parent) for p in (ecp_bin, client, offload)}
    for d in ecp_dirs:
        _ensure_ecp_on_path(Path(d))

    # On Windows, libtls_offload.dll requires the VC++ Redistributable.
    # Detect its absence early with a clear error message.
    if sys.platform == "win32":
        import ctypes
        for vcrt in ("VCRUNTIME140.dll", "MSVCP140.dll"):
            try:
                ctypes.WinDLL(vcrt)
            except OSError:
                raise RuntimeError(
                    f"ECP requires the Visual C++ Redistributable but "
                    f"'{vcrt}' was not found.\n"
                    f"Download and install it from:\n"
                    f"  https://learn.microsoft.com/en-us/cpp/windows/"
                    f"latest-supported-vc-redist\n"
                    f"Then re-run this script."
                ) from None

    return ecp_bin, client, offload


def _get_ecp_install_dir() -> Path:
    """Returns the standard persistent directory for ECP binaries."""
    if sys.platform == "win32":
        local_app_data = os.environ.get(
            "LOCALAPPDATA", str(Path.home() / "AppData" / "Local"),
        )
        return Path(local_app_data) / "Google" / "ECP"
    else:
        return Path.home() / ".config" / "bunker-ecp"


def _ensure_ecp_on_path(ecp_dir: Path) -> None:
    """Ensures the ECP binary directory is discoverable for DLL loading."""
    ecp_dir_str = str(ecp_dir)

    # os.add_dll_directory() is per-process (not inherited) and is the
    # ONLY mechanism that works on Python 3.8+ for DLL dependency
    # resolution.  Must be called every time, even if PATH already has it.
    if sys.platform == "win32" and ecp_dir.is_dir():
        os.add_dll_directory(ecp_dir_str)

    # Also add to PATH for the current process (belt and suspenders).
    current_path = os.environ.get("PATH", "")
    if ecp_dir_str not in current_path:
        os.environ["PATH"] = ecp_dir_str + os.pathsep + current_path

    # Persist to the user's PATH on Windows so any future process can
    # find the ECP DLLs (e.g. a Python app using google-auth ADC).
    if sys.platform == "win32":
        ps_add_path = (
            f"$userPath = [Environment]::GetEnvironmentVariable('PATH','User'); "
            f"if ($userPath -notlike '*{ecp_dir_str}*') {{ "
            f"  [Environment]::SetEnvironmentVariable("
            f"    'PATH', '{ecp_dir_str};' + $userPath, 'User'"
            f"  ); "
            f"  Write-Output 'ADDED' "
            f"}} else {{ Write-Output 'EXISTS' }}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_add_path],
            capture_output=True, text=True,
        )
        if "ADDED" in result.stdout:
            logger.info("    Added %s to user PATH (permanent).", ecp_dir_str)


def _patch_google_auth_for_hardware_keys() -> None:
    """Monkey-patch google-auth to support hardware-backed keys.

    google-auth versions <= 2.56 require both cert_path AND key_path in
    the workload certificate config.  For hardware-backed keys (TPM/SE),
    there IS no extractable key_path.  This patches two spots:

    1. _mtls_helper._get_workload_cert_and_key_paths — allow missing key_path
    2. external_account._perform_refresh_token — skip cert=(cert, key)
       injection when key_path is None (mTLS adapter handles signing)
    """
    import google.auth.transport._mtls_helper as _mtls_mod
    import google.auth.external_account as _ea_mod

    # --- Patch 1: _mtls_helper ---
    _orig_get_paths = _mtls_mod._get_workload_cert_and_key_paths

    def _patched_get_paths(config_path, include_context_aware=True):
        """Allow missing key_path for hardware-backed keys."""
        absolute_path = _mtls_mod._get_cert_config_path(
            config_path, include_context_aware,
        )
        if absolute_path is None:
            return None, None
        data = _mtls_mod._load_json_file(absolute_path)
        cert_configs = data.get("cert_configs", {})
        workload = cert_configs.get("workload")
        if workload is None:
            return None, None
        cert_path = workload.get("cert_path")
        key_path = workload.get("key_path")  # None for hardware-backed keys
        if cert_path is None:
            from google.auth import exceptions
            raise exceptions.ClientCertError(
                f'Workload config missing "cert_path" in {absolute_path}',
            )
        return cert_path, key_path

    # Always apply — safe because our versions delegate to the originals
    # and gracefully handle the hardware-key case.
    _mtls_mod._get_workload_cert_and_key_paths = _patched_get_paths
    logger.debug("    Patched _mtls_helper for hardware-backed keys.")

    # --- Patch 2: external_account ---
    # When key_path is None (hardware-backed), the original code may still
    # inject cert=(cert_path, None) which causes urllib3's load_cert_chain
    # to try reading a private key from the cert PEM file.
    # We can't null _get_mtls_cert_and_key_paths because _get_cert_bytes()
    # also needs cert_path for subject token retrieval.
    # Solution: wrap the request callable to silently strip cert= kwargs.
    _orig_refresh = getattr(_ea_mod.Credentials, "_perform_refresh_token", None)
    if _orig_refresh:
        import functools

        @functools.wraps(_orig_refresh)
        def _patched_refresh(self, request, **kwargs):
            """Strip cert= injection when key_path is None."""
            paths_fn = getattr(self, "_get_mtls_cert_and_key_paths", None)
            if paths_fn:
                try:
                    _, key_path = paths_fn()
                except Exception:
                    key_path = "unknown"
                if key_path is None:
                    # Wrap the request to strip cert= — the mTLS adapter
                    # handles signing via ECP callbacks instead.
                    _inner = request

                    class _NoCertRequest:
                        """Proxy that strips cert= from request calls."""
                        def __call__(self_req, *args, **kw):
                            kw.pop("cert", None)
                            return _inner(*args, **kw)

                        def __getattr__(self_req, name):
                            return getattr(_inner, name)

                    request = _NoCertRequest()
            return _orig_refresh(self, request, **kwargs)

        _ea_mod.Credentials._perform_refresh_token = _patched_refresh
        logger.debug("    Patched external_account for hardware-backed keys.")


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
    logger.info(
        "Instructing OS to generate non-exportable hardware-backed certificate..."
    )
    for platform_prefix, generator in _KEYSTORE_GENERATORS.items():
        if sys.platform.startswith(platform_prefix):
            return generator(config)
    raise OSError(f"Unsupported Operating System: {sys.platform}")


# --- Core Workflow ---
def main() -> None:
    parser = argparse.ArgumentParser(
        description="WIF Bunker — Hardware-backed X.509 Workload Identity Federation",
    )
    parser.add_argument("--debug", action="store_true")
    project_group = parser.add_mutually_exclusive_group()
    project_group.add_argument(
        "--use-project", metavar="PROJECT_ID",
        help="Reuse an existing GCP project (skip creation & API enablement)",
    )
    project_group.add_argument(
        "--create-project", metavar="PROJECT_ID",
        help="Create a new GCP project with this ID",
    )
    sa_group = parser.add_mutually_exclusive_group()
    sa_group.add_argument(
        "--use-service-account", metavar="SA_EMAIL",
        help="Reuse an existing service account email (skip SA creation)",
    )
    sa_group.add_argument(
        "--create-service-account", metavar="SA_NAME",
        help="Create service account with this name",
    )
    sa_group.add_argument(
        "--no-service-account", action="store_true",
        help=(
            "Skip service account creation — WIF credentials authenticate "
            "directly without SA impersonation.  IAM roles must be granted "
            "to the WIF principal directly."
        ),
    )
    pool_group = parser.add_mutually_exclusive_group()
    pool_group.add_argument(
        "--use-pool", metavar="POOL_ID",
        help="Reuse an existing WIF pool ID (skip pool creation)",
    )
    pool_group.add_argument(
        "--create-pool", metavar="POOL_ID",
        help="Create WIF pool with this ID",
    )
    algo_choices = list(_KEY_ALGORITHMS.keys())
    algo_help_lines = [f"{k}: {v['desc']}" for k, v in _KEY_ALGORITHMS.items()]
    parser.add_argument(
        "--key-algorithm", choices=algo_choices, default="es256",
        metavar="ALGO",
        help=(
            "Key algorithm for the hardware-backed certificate. "
            "Choices: " + ", ".join(algo_help_lines) + ". "
            "macOS supports es256/es384 only. Default: es256."
        ),
    )
    parser.add_argument(
        "--client-secrets-file", metavar="FILE",
        help=(
            "Path to a Google OAuth client_secrets.json file "
            "(Desktop app type).  Create one at: "
            "https://console.cloud.google.com/apis/credentials"
        ),
    )
    parser.add_argument(
        "--soft-key", action="store_true",
        help=(
            "Use software keys instead of hardware-backed keys (for CI "
            "testing without a TPM).  NOT for production use."
        ),
    )
    parser.add_argument(
        "--use-adc", action="store_true",
        help=(
            "Use Application Default Credentials instead of browser-based "
            "OAuth.  For CI/CD environments where "
            "GOOGLE_APPLICATION_CREDENTIALS is already set "
            "(e.g. via google-github-actions/auth)."
        ),
    )
    parser.add_argument(
        "--folder", metavar="FOLDER_ID",
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
        platform_ok = any(
            sys.platform.startswith(p) for p in algo_info["platforms"]
        )
        if not platform_ok:
            supported = [
                k for k, v in _KEY_ALGORITHMS.items()
                if any(sys.platform.startswith(p) for p in v["platforms"])
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
                "GET", f"https://{crm_base}/v1/projects/{config.project_id}",
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
                "GET", f"https://{crm_base}/v1/projects/{config.project_id}",
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
            f"https://{iam_base}/v1/projects/{project_number}"
            f"/locations/global/workloadIdentityPools/{config.pool_id}"
        )
        provider_res_url = (
            f"{pool_res_url}/providers/{config.provider_id}"
        )

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
                        "GET", f"{pool_res_url}/providers",
                    ).get("workloadIdentityPoolProviders", [])
                    for p in provs:
                        pname = p["name"].split("/")[-1]
                        if pname.startswith("bunker-x509-prov-") and \
                           pname != config.provider_id:
                            logger.info("    Deleting stale provider: %s", pname)
                            try:
                                del_op = client.api_call("DELETE",
                                    f"{pool_res_url}/providers/{pname}")
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
            cert_pin_condition = (
                f'assertion.sha256Fingerprint == "{cert_bundle.sha256_fingerprint}"'
            )
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

            logger.info("[Thread] Creating WIF X.509 Provider: %s",
                        config.provider_id)
            prov_op = client.api_call(
                "POST",
                f"{pool_res_url}/providers"
                f"?workloadIdentityPoolProviderId={config.provider_id}",
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
            sa_iam_url = (
                f"https://{iam_base}/v1/projects/{config.project_id}"
                f"/serviceAccounts/{sa_email}:setIamPolicy"
            )
            sa_policy = client.api_call(
                "POST", sa_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
            )
            sa_policy.setdefault("bindings", []).append(
                {"role": "roles/iam.workloadIdentityUser", "members": [wif_principal]},
            )
            client.api_call("POST", sa_iam_url, {"policy": sa_policy})

        # Project-level binding: grant to SA (impersonation mode) or
        # directly to the WIF principal (no-SA mode).
        proj_iam_url = (
            f"https://{crm_base}/v1/projects/{config.project_id}:setIamPolicy"
        )
        proj_policy = client.api_call(
            "POST", proj_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
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
            ecp_binary, ecp_client_lib, tls_offload_lib = _ensure_ecp_binaries()
        except FileNotFoundError as ecp_err:
            github_os, arch, _, _ = _get_ecp_platform_info()
            logger.warning(
                "    ECP binaries not available for %s/%s — "
                "skipping ECP config and auth demo (steps 6-7).",
                github_os, arch,
            )
            logger.warning("    %s", ecp_err)
            logger.info("=== Steps 1-5 completed successfully. ===")
            logger.info("WIF Bunker setup is complete. ECP auth demo "
                        "requires a platform with ECP support.")
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
                raise FileNotFoundError(
                    "Could not find libtpm2_pkcs11.so. "
                    "Install libtpm2-pkcs11-1."
                )

            cert_configs = {
                "pkcs11": {
                    "module": pkcs11_module,
                    "token_label": "bunker-wif",
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
        # - key_path absent: our external_account.py patch skips the
        #   cert=(cert, key) injection that would crash with SSLError
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
            cert_config_path, json.dumps(certificate_config, indent=2),
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
                f"https://iamcredentials.googleapis.com/v1/projects/-"
                f"/serviceAccounts/{sa_email}:generateAccessToken"
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

            # Check if ECP signer binary contains our patch marker
            try:
                _ecp_bin = Path(json.loads(_cfg_text)["libs"]["ecp"])
                if _ecp_bin.exists():
                    _bin_data = _ecp_bin.read_bytes()
                    log.warning("    ECP binary: %s (%d KB)", _ecp_bin, len(_bin_data) // 1024)
                    if sys.platform == "darwin":
                        log.warning("    Contains SecCertificateCopyData (patched): %s",
                                    b"SecCertificateCopyData" in _bin_data)
                        log.warning("    Contains SecItemExport (unpatched): %s",
                                    b"SecItemExport" in _bin_data)
                else:
                    log.warning("    ECP binary NOT FOUND: %s", _ecp_bin)
            except Exception as _e:
                log.warning("    Binary check error: %s", _e)

            # Run signer binary directly to capture its stderr
            try:
                _ecp_bin_path = str(Path(json.loads(_cfg_text)["libs"]["ecp"]))
                _result = subprocess.run(
                    [_ecp_bin_path, str(config_path)],
                    capture_output=True, text=True, timeout=10,
                )
                log.warning("    ECP signer stderr: %s",
                            _result.stderr[:500] if _result.stderr else "(empty)")
            except subprocess.TimeoutExpired:
                log.warning("    ECP signer listening for RPC (OK)")
            except Exception as _e:
                log.warning("    ECP signer error: %s", _e)

            # Check keychain identities (macOS)
            if sys.platform == "darwin":
                try:
                    _id_result = subprocess.run(
                        ["security", "find-identity", "-v", "-p", "ssl-client"],
                        capture_output=True, text=True, timeout=5,
                    )
                    log.warning("    Keychain SSL-client identities:\n%s",
                                _id_result.stdout)
                except Exception as _e:
                    log.warning("    find-identity error: %s", _e)

        logger.info("=== 7) Executing Full ADC Auth Flow Demo ===")

        try:
            # Set environment so google-auth discovers our configs.
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(adc_path)
            os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "true"
            os.environ["GOOGLE_API_CERTIFICATE_CONFIG"] = str(cert_config_path)

            # Build a Request with the ECP mTLS adapter so that default()'s
            # internal token exchange presents the SE-backed client cert.
            # The cert was imported into the login keychain (step 3) so ECP's
            # GetCertPemForPython / SignForPython can find it via
            # SecItemCopyMatching.  macOS auto-associates it with the SE key.
            from google.auth import default
            from google.auth.transport.requests import (
                Request as AuthRequest,
                _MutualTlsOffloadAdapter,
            )
            import requests as req_lib

            # Pre-load ECP DLLs so ctypes.CDLL can resolve dependencies.
            # On Windows, ctypes.CDLL(winmode=0) uses legacy DLL search which
            # doesn't honour os.add_dll_directory().  Loading all ECP DLLs
            # from the same directory ensures they can find each other.
            if sys.platform == "win32":
                import ctypes
                for lib in (ecp_client_lib, tls_offload_lib):
                    try:
                        ctypes.WinDLL(str(lib))
                    except OSError:
                        pass  # Will fail properly in _MutualTlsOffloadAdapter

            if args.debug:
                os.environ["ENABLE_ENTERPRISE_CERTIFICATE_LOGS"] = "1"

            # Diagnostic: verify ECP libs can load and work.
            import ctypes
            _ecp_lib = ctypes.CDLL(str(ecp_client_lib))
            _ecp_lib.GetCertPemForPython.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
            ]
            _ecp_lib.GetCertPemForPython.restype = ctypes.c_int
            _cert_len = _ecp_lib.GetCertPemForPython(
                str(cert_config_path).encode(), None, 0,
            )
            logger.debug("    ECP GetCertPemForPython returned cert_len=%d", _cert_len)
            if _cert_len == 0:
                logger.warning("    ECP cert_len=0 — cert lookup failed.")
                if args.debug:
                    _run_ecp_diagnostics(
                        cert_config_path, logger,
                    )
            if _cert_len > 0:
                logger.debug("    ECP cert loaded successfully (%d bytes)", _cert_len)

            _offload = ctypes.CDLL(str(tls_offload_lib))
            logger.debug("    TLS offload lib loaded: %s", tls_offload_lib)

            mtls_session = req_lib.Session()
            mtls_adapter = _MutualTlsOffloadAdapter(str(cert_config_path))
            mtls_session.mount("https://", mtls_adapter)
            mtls_request = AuthRequest(session=mtls_session)

            # Quick SSL connectivity test.
            logger.debug("    Testing SSL handshake to sts.mtls.googleapis.com...")
            try:
                test_resp = mtls_session.get(
                    "https://sts.mtls.googleapis.com/",
                    timeout=15,
                )
                logger.debug("    SSL test status: %s", test_resp.status_code)
            except Exception as ssl_test_err:
                logger.debug("    SSL test failed: %s", ssl_test_err)

            # Allow IAM bindings to propagate before attempting auth.
            logger.info("    Waiting 15s for IAM propagation...")
            time.sleep(15)

            from ssl import SSLError
            @with_retries(
                max_attempts=10,
                retryable_exceptions=(RefreshError, OAuthError, TypeError),
                retry_msg="Waiting for STS propagation",
            )
            def _verify_adc():
                adc_creds, _ = default(
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
            logger.info(
                f"{SYM_OK} API Call Successful! The OS signed the handshake via ECP."
            )
            if use_sa:
                logger.info("   Authenticated SA: %s", sa_email)
            logger.info("   Target Project:   %s", proj_result.get("name"))
        except Exception as e:
            # Log full traceback for SSL/auth failures
            import traceback
            logger.error("Step 7 (ECP auth demo) failed: %s", e)
            logger.error("Full traceback:\n%s", traceback.format_exc())
            sys.exit(1)


if __name__ == "__main__":
    main()
