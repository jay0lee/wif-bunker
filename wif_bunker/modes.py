"""Alternate CLI modes: --cert-only, --cert-and-mtls-test, --status, --attest, --supported-algorithms, and --all-versions."""  # pylint: disable=duplicate-code

from __future__ import annotations

import datetime
import json
import logging
import os
import sys
from pathlib import Path

import google.auth
from cryptography import x509 as cx509
from cryptography.x509.oid import NameOID
from google.auth.transport.requests import AuthorizedSession

from wif_bunker.attestation import generate_attestation, print_attestation_summary, write_attestation_report
from wif_bunker.config import _CONFIG_FILES, WorkloadConfig
from wif_bunker.keystore import generate_os_keystore_cert
from wif_bunker.utils import (
    SYM_CHECK,
    SYM_CROSS,
    SYM_FAIL,
    SYM_WARN,
    write_secure_file,
)

logger = logging.getLogger(__name__)


def _run_cert_only(config: WorkloadConfig, output_dir: str) -> None:
    """Generate a hardware-backed certificate without any GCP/WIF setup."""
    logger.info("=== Generating Hardware-Backed Certificate (cert-only mode) ===")

    cert_bundle = generate_os_keystore_cert(config)

    os.makedirs(output_dir, exist_ok=True)
    cert_path = Path(output_dir) / "workload_cert.pem"
    chain_path = Path(output_dir) / "trust_chain.pem"
    write_secure_file(cert_path, cert_bundle.workload_cert_pem)
    write_secure_file(chain_path, cert_bundle.trust_anchor_pem)

    logger.info("")
    logger.info("Certificate generated:")
    logger.info("  Subject:     CN=%s", config.workload_cn)
    logger.info("  Issuer:      CN=%s", cert_bundle.issuer_cn)
    logger.info("  Algorithm:   %s", config.key_algorithm)
    logger.info("  Fingerprint: %s", cert_bundle.sha256_fingerprint)
    logger.info("  Lifetime:    %d days", config.cert_lifetime_days)
    logger.info("")
    logger.info("Files written:")
    logger.info("  %s", cert_path)
    logger.info("  %s", chain_path)


def _run_cert_and_mtls_test(config: WorkloadConfig, output_dir: str, debug: bool = False) -> None:
    """Generate a hardware-backed cert and validate mTLS against external endpoints.

    This is a self-contained test that proves the full hardmTLS signing
    pipeline works without needing GCP project/WIF infrastructure:

    1. Generate a hardware-backed certificate (same as --cert-only)
    2. Build certificate_config.json pointing to the hardmTLS library
    3. Verify hardmTLS can retrieve the cert
    4. Test mTLS handshake against certauth.idrix.fr (REQUIRES client cert)
    5. Test mTLS handshake against sts.mtls.googleapis.com (accepts client cert)
    """
    import ctypes  # pylint: disable=import-outside-toplevel

    import requests  # pylint: disable=import-outside-toplevel

    from wif_bunker.cert import (  # pylint: disable=import-outside-toplevel
        _find_hardmtls_library,
        build_certificate_config,
        verify_cert_retrieval,
    )

    logger.info("=== mTLS Smoke Test: Generating Hardware-Backed Certificate ===")
    cert_bundle = generate_os_keystore_cert(config)

    os.makedirs(output_dir, exist_ok=True)
    cert_path = Path(output_dir) / "workload_cert.pem"
    chain_path = Path(output_dir) / "trust_chain.pem"
    write_secure_file(cert_path, cert_bundle.workload_cert_pem)
    write_secure_file(chain_path, cert_bundle.trust_anchor_pem)

    logger.info("  Certificate generated:")
    logger.info("    Subject:     CN=%s", config.workload_cn)
    logger.info("    Issuer:      CN=%s", cert_bundle.issuer_cn)
    logger.info("    Algorithm:   %s", config.key_algorithm)
    logger.info("    Fingerprint: %s", cert_bundle.sha256_fingerprint)

    # ── Find hardmTLS library ──
    logger.info("")
    logger.info("=== mTLS Smoke Test: Configuring hardmTLS ===")
    try:
        hardmtls_lib = _find_hardmtls_library()
    except FileNotFoundError as lib_err:
        logger.error("❌ hardmTLS library not found: %s", lib_err)
        raise SystemExit(1) from lib_err

    # ── Build certificate_config.json ──
    # Save CWD state — build_certificate_config writes to CWD, so temporarily
    # change to output_dir so files land there.
    orig_cwd = os.getcwd()
    os.chdir(output_dir)
    try:
        _cert_config, cert_config_path, _wl_cert_path, _trust_path = build_certificate_config(
            config, cert_bundle, hardmtls_lib
        )
    finally:
        os.chdir(orig_cwd)

    logger.info("  certificate_config.json: %s", cert_config_path)

    # ── Set environment for hardmTLS ──
    os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "true"
    os.environ["GOOGLE_API_CERTIFICATE_CONFIG"] = str(cert_config_path)
    if debug:
        os.environ["ENABLE_ENTERPRISE_CERTIFICATE_LOGS"] = "1"
        os.environ["RUST_LOG"] = os.environ.get("RUST_LOG", "hardmtls=debug")

    # Pre-load hardmTLS DLL on Windows
    if sys.platform == "win32":
        try:
            ctypes.WinDLL(str(hardmtls_lib))  # type: ignore[attr-defined]
        except OSError:
            pass

    # ── Step A: Certificate Retrieval ──
    logger.info("")
    logger.info("=== mTLS Smoke Test: Certificate Retrieval ===")
    try:
        verify_cert_retrieval(cert_config_path, hardmtls_lib, debug=debug)
    except RuntimeError:
        sys.exit(1)

    # ── Step B: mTLS against certauth.idrix.fr (REQUIRES client cert) ──
    logger.info("")
    logger.info("=== mTLS Smoke Test: certauth.idrix.fr (requires client cert) ===")
    try:
        from google.auth.transport.requests import _MutualTlsOffloadAdapter  # pylint: disable=import-outside-toplevel

        mtls_session = requests.Session()
        mtls_session.mount("https://", _MutualTlsOffloadAdapter(str(cert_config_path)))

        mtls_resp = mtls_session.get("https://certauth.idrix.fr/json/", timeout=15)
        if mtls_resp.status_code == 200:
            cert_info = mtls_resp.json()
            client_dn = cert_info.get("SSL_CLIENT_S_DN", "(not present)")
            client_issuer = cert_info.get("SSL_CLIENT_I_DN", "(not present)")
            client_serial = cert_info.get("SSL_CLIENT_SERIAL", "(not present)")
            client_verify = cert_info.get("SSL_CLIENT_VERIFY", "(not present)")
            logger.info("  ✅ PASS: Server confirmed client cert was presented")
            logger.info("    Subject:  %s", client_dn)
            logger.info("    Issuer:   %s", client_issuer)
            logger.info("    Serial:   %s", client_serial)
            logger.info("    Verify:   %s", client_verify)
        else:
            logger.warning(
                "  ⚠️  Server returned HTTP %d — client cert may not have been sent",
                mtls_resp.status_code,
            )
    except requests.exceptions.SSLError as ssl_err:
        logger.error("  ❌ FAIL: mTLS handshake failed (server requires client cert):")
        logger.error("    %s", ssl_err)
        logger.error("    This means hardmTLS did NOT send the client certificate.")
        if debug:
            from wif_bunker.cert import run_hardmtls_diagnostics  # pylint: disable=import-outside-toplevel

            run_hardmtls_diagnostics(cert_config_path, logger)
        sys.exit(1)
    except Exception as mtls_err:
        logger.error("  ❌ FAIL: mTLS verification error: %s", mtls_err)
        sys.exit(1)

    # ── Step C: mTLS against sts.mtls.googleapis.com ──
    # STS makes client certs RECOMMENDED (not required), so the handshake
    # will succeed even without one.  But if hardmTLS is working, the
    # server will see our cert.  We just verify the TLS handshake works.
    #
    # Reuse the same session from Step B — creating a second adapter would
    # re-load libtpm2_pkcs11.so and try to open a new TPM auth session,
    # which fails on hardware TPMs with "handle is not correct for the use".
    logger.info("")
    logger.info("=== mTLS Smoke Test: sts.mtls.googleapis.com (recommends client cert) ===")
    try:
        # A GET to /v1/token is not a valid STS request but exercises the
        # mTLS handshake.  We expect HTTP 400/405/etc — any HTTP response
        # means the TLS handshake (including client cert) succeeded.
        sts_resp = mtls_session.get("https://sts.mtls.googleapis.com/v1/token", timeout=15)
        logger.info("  ✅ PASS: mTLS handshake with Google STS succeeded (HTTP %d)", sts_resp.status_code)
    except requests.exceptions.SSLError as ssl_err:
        logger.error("  ❌ FAIL: mTLS handshake with Google STS failed:")
        logger.error("    %s", ssl_err)
        sys.exit(1)
    except Exception as sts_err:
        logger.error("  ❌ FAIL: STS connection error: %s", sts_err)
        sys.exit(1)

    logger.info("")
    logger.info("=== mTLS Smoke Test: ALL PASSED ✅ ===")


def _default_attest_dir() -> str:
    """Return the platform-appropriate default attestation output directory."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        return str(Path(base) / "wif-bunker" / "attestation")
    return str(Path.home() / ".config" / "wif-bunker" / "attestation")


def _run_attest(config: WorkloadConfig, output_dir: str | None, cert_file: str | None) -> None:
    """Generate hardware attestation artifacts for the current platform."""
    target_dir = output_dir or _default_attest_dir()
    logger.info("=== Hardware Key Attestation ===")

    # If a cert file is provided, extract the CN to target the correct key
    if cert_file:
        cert_path = Path(cert_file)
        if not cert_path.exists():
            logger.error("Certificate file not found: %s", cert_file)
            raise SystemExit(1)
        cert_pem = cert_path.read_bytes()
        cert = cx509.load_pem_x509_certificate(cert_pem)
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            config.workload_cn = cn_attrs[0].value
            logger.info("  Attesting key: %s (from %s)", config.workload_cn, cert_file)
        else:
            logger.warning("  Certificate has no CN — using default config")
    else:
        logger.info("  No --cert-file specified — attesting platform TPM capabilities only")

    logger.info("  Output directory: %s", target_dir)
    logger.info("")

    report = generate_attestation(config)

    # Write artifacts and reports
    write_attestation_report(report, Path(target_dir))

    # Print summary to terminal
    print_attestation_summary(report)

    logger.info("")
    logger.info("Attestation artifacts written to: %s", target_dir)


def _run_status() -> None:
    """Show current WIF Bunker configuration status and health."""
    logger.info("=== WIF Bunker Status ===")

    # Stage 1: Check config files
    logger.info("Config files:")
    missing = []
    for name in _CONFIG_FILES:
        path = Path.cwd() / name
        if path.exists():
            logger.info("  %s %s", SYM_CHECK, name)
        else:
            logger.info("  %s %s (missing)", SYM_CROSS, name)
            missing.append(name)
    if missing:
        logger.error("")
        logger.error("Missing config files: %s", ", ".join(missing))
        logger.error("Run wif-bunker to generate configuration first.")
        return

    # Stage 2: Parse certificate
    logger.info("")
    logger.info("Certificate:")
    cert_path = Path.cwd() / "workload_cert.pem"
    try:
        cert = cx509.load_pem_x509_certificate(cert_path.read_bytes())
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        key_type = type(cert.public_key()).__name__
        serial_hex = format(cert.serial_number, "X")
        serial_display = serial_hex[:16] + "..." if len(serial_hex) > 16 else serial_hex
        valid_from = cert.not_valid_before_utc
        expires = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.UTC)
        days_remaining = (expires - now).days

        logger.info("  Subject:    CN=%s", subject_cn)
        logger.info("  Issuer:     CN=%s", issuer_cn)
        logger.info("  Algorithm:  %s", key_type)
        logger.info("  Serial:     %s", serial_display)
        logger.info("  Valid from: %s", valid_from.strftime("%Y-%m-%d"))
        logger.info("  Expires:    %s (%d days remaining)", expires.strftime("%Y-%m-%d"), days_remaining)

        if days_remaining < 0:
            logger.error("  %s Certificate has EXPIRED. Re-run wif-bunker to rotate.", SYM_FAIL)
            return
        if days_remaining < 15:
            logger.warning(
                "  %s WARNING: Certificate expires in %d days. Re-run wif-bunker to rotate.",
                SYM_WARN,
                days_remaining,
            )
    except Exception as exc:
        logger.error("  %s Failed to parse certificate: %s", SYM_CROSS, exc)
        return

    # Stage 3: Test hardmTLS
    logger.info("")
    cert_config_path = Path.cwd() / "certificate_config.json"
    try:
        cert_config = json.loads(cert_config_path.read_text())
        hardmtls_lib_path = cert_config.get("libs", {}).get("ecp_client")
        if not hardmtls_lib_path or not Path(hardmtls_lib_path).exists():
            logger.error("hardmTLS:  %s library not found at: %s", SYM_CROSS, hardmtls_lib_path)
            return

        from wif_bunker.cert import hardmtls_get_cert_pem

        _cert_pem_bytes = hardmtls_get_cert_pem(hardmtls_lib_path, cert_config_path)
        logger.info("hardmTLS:  %s Certificate retrieved (%d bytes)", SYM_CHECK, len(_cert_pem_bytes))
    except Exception as exc:
        logger.error("hardmTLS:  %s %s", SYM_CROSS, exc)
        return

    # Stage 4: Test ADC
    try:
        adc_path = Path.cwd() / "adc.json"
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(adc_path)
        os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "true"
        os.environ["GOOGLE_API_CERTIFICATE_CONFIG"] = str(cert_config_path)

        adc_creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        authed_session = AuthorizedSession(adc_creds)
        authed_session.configure_mtls_offload_channel(str(cert_config_path))

        # Read project ID from adc.json
        adc_config = json.loads(adc_path.read_text())
        project_id = adc_config.get("workforce_pool_user_project", "")

        crm_base = "cloudresourcemanager.googleapis.com"
        target_res = authed_session.get(
            f"https://{crm_base}/v1/projects/{project_id}",
        )
        target_res.raise_for_status()
        logger.info("ADC:       %s API call successful", SYM_CHECK)
    except Exception as exc:
        logger.error("ADC:       %s %s", SYM_CROSS, exc)
        logger.error("Re-run with --debug for detailed hardmTLS and TLS diagnostics.")


def _run_supported_algorithms(
    use_yubikey: bool = False,
    yubikey_serial: int | None = None,
    soft_key: bool = False,
    verbose: bool = False,
) -> None:
    """Probe the active keystore for supported algorithms and print them."""
    from wif_bunker.config import _KEY_ALGORITHMS  # pylint: disable=import-outside-toplevel

    # Determine keystore and probe
    if use_yubikey:
        keystore_name = "YubiKey"
        from wif_bunker.keystore.yubikey import (
            get_supported_algorithms_yubikey,  # pylint: disable=import-outside-toplevel
        )

        supported = get_supported_algorithms_yubikey(serial=yubikey_serial)
        all_algos = [k for k, v in _KEY_ALGORITHMS.items() if "yubikey" in v["platforms"]]
    elif sys.platform == "darwin":
        keystore_name = "macOS Secure Enclave"
        from wif_bunker.keystore.macos import get_supported_algorithms_macos  # pylint: disable=import-outside-toplevel

        supported = get_supported_algorithms_macos()
        all_algos = [k for k, v in _KEY_ALGORITHMS.items() if "darwin" in v["platforms"]]
    elif sys.platform == "win32":
        keystore_name = "Windows CNG (Software KSP)" if soft_key else "Windows CNG (Platform TPM)"
        from wif_bunker.keystore.windows import (
            get_supported_algorithms_windows,  # pylint: disable=import-outside-toplevel
        )

        supported = get_supported_algorithms_windows(soft_key=soft_key)
        all_algos = [k for k, v in _KEY_ALGORITHMS.items() if "win32" in v["platforms"]]
    elif sys.platform.startswith("linux"):
        keystore_name = "Linux TPM"
        from wif_bunker.keystore.linux import get_supported_algorithms_linux  # pylint: disable=import-outside-toplevel

        supported = get_supported_algorithms_linux()
        all_algos = [k for k, v in _KEY_ALGORITHMS.items() if "linux" in v["platforms"]]
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")

    if verbose:
        print(f"Keystore: {keystore_name}")
        for algo in all_algos:
            desc = _KEY_ALGORITHMS[algo]["desc"]
            if algo in supported:
                print(f"  {SYM_CHECK} {algo:<8}  {desc}")
            else:
                print(f"  {SYM_CROSS} {algo:<8}  {desc}")
    else:
        for algo in supported:
            print(algo)


def _run_all_versions() -> None:
    """Print comprehensive version, environment, and system info for debugging."""
    import platform
    import shutil
    import ssl
    import struct
    import subprocess

    from wif_bunker import __version__

    def _safe_version(module_name: str) -> str:
        """Import a module and return its version, or a fallback message."""
        import importlib

        try:
            mod = importlib.import_module(module_name)
            return getattr(mod, "__version__", getattr(mod, "VERSION", "(no __version__)"))
        except ImportError:
            return "(not installed)"
        except Exception as exc:  # pylint: disable=broad-except
            return f"(error: {exc})"

    # ── WIF Bunker ──
    print("WIF Bunker")
    print(f"  wif-bunker:        {__version__}")

    # ── Python ──
    print("\nPython")
    print(f"  Python:            {platform.python_version()}")
    print(f"  Implementation:    {platform.python_implementation()}")
    print(f"  Compiler:          {platform.python_compiler()}")
    print(f"  Executable:        {sys.executable}")
    print(f"  Prefix:            {sys.prefix}")
    frozen = getattr(sys, "frozen", False)
    if frozen:
        print(f"  Frozen:            {frozen} (PyInstaller bundle)")

    # ── OpenSSL (as linked by Python's ssl module) ──
    print("\nOpenSSL")
    print(f"  ssl.OPENSSL_VERSION:        {ssl.OPENSSL_VERSION}")
    print(f"  ssl.OPENSSL_VERSION_INFO:   {ssl.OPENSSL_VERSION_INFO}")
    ssl_path = shutil.which("openssl")
    if ssl_path:
        try:
            result = subprocess.run(
                [ssl_path, "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            print(f"  openssl CLI:                {result.stdout.strip()}")
            print(f"  openssl path:               {ssl_path}")
        except Exception:  # pylint: disable=broad-except
            print(f"  openssl path:               {ssl_path} (version query failed)")
    else:
        print("  openssl CLI:                (not found on PATH)")
    openssl_dir = os.environ.get("OPENSSL_DIR")
    if openssl_dir:
        print(f"  OPENSSL_DIR:                {openssl_dir}")

    # ── Key Dependencies ──
    print("\nKey Dependencies")
    print(f"  cryptography:      {_safe_version('cryptography')}")
    print(f"  pyOpenSSL:         {_safe_version('OpenSSL')}")
    print(f"  google-auth:       {_safe_version('google.auth')}")
    print(f"  requests:          {_safe_version('requests')}")
    print(f"  cffi:              {_safe_version('cffi')}")
    print(f"  yubikey-manager:   {_safe_version('ykman')}")

    # Platform-specific deps
    if sys.platform == "linux":
        print(f"  tpm2-pytss:        {_safe_version('tpm2_pytss')}")
        print(f"  python-pkcs11:     {_safe_version('pkcs11')}")

    # ── hardmTLS ──
    print("\nhardmTLS")
    try:
        from wif_bunker.cert import _find_hardmtls_library

        lib_path = _find_hardmtls_library()
        print(f"  Library:           {lib_path}")
    except FileNotFoundError:
        print("  Library:           (not found)")
    except Exception as exc:  # pylint: disable=broad-except
        print(f"  Library:           (error: {exc})")

    # ── Environment Variables ──
    print("\nEnvironment Variables")
    env_keys = [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_API_USE_CLIENT_CERTIFICATE",
        "GOOGLE_API_CERTIFICATE_CONFIG",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "GOOGLE_CLOUD_PROJECT",
        "CLOUDSDK_CORE_PROJECT",
        "OPENSSL_DIR",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "ENABLE_ENTERPRISE_CERTIFICATE_LOGS",
        "RUST_LOG",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "TPM2TOOLS_TCTI",
        "TPM2_PKCS11_TCTI",
        "TPM2_PKCS11_STORE",
        "DBUS_SESSION_BUS_ADDRESS",
    ]
    found_any = False
    for key in env_keys:
        val = os.environ.get(key)
        if val is not None:
            found_any = True
            print(f"  {key}={val}")
    if not found_any:
        print("  (none of the relevant variables are set)")

    # ── System ──
    print("\nSystem")
    print(f"  OS:                {platform.system()} {platform.release()}")
    print(f"  Platform:          {platform.platform()}")
    print(f"  Machine:           {platform.machine()}")
    print(f"  Architecture:      {struct.calcsize('P') * 8}-bit")
    if sys.platform == "darwin":
        print(f"  macOS version:     {platform.mac_ver()[0]}")
    elif sys.platform == "win32":
        ver = platform.win32_ver()
        print(f"  Windows version:   {ver[0]} {ver[1]}")

    # ── Config Files ──
    print("\nConfig Files")
    for fname in _CONFIG_FILES:
        fpath = Path.cwd() / fname
        if fpath.exists():
            size = fpath.stat().st_size
            print(f"  {SYM_CHECK} {fname} ({size} bytes)")
        else:
            print(f"  {SYM_CROSS} {fname}")
