"""Alternate CLI modes: --cert-only, --status, --attest, and --supported-algorithms."""  # pylint: disable=duplicate-code

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
