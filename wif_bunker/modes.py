"""Alternate CLI modes: --cert-only and --status."""

from __future__ import annotations

import ctypes
import datetime
import json
import logging
import os
import re
from pathlib import Path

import google.auth
from cryptography import x509 as cx509
from cryptography.x509.oid import NameOID
from google.auth.transport.requests import AuthorizedSession

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
    except Exception as e:
        logger.error("  %s Failed to parse certificate: %s", SYM_CROSS, e)
        return

    # Stage 3: Test ECP
    logger.info("")
    cert_config_path = Path.cwd() / "certificate_config.json"
    try:
        cert_config = json.loads(cert_config_path.read_text())
        ecp_client_path = cert_config.get("libs", {}).get("ecp_client")
        if not ecp_client_path or not Path(ecp_client_path).exists():
            logger.error("ECP:       %s ECP client library not found at: %s", SYM_CROSS, ecp_client_path)
            return

        _ecp_lib = ctypes.CDLL(ecp_client_path)
        _ecp_lib.GetCertPemForPython.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        _ecp_lib.GetCertPemForPython.restype = ctypes.c_int
        _cert_len = _ecp_lib.GetCertPemForPython(str(cert_config_path).encode(), None, 0)
        if _cert_len <= 0:
            logger.error("ECP:       %s ECP returned cert_len=%d", SYM_CROSS, _cert_len)
            return
        logger.info("ECP:       %s Certificate retrieved (%d bytes)", SYM_CHECK, _cert_len)
    except Exception as e:
        logger.error("ECP:       %s %s", SYM_CROSS, e)
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

        # Who am I?
        whoami_res = authed_session.get(
            f"https://{crm_base}/v1/projects/wif-bunker-whoami-00000",
        )
        if whoami_res.status_code == 403:
            error_msg = whoami_res.json().get("error", {}).get("message", "")
            match = re.search(r"principal://\S+", error_msg)
            if match:
                principal = match.group(0).rstrip(".")
                logger.info("Principal: %s", principal)
    except Exception as e:
        logger.error("ADC:       %s %s", SYM_CROSS, e)
        logger.error("Re-run with --debug for detailed ECP and TLS diagnostics.")
