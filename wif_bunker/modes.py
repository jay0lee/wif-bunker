"""Alternate CLI modes: status, attest, and versions."""

from __future__ import annotations

import importlib
import json
import logging
import os
import platform
import ssl
import struct
import sys
from pathlib import Path
from typing import Any

import requests

from wif_bunker import __version__
from wif_bunker.attestation import generate_attestation, print_attestation_summary, write_attestation_report
from wif_bunker.config import BunkerConfig, WorkloadConfig
from wif_bunker.oidc import mint_google_access_token, verify_project_access
from wif_bunker.signers import load_signer
from wif_bunker.utils import SYM_CHECK, SYM_CROSS, SYM_WARN

logger = logging.getLogger(__name__)


def _default_attest_dir() -> str:
    """Return the platform-appropriate default attestation output directory."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        return str(Path(base) / "wif-bunker" / "attestation")
    return str(Path.home() / ".config" / "wif-bunker" / "attestation")


def _run_attest(
    config: WorkloadConfig,
    output_dir: str | None = None,
    bunker_config_path: str | None = None,
) -> None:
    """Run read-only hardware attestation on a pre-existing hardware key."""
    target_dir = output_dir or _default_attest_dir()
    logger.info("=== Hardware Key Attestation ===")

    # If bunker.json exists (or --config was passed), inherit key locator details
    cfg_path = Path(bunker_config_path) if bunker_config_path else Path.cwd() / "bunker.json"
    if cfg_path.exists():
        try:
            bunker_cfg = BunkerConfig.load(cfg_path)
            signer_cfg = bunker_cfg.signer
            stype = signer_cfg.get("type", "")
            if stype == "linux-tpm" and config.linux_tpm_handle is None and signer_cfg.get("handle"):
                raw = signer_cfg["handle"]
                config.linux_tpm_handle = int(raw, 0) if isinstance(raw, str) else int(raw)
                config.workload_cn = f"tpm:{config.linux_tpm_handle:#010x}"
                logger.info("  Loaded Linux TPM handle 0x%08x from %s", config.linux_tpm_handle, cfg_path)
            elif stype == "yubikey" and not config.use_yubikey:
                config.use_yubikey = True
                if signer_cfg.get("slot"):
                    config.yubikey_slot = str(signer_cfg["slot"])
                if signer_cfg.get("serial") is not None:
                    config.yubikey_serial = int(signer_cfg["serial"])
                logger.info("  Loaded YubiKey slot %s from %s", config.yubikey_slot, cfg_path)
            elif stype == "windows-certstore":
                if signer_cfg.get("subject"):
                    config.workload_cn = str(signer_cfg["subject"])
                if signer_cfg.get("thumbprint"):
                    config.signer_params["thumbprint"] = str(signer_cfg["thumbprint"])
                if signer_cfg.get("store_location"):
                    config.windows_store_location = str(signer_cfg["store_location"])
                logger.info("  Loaded Windows certstore subject '%s' from %s", config.workload_cn, cfg_path)
            elif stype == "macos-secureenclave" and signer_cfg.get("label"):
                config.workload_cn = str(signer_cfg["label"])
                logger.info("  Loaded macOS Secure Enclave label '%s' from %s", config.workload_cn, cfg_path)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("  Could not load %s for attestation hints: %s", cfg_path, exc)

    logger.info("  Output directory: %s", target_dir)
    logger.info("")

    report = generate_attestation(config)
    write_attestation_report(report, Path(target_dir))
    print_attestation_summary(report)

    logger.info("")
    logger.info("Attestation artifacts written to: %s", target_dir)


def _check_agent_health(adc_path: Path) -> None:
    """If ``adc.json`` points at a localhost ``wif-bunker agent``, probe ``/health``."""
    if not adc_path.exists():
        logger.info("ADC file:  %s %s (not generated yet)", SYM_WARN, adc_path)
        return
    try:
        adc_cfg = json.loads(adc_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("ADC file:  %s Invalid JSON in %s: %s", SYM_CROSS, adc_path, exc)
        return

    token_url = str(adc_cfg.get("token_url", ""))
    cred_src = adc_cfg.get("credential_source", {})
    if token_url.startswith("http://127.0.0.1:"):
        health_url = token_url.rsplit("/v1/token", 1)[0] + "/health"
        try:
            resp = requests.get(health_url, timeout=3)
            resp.raise_for_status()
            stats: dict[str, Any] = resp.json()
            logger.info(
                "Agent:     %s Running at %s (hardware_signs=%s, cache_hits=%s)",
                SYM_CHECK,
                token_url,
                stats.get("hardware_signs", 0),
                stats.get("cache_hits", 0),
            )
        except requests.RequestException:
            logger.warning("Agent:     %s Not running at %s (start with: wif-bunker agent)", SYM_WARN, token_url)
    elif "executable" in cred_src:
        logger.info("ADC mode:  %s Executable (%s)", SYM_CHECK, cred_src["executable"].get("command", ""))
    else:
        logger.info("ADC file:  %s Present (%s)", SYM_CHECK, adc_path)


def _run_status(config_path: str | None = None, adc_path: str | None = None) -> None:
    """Show current WIF Bunker OIDC configuration status and run live token verification."""
    logger.info("=== WIF Bunker Status ===")

    bunker_file = Path(config_path) if config_path else Path.cwd() / "bunker.json"
    adc_file = Path(adc_path) if adc_path else Path.cwd() / "adc.json"

    if not bunker_file.exists():
        logger.error("Config:    %s %s not found.", SYM_CROSS, bunker_file)
        logger.error("Run 'wif-bunker setup' first to bind your hardware key to GCP OIDC WIF.")
        return

    try:
        bunker_cfg = BunkerConfig.load(bunker_file)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Config:    %s Failed to load %s: %s", SYM_CROSS, bunker_file, exc)
        return

    logger.info("Config:    %s %s", SYM_CHECK, bunker_file)
    logger.info("  Project:         %s (%s)", bunker_cfg.project_id, bunker_cfg.project_number)
    logger.info("  WIF Pool:        %s", bunker_cfg.pool_id)
    logger.info("  OIDC Provider:   %s", bunker_cfg.provider_id)
    logger.info("  Issuer URI:      %s", bunker_cfg.issuer_uri)
    logger.info("  Subject:         %s", bunker_cfg.subject)
    logger.info("  Service Account: %s", bunker_cfg.service_account_email or "(direct WIF — no SA)")
    logger.info(
        "  Key:             %s (alg=%s, kid=%s)",
        bunker_cfg.signer.get("type", "unknown"),
        bunker_cfg.public_jwk.get("alg", "?"),
        bunker_cfg.public_jwk.get("kid", "?"),
    )

    logger.info("")
    _check_agent_health(adc_file)

    # Verify signer can be opened and matches configured public key
    logger.info("")
    try:
        signer = load_signer(bunker_cfg.signer)
        logger.info(
            "Signer:    %s Loaded '%s' (alg=%s, kid=%s)",
            SYM_CHECK,
            bunker_cfg.signer.get("type"),
            signer.algorithm,
            signer.key_id,
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Signer:    %s %s", SYM_CROSS, exc)
        return

    # Live OIDC JWT → STS → SA token exchange + project API check
    try:
        token, expiry = mint_google_access_token(
            bunker_cfg,
            signer,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        logger.info("OIDC STS:  %s Token minted successfully (expires epoch=%d)", SYM_CHECK, expiry)

        proj_data = verify_project_access(token, bunker_cfg.project_id, timeout=15)
        logger.info("GCP API:   %s Project call succeeded (%s)", SYM_CHECK, proj_data.get("name", ""))
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        body = exc.response.text[:300] if exc.response is not None else str(exc)
        logger.error("OIDC/API:  %s HTTP %s: %s", SYM_CROSS, status, body)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("OIDC/API:  %s %s", SYM_CROSS, exc)


def _run_all_versions() -> None:
    """Print comprehensive version, signer availability, environment, and system info."""

    def _safe_version(module_name: str) -> str:
        try:
            mod = importlib.import_module(module_name)
            return str(getattr(mod, "__version__", getattr(mod, "VERSION", "(installed)")))
        except ImportError:
            return "(not installed)"
        except Exception as exc:  # pylint: disable=broad-except
            return f"(error: {exc})"

    print("WIF Bunker")
    print(f"  wif-bunker:        {__version__}")

    print("\nPython")
    print(f"  Python:            {platform.python_version()}")
    print(f"  Implementation:    {platform.python_implementation()}")
    print(f"  Executable:        {sys.executable}")
    print(f"  SSL:               {ssl.OPENSSL_VERSION}")
    frozen = getattr(sys, "frozen", False)
    if frozen:
        print(f"  Frozen:            {frozen} (PyInstaller bundle)")

    print("\nCore Dependencies")
    print(f"  cryptography:      {_safe_version('cryptography')}")
    print(f"  pyOpenSSL:         {_safe_version('OpenSSL')}")
    print(f"  google-auth:       {_safe_version('google.auth')}")
    print(f"  google.auth.dpop:  {_safe_version('google.auth.dpop')}")
    print(f"  requests:          {_safe_version('requests')}")

    print("\nHardware Signer Backends (dpop-signers)")
    signer_modules = [
        ("linux-tpm", "dpop_signer_linux_tpm"),
        ("windows-certstore", "dpop_signer_windows_certstore"),
        ("macos-secureenclave", "dpop_signer_macos_secureenclave"),
        ("yubikey", "dpop_signer_yubikey"),
        ("pkcs11", "dpop_signer_pkcs11"),
        ("fido2-previewsign", "dpop_signer_fido2_previewsign"),
    ]
    for label, mod_name in signer_modules:
        print(f"  {label:<20} {_safe_version(mod_name)}")

    if sys.platform == "linux":
        print(f"  tpm2-pytss:        {_safe_version('tpm2_pytss')}")

    print("\nEnvironment Variables")
    env_keys = [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
        "GOOGLE_CLOUD_PROJECT",
        "XDG_RUNTIME_DIR",
        "TPM2TOOLS_TCTI",
        "PKCS11_MODULE",
    ]
    found_any = False
    for key in env_keys:
        val = os.environ.get(key)
        if val is not None:
            found_any = True
            print(f"  {key}={val}")
    if not found_any:
        print("  (none of the relevant variables are set)")

    print("\nSystem")
    print(f"  OS:                {platform.system()} {platform.release()}")
    print(f"  Platform:          {platform.platform()}")
    print(f"  Machine:           {platform.machine()}")
    print(f"  Architecture:      {struct.calcsize('P') * 8}-bit")

    print("\nConfig Files")
    for fname in ("bunker.json", "adc.json"):
        fpath = Path.cwd() / fname
        if fpath.exists():
            print(f"  {SYM_CHECK} {fname} ({fpath.stat().st_size} bytes)")
        else:
            print(f"  {SYM_CROSS} {fname}")
