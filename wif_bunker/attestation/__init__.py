"""Hardware key attestation — platform dispatcher and report writer.

Dispatches to platform-specific attestation implementations and handles
writing attestation artifacts and reports to the output directory.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from wif_bunker.attestation.base import AttestationReport
from wif_bunker.config import WorkloadConfig
from wif_bunker.utils import SYM_CHECK, SYM_CROSS, SYM_WARN

logger = logging.getLogger(__name__)

# Symbols for terminal output
_SYM_OK = SYM_CHECK
_SYM_FAIL = SYM_CROSS
_SYM_WARN = SYM_WARN


def generate_attestation(config: WorkloadConfig) -> AttestationReport:
    """Dispatch to the platform-specific attestation implementation."""
    platform = sys.platform
    generators = {
        "linux": "_attest_linux",
        "darwin": "_attest_macos",
        "win32": "_attest_windows",
    }

    for prefix, _ in generators.items():
        if platform.startswith(prefix):
            # Lazy import to avoid loading platform-specific code on wrong OS
            if prefix == "linux":
                from wif_bunker.attestation.linux import _attest_linux  # pylint: disable=import-outside-toplevel

                return _attest_linux(config)
            if prefix == "darwin":
                from wif_bunker.attestation.macos import _attest_macos  # pylint: disable=import-outside-toplevel

                return _attest_macos(config)
            if prefix == "win32":
                from wif_bunker.attestation.windows import _attest_windows  # pylint: disable=import-outside-toplevel

                return _attest_windows(config)

    raise RuntimeError(f"Unsupported platform for attestation: {platform}")


def write_attestation_report(report: AttestationReport, output_dir: Path) -> None:
    """Write all attestation artifacts and reports to the output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write individual artifacts
    for artifact in report.artifacts:
        artifact_path = output_dir / artifact.filename
        if artifact.is_binary:
            artifact_path.write_bytes(
                artifact.content if isinstance(artifact.content, bytes) else artifact.content.encode()
            )
        else:
            artifact_path.write_text(
                artifact.content if isinstance(artifact.content, str) else artifact.content.decode(),
                encoding="utf-8",
            )
        logger.info("  Wrote %s — %s", artifact.filename, artifact.description)

    # Write machine-readable JSON report
    json_path = output_dir / "attestation_report.json"
    json_path.write_text(
        json.dumps(report.to_dict(), indent=2),
        encoding="utf-8",
    )
    logger.info("  Wrote attestation_report.json")

    # Write human-readable text report
    text_path = output_dir / "attestation_report.txt"
    text_path.write_text(_format_text_report(report), encoding="utf-8")
    logger.info("  Wrote attestation_report.txt")


def print_attestation_summary(report: AttestationReport) -> None:
    """Print a human-readable attestation summary to the terminal."""
    logger.info("")
    logger.info("=" * 70)
    logger.info("  Hardware Attestation Report")
    logger.info("=" * 70)
    logger.info("  Platform:      %s", report.platform)
    logger.info("  Hardware Type: %s", report.hardware_type)
    logger.info("  Supported:     %s", "Yes" if report.supported else "No")
    logger.info("")

    if not report.supported and report.not_supported_reason:
        logger.warning("  %s Hardware attestation is not available on this platform.", _SYM_WARN)
        logger.warning("")
        for line in report.not_supported_reason.split("\n"):
            logger.warning("  %s", line)
        logger.warning("")

    for check in report.checks:
        sym = _SYM_OK if check.passed else _SYM_FAIL
        logger.info("  %s %s", sym, check.name)
        logger.info("    %s", check.detail)

    logger.info("")
    all_passed = report.checks and all(c.passed for c in report.checks)
    if all_passed:
        logger.info("  🎉🎆 %s 🎆🎉", report.summary)
    else:
        logger.info("  %s", report.summary)

    logger.info("=" * 70)

    # Visual attestation chain when all checks pass
    all_passed = report.checks and all(c.passed for c in report.checks)
    if all_passed:
        _print_attestation_chain(report)


def _box(label: str, lines: list[str], width: int = 55) -> list[str]:
    """Build an ASCII box with a label and content lines."""
    result = []
    inner = width - 4  # account for "│  " and "  │"
    result.append(f"  ┌─ {label} {'─' * max(0, inner - len(label) - 1)}┐")
    for line in lines:
        padded = line[:inner].ljust(inner)
        result.append(f"  │  {padded}│")
    result.append(f"  └{'─' * (width - 2)}┘")
    return result


def _print_attestation_chain(report: AttestationReport) -> None:
    """Print a visual attestation chain diagram."""
    logger.info("")
    logger.info("  Attestation Chain")
    logger.info("  ═════════════════")
    logger.info("")

    W = 55  # box width
    connector_pad = " " * ((W // 2) - 1)

    # Platform Certificate box (if found — OEM attested)
    pi = report.platform_info
    if pi and pi.get("manufacturer"):
        mfr = pi.get("manufacturer", "Unknown OEM")
        model = pi.get("model", "")
        sn = pi.get("serial_number", "")
        issuer = pi.get("issuer", "unknown")
        plat_lines = [f"{mfr} {model}".strip()]
        if sn:
            plat_lines.append(f"S/N: {sn}")
        plat_lines.append(f"Signed by: {issuer[:45]}")
        for line in _box("Platform (OEM Attested) 🏭", plat_lines, W):
            logger.info(line)
        logger.info(f"{connector_pad}│ contains (platform cert)")

    # TPM Hardware box
    tpm = report.tpm_info or {}
    ek = report.ek_details or {}

    # Build TPM manufacturer string
    mfr_id = tpm.get("ManufacturerId", 0)
    try:
        from wif_bunker.attestation.windows import _decode_manufacturer_id

        tpm_mfr = _decode_manufacturer_id(mfr_id) if mfr_id else "Unknown"
    except ImportError:
        tpm_mfr = str(mfr_id) if mfr_id else "Unknown"
    tpm_model = ek.get("tpm_model", "")
    fw = tpm.get("ManufacturerVersion", "")

    tpm_lines = [f"{tpm_mfr}"]
    if tpm_model:
        tpm_lines[0] += f" {tpm_model}"
    if fw:
        tpm_lines[0] += f", FW {fw}"

    # EK info
    ek_issuer = ek.get("issuer", "")
    if ek_issuer:
        ek_short = ek_issuer[:45]
        tpm_lines.append(f"EK Issuer: {ek_short}")
    ek_serial = ek.get("serial", "")
    if ek_serial:
        tpm_lines.append(f"EK Serial: {ek_serial[:30]}...")

    for line in _box("TPM Hardware (Cryptographic) 🔐", tpm_lines, W):
        logger.info(line)
    logger.info(f"{connector_pad}│ certifies (NCryptCreateClaim)")

    # Workload Key box
    # Extract workload key name from checks
    wk_name = ""
    wk_provider = ""
    for check in report.checks:
        if check.name == "Key storage provider" and check.passed:
            # Parse key name from detail
            if "'" in check.detail:
                parts = check.detail.split("'")
                if len(parts) >= 2:
                    wk_name = parts[1]
            if "Platform Crypto Provider" in check.detail:
                wk_provider = "Platform Crypto Provider (TPM)"

    wk_lines = [wk_name or "workload key"]
    if wk_provider:
        wk_lines.append(f"Provider: {wk_provider}")
    wk_lines.append(f"Non-exportable: {_SYM_OK}")

    for line in _box("Workload Key 🔑", wk_lines, W):
        logger.info(line)
    logger.info(f"{connector_pad}│ bound to certificate")

    # mTLS Identity box
    mtls_lines = [
        f"CN={wk_name or 'workload'}",
        "mTLS via ECP → STS → GCP IAM",
    ]
    for line in _box("mTLS Identity 🌐", mtls_lines, W):
        logger.info(line)

    # Platform cert note
    if not pi or not pi.get("manufacturer"):
        logger.info("")
        logger.info("  (i) Platform Certificate not found at TPM NV 0x01C08000")
        logger.info("     (OEM binding unavailable — common on business PCs)")

    logger.info("")


def _format_text_report(report: AttestationReport) -> str:
    """Format a complete human-readable text report."""
    lines = [
        "=" * 70,
        "  Hardware Attestation Report",
        "=" * 70,
        f"  Platform:      {report.platform}",
        f"  Hardware Type: {report.hardware_type}",
        f"  Supported:     {'Yes' if report.supported else 'No'}",
        "",
    ]

    if not report.supported and report.not_supported_reason:
        lines.append(f"  {_SYM_WARN} Hardware attestation is not available on this platform.")
        lines.append("")
        for line in report.not_supported_reason.split("\n"):
            lines.append(f"  {line}")
        lines.append("")

    lines.append("  Checks:")
    for check in report.checks:
        sym = _SYM_OK if check.passed else _SYM_FAIL
        lines.append(f"    {sym} {check.name}")
        lines.append(f"      {check.detail}")
    lines.append("")

    all_passed = report.checks and all(c.passed for c in report.checks)
    if all_passed:
        lines.append(f"  🎉🎆 {report.summary} 🎆🎉")
    else:
        lines.append(f"  {report.summary}")
    lines.append("")

    if report.artifacts:
        lines.append("  Artifacts:")
        for artifact in report.artifacts:
            lines.append(f"    - {artifact.filename}: {artifact.description}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines) + "\n"
