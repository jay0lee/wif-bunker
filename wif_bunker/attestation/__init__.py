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
    logger.info("  Summary: %s", report.summary)

    if report.documentation_urls:
        logger.info("")
        logger.info("  References:")
        for url in report.documentation_urls:
            logger.info("    %s", url)

    if report.verification_steps:
        logger.info("")
        logger.info("  Verification Steps:")
        for step in report.verification_steps:
            logger.info("    %s", step)

    logger.info("=" * 70)


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

    lines.append(f"  Summary: {report.summary}")
    lines.append("")

    if report.artifacts:
        lines.append("  Artifacts:")
        for artifact in report.artifacts:
            lines.append(f"    - {artifact.filename}: {artifact.description}")
        lines.append("")

    if report.documentation_urls:
        lines.append("  References:")
        for url in report.documentation_urls:
            lines.append(f"    {url}")
        lines.append("")

    if report.verification_steps:
        lines.append("  Verification Steps:")
        for step in report.verification_steps:
            lines.append(f"    {step}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines) + "\n"
