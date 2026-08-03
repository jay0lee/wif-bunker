"""Attestation result dataclasses shared across all platform implementations."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AttestationArtifact:
    """A single attestation output file."""

    filename: str  # e.g. "ek_certificate.pem"
    content: str | bytes  # PEM text or binary blob
    description: str  # Human-readable explanation
    is_binary: bool = False  # True for .bin files, False for text/PEM


@dataclass
class AttestationCheck:
    """A single attestation verification check."""

    name: str  # e.g. "EK Certificate Chain Valid"
    passed: bool
    detail: str  # Evidence/explanation


@dataclass
class AttestationReport:
    """Complete attestation result for a platform."""

    platform: str  # "linux-tpm2", "windows-cng", "macos-se"
    supported: bool  # False for macOS
    hardware_type: str  # "TPM 2.0", "Secure Enclave", "CNG/TPM"
    artifacts: list[AttestationArtifact] = field(default_factory=list)
    checks: list[AttestationCheck] = field(default_factory=list)
    summary: str = ""
    not_supported_reason: str | None = None
    documentation_urls: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)

    @property
    def checks_passed(self) -> int:
        """Count of passed checks."""
        return sum(1 for chk in self.checks if chk.passed)

    @property
    def checks_total(self) -> int:
        """Total number of checks."""
        return len(self.checks)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dictionary."""
        return {
            "platform": self.platform,
            "supported": self.supported,
            "hardware_type": self.hardware_type,
            "checks_passed": self.checks_passed,
            "checks_total": self.checks_total,
            "checks": [{"name": chk.name, "passed": chk.passed, "detail": chk.detail} for chk in self.checks],
            "artifacts": [{"filename": art.filename, "description": art.description} for art in self.artifacts],
            "summary": self.summary,
            "not_supported_reason": self.not_supported_reason,
            "documentation_urls": self.documentation_urls,
            "verification_steps": self.verification_steps,
        }


def verify_ek_chain(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs.

    Shared by Linux and Windows attestation modules. Writes the EK PEM
    to a temp file, iterates over bundled root CAs, and runs ``openssl verify``.
    """
    roots_dir = Path(__file__).parent / "roots"
    if not roots_dir.exists() or not any(roots_dir.glob("*.pem")):
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail="No manufacturer root CA certificates bundled. Chain verification skipped.",
        )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
        tmp.write(ek_pem)
        ek_path = tmp.name

    try:
        for root_ca in sorted(roots_dir.glob("*.pem")):
            result = subprocess.run(
                ["openssl", "verify", "-CAfile", str(root_ca), ek_path],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and ": OK" in result.stdout:
                manufacturer = root_ca.stem.replace("_", " ").title()
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=True,
                    detail=f"EK certificate verified against {manufacturer} root CA ({root_ca.name})",
                )
    finally:
        Path(ek_path).unlink(missing_ok=True)

    return AttestationCheck(
        name="EK certificate chain verified",
        passed=False,
        detail=(
            "EK certificate did not chain to any bundled manufacturer root CA. "
            "The TPM manufacturer's root CA may not be bundled yet."
        ),
    )
