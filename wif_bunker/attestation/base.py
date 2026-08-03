"""Attestation result dataclasses shared across all platform implementations."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


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


def _load_certs(directory: Path) -> list[x509.Certificate]:
    """Load all PEM certificates from a directory."""
    certs = []
    for pem_file in sorted(directory.glob("*.pem")):
        certs.append(x509.load_pem_x509_certificate(pem_file.read_bytes()))
    return certs


def verify_ek_chain(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs.

    Shared by Linux and Windows attestation modules. Loads individual
    root and intermediate CA PEMs from the ``roots/roots/`` and
    ``roots/intermediates/`` directories (sourced from
    https://github.com/loicsikidi/tpm-ca-certificates) and uses
    cryptography.x509.verification.
    """
    # In PyInstaller builds, data files are extracted under sys._MEIPASS
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        certs_dir = Path(sys._MEIPASS) / "wif_bunker" / "attestation" / "roots"
    else:
        certs_dir = Path(__file__).parent / "roots"
    roots_dir = certs_dir / "roots"
    intermediates_dir = certs_dir / "intermediates"

    if not roots_dir.exists() or not any(roots_dir.glob("*.pem")):
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail="No manufacturer root CA certificates bundled. Chain verification skipped.",
        )

    try:
        ek_cert = x509.load_pem_x509_certificate(ek_pem.encode("utf-8"))

        roots = _load_certs(roots_dir)
        intermediates = []
        if intermediates_dir.exists():
            intermediates = _load_certs(intermediates_dir)

        # Build a lookup of potential issuers by subject.
        all_ca_certs = {cert.subject: cert for cert in roots + intermediates}

        # Walk up the chain from the EK cert to a trusted root.
        current = ek_cert
        depth = 0
        max_depth = 10
        while depth < max_depth:
            # Find the issuer cert.
            issuer_cert = all_ca_certs.get(current.issuer)
            if issuer_cert is None:
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=False,
                    detail=(
                        f"Could not find issuer '{current.issuer.rfc4514_string()}' "
                        "in bundled manufacturer CA certificates."
                    ),
                )

            # Verify the signature.
            issuer_pub = issuer_cert.public_key()
            if isinstance(issuer_pub, rsa.RSAPublicKey):
                issuer_pub.verify(
                    current.signature,
                    current.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    current.signature_hash_algorithm,
                )
            elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
                issuer_pub.verify(
                    current.signature,
                    current.tbs_certificate_bytes,
                    ec.ECDSA(current.signature_hash_algorithm),
                )
            else:
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=False,
                    detail=f"Unsupported key type: {type(issuer_pub).__name__}",
                )

            # If the issuer is a trusted root, chain is verified.
            if issuer_cert in roots:
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=True,
                    detail=(
                        "EK certificate verified against tpm-ca-certificates bundle "
                        "(https://github.com/loicsikidi/tpm-ca-certificates)"
                    ),
                )

            # Move up the chain.
            current = issuer_cert
            depth += 1

        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail="Certificate chain too deep (exceeded 10 levels).",
        )
    except Exception as e:
        stderr_hint = f" Error: {e}"
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=f"EK certificate did not chain to any bundled manufacturer root CA.{stderr_hint}",
        )
