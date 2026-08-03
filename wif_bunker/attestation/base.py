"""Attestation result dataclasses shared across all platform implementations."""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

logger = logging.getLogger(__name__)


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
    # Optional enrichment data for visual chain display
    platform_info: dict | None = None  # OEM platform cert details (if found)
    ek_details: dict | None = None  # Parsed EK certificate details
    tpm_info: dict | None = None  # Raw Get-Tpm info

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
    """Load all PEM certificates from a directory, skipping unparseable files."""
    certs = []
    for pem_file in sorted(directory.glob("*.pem")):
        try:
            certs.append(x509.load_pem_x509_certificate(pem_file.read_bytes()))
        except Exception:
            # Some manufacturer CA certs have non-canonical DER encoding.
            # Skip rather than crash the entire chain verification.
            pass
    return certs


def _verify_ek_chain_pyopenssl(ek_pem: str, roots_dir: Path, intermediates_dir: Path) -> AttestationCheck:
    """Verify EK cert chain using pyOpenSSL when cryptography's strict parser fails.

    **Why this exists:**

    The ``cryptography`` library (>= v42) uses a strict Rust-based X.509
    parser that rejects certificates with non-canonical DER encoding — in
    particular, SET OF elements that aren't sorted in lexicographic order
    (``InvalidSetOrdering``).  The library maintainers intentionally refuse
    to add a leniency flag for this (see pyca/cryptography#7189).

    Several major TPM manufacturers (e.g. Nuvoton on Dell hardware) ship
    EK certificates that violate this rule.  The certificate data itself is
    perfectly valid — OpenSSL has no trouble with it.

    OpenSSL's ``d2i_X509`` / ``i2d_X509`` preserves original DER byte
    ordering on output, so the "re-encode to fix" approach doesn't work.
    Instead we use ``pyOpenSSL``'s ``X509StoreContext`` to do the **entire**
    chain verification natively in OpenSSL's C library — no conversion back
    to ``cryptography`` needed.
    """
    from OpenSSL.crypto import (
        FILETYPE_PEM,
        X509Store,
        X509StoreContext,
        X509StoreContextError,
        load_certificate,
    )

    logger.debug("Using pyOpenSSL X509StoreContext for EK chain verification")

    try:
        ek_cert = load_certificate(FILETYPE_PEM, ek_pem.encode("utf-8"))
    except Exception as e:
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=f"pyOpenSSL could not parse EK certificate either: {e}",
        )

    # Build an X509Store with all root CAs.
    store = X509Store()
    roots_loaded = 0
    for pem_file in sorted(roots_dir.glob("*.pem")):
        try:
            ca_cert = load_certificate(FILETYPE_PEM, pem_file.read_bytes())
            store.add_cert(ca_cert)
            roots_loaded += 1
        except Exception:
            pass

    if roots_loaded == 0:
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail="No root CA certificates could be loaded by pyOpenSSL.",
        )

    # Load intermediates (untrusted chain certs).
    intermediates = []
    if intermediates_dir.exists():
        for pem_file in sorted(intermediates_dir.glob("*.pem")):
            try:
                intermediates.append(load_certificate(FILETYPE_PEM, pem_file.read_bytes()))
            except Exception:
                pass

    # Verify the chain using OpenSSL's C library.
    try:
        ctx = X509StoreContext(store, ek_cert, chain=intermediates)
        ctx.verify_certificate()
    except X509StoreContextError as e:
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=f"EK certificate chain verification failed (pyOpenSSL): {e}",
        )

    return AttestationCheck(
        name="EK certificate chain verified",
        passed=True,
        detail=(
            "EK certificate verified against tpm-ca-certificates bundle "
            "(via pyOpenSSL — cert has non-standard DER encoding)"
        ),
    )


def verify_ek_chain(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs.

    Shared by Linux and Windows attestation modules. Loads individual
    root and intermediate CA PEMs from the ``roots/roots/`` and
    ``roots/intermediates/`` directories (sourced from
    https://github.com/loicsikidi/tpm-ca-certificates) and uses
    cryptography.x509.verification.

    Falls back to pyOpenSSL's X509StoreContext for certs with non-canonical
    DER encoding (e.g. Nuvoton TPMs with InvalidSetOrdering in issuer).
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

    # Try the standard path: cryptography's strict parser.
    ek_cert = None
    try:
        ek_cert = x509.load_pem_x509_certificate(ek_pem.encode("utf-8"))
    except Exception:
        # Strict parser rejected the cert (e.g. InvalidSetOrdering).
        # Fall back to pyOpenSSL for the entire chain verification.
        logger.debug("cryptography's strict parser rejected EK cert; falling back to pyOpenSSL")
        return _verify_ek_chain_pyopenssl(ek_pem, roots_dir, intermediates_dir)

    try:
        roots = _load_certs(roots_dir)
        intermediates = []
        if intermediates_dir.exists():
            intermediates = _load_certs(intermediates_dir)

        # Build issuer lookup using raw subject bytes.
        all_ca_certs: list[x509.Certificate] = roots + intermediates
        issuer_lookup: dict[bytes, x509.Certificate] = {}
        for cert in all_ca_certs:
            try:
                issuer_lookup[cert.subject.public_bytes()] = cert
            except Exception:
                pass

        # Walk up the chain from the EK cert to a trusted root.
        current = ek_cert
        depth = 0
        max_depth = 10
        while depth < max_depth:
            try:
                issuer_bytes = current.issuer.public_bytes()
            except Exception:
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=False,
                    detail=(
                        "Could not read EK certificate issuer field. "
                        "The TPM manufacturer may have used non-standard DER encoding."
                    ),
                )

            issuer_cert = issuer_lookup.get(issuer_bytes)
            if issuer_cert is None:
                try:
                    issuer_str = current.issuer.rfc4514_string()
                except Exception:
                    issuer_str = "(unparseable issuer)"
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=False,
                    detail=(f"Could not find issuer '{issuer_str}' in bundled manufacturer CA certificates."),
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

            if issuer_cert in roots:
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=True,
                    detail=(
                        "EK certificate verified against tpm-ca-certificates bundle "
                        "(https://github.com/loicsikidi/tpm-ca-certificates)"
                    ),
                )

            current = issuer_cert
            depth += 1

        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail="Certificate chain too deep (exceeded 10 levels).",
        )
    except Exception as e:
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=f"EK certificate did not chain to any bundled manufacturer root CA. Error: {e}",
        )
