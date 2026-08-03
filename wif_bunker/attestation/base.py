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


def _load_cert_lenient(pem_data: bytes) -> x509.Certificate:
    """Load a PEM certificate, falling back to pyOpenSSL for non-canonical DER.

    **Why this exists:**

    The ``cryptography`` library (>= v42) uses a strict Rust-based X.509
    parser that rejects certificates with non-canonical DER encoding — in
    particular, SET OF elements that aren't sorted in lexicographic order
    (``InvalidSetOrdering``).  The library maintainers intentionally refuse
    to add a leniency flag for this (see pyca/cryptography#7189).

    Unfortunately, several major TPM manufacturers ship EK certificates
    that violate this rule.  Nuvoton TPMs (found in Dell hardware) are a
    known example — their issuer field has attributes in the "wrong" order.
    The certificate data itself is perfectly valid and OpenSSL has no
    trouble with it; it's only ``cryptography``'s Rust layer that objects.

    **How it works:**

    ``pyOpenSSL`` wraps OpenSSL's C library (the same one ``cryptography``
    bundles for its own crypto operations) and exposes the lenient
    ``PEM_read_bio_X509`` / ``d2i_X509`` functions.  We use it to:

    1. Load the cert via OpenSSL's lenient C parser
    2. Re-encode it back to PEM — OpenSSL normalises the DER on output
    3. Feed the cleaned PEM to ``cryptography``'s strict parser

    This way all downstream code gets a proper ``cryptography`` cert
    object with full access to ``.issuer``, ``.tbs_certificate_bytes``,
    ``.signature``, etc.
    """
    # Happy path: cryptography can parse this cert natively.
    try:
        return x509.load_pem_x509_certificate(pem_data)
    except Exception:
        pass

    # Fallback: the cert has non-standard DER encoding that cryptography
    # rejects.  Use pyOpenSSL (OpenSSL C library) to re-encode it.
    # pyOpenSSL is a pure-Python package that uses the OpenSSL already
    # bundled inside cryptography — no new native dependencies.
    from OpenSSL.crypto import FILETYPE_PEM, dump_certificate, load_certificate

    logger.debug("cryptography's strict parser rejected cert; re-encoding via pyOpenSSL")
    openssl_cert = load_certificate(FILETYPE_PEM, pem_data)
    fixed_pem = dump_certificate(FILETYPE_PEM, openssl_cert)
    return x509.load_pem_x509_certificate(fixed_pem)


def verify_ek_chain(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs.

    Shared by Linux and Windows attestation modules. Loads individual
    root and intermediate CA PEMs from the ``roots/roots/`` and
    ``roots/intermediates/`` directories (sourced from
    https://github.com/loicsikidi/tpm-ca-certificates) and uses
    cryptography.x509.verification.

    Falls back to pyOpenSSL re-encoding for certs with non-canonical DER
    encoding (e.g. Nuvoton TPMs with InvalidSetOrdering in issuer).
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
        ek_cert = _load_cert_lenient(ek_pem.encode("utf-8"))
    except Exception as e:
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=f"Could not parse EK certificate: {e}",
        )

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
