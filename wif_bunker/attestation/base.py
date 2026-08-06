"""Attestation result dataclasses shared across all platform implementations.

.. ai-note::
   IMPORTANT FOR AI AGENTS: Before reading, editing, or debugging this file,
   you MUST read docs/attestation-overview.md in the repository root.
   That document covers the shared data model, EK chain verification logic,
   AIA chasing, ASN.1 compatibility (pyOpenSSL vs cryptography), and the
   trust chain architecture.  If you make changes to this file, update
   docs/attestation-overview.md to match.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509

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
    workload_cn: str = ""  # Workload certificate CN for chain display

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


def _verify_ek_chain_openssl(
    ek_pem: str, roots_dir: Path, intermediates_dir: Path, manually_managed_dir: Path | None = None
) -> AttestationCheck:
    """Verify EK cert chain using pyOpenSSL's X509StoreContext.

    Uses OpenSSL's native chain verification rather than the ``cryptography``
    library's strict Rust-based parser, which rejects certificates with
    non-canonical DER encoding (e.g. ``InvalidSetOrdering`` in Nuvoton TPMs).
    See pyca/cryptography#7189 — the maintainers refuse to add leniency.

    In practice, 100% of real-world TPM EK certificates we've tested
    (Intel, Nuvoton/Dell) require this path — either because the cert has
    non-standard encoding, or because an intermediate must be fetched via
    AIA chasing (which only this path implements).

    Includes AIA (Authority Information Access) chasing: if the issuer
    certificate is not bundled locally, it fetches intermediates from the
    URLs embedded in the cert's AIA extension (up to 3 levels deep).
    """
    import re
    import subprocess
    import urllib.request

    import OpenSSL.crypto
    from OpenSSL.crypto import (
        FILETYPE_ASN1,
        FILETYPE_PEM,
        X509Store,
        X509StoreContext,
        X509StoreContextError,
        load_certificate,
    )

    logger.debug("Verifying EK chain via OpenSSL X509StoreContext")

    try:
        ek_cert = load_certificate(FILETYPE_PEM, ek_pem.encode("utf-8"))
    except Exception as e:
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=f"Could not parse EK certificate: {e}",
        )

    # Build an X509Store with all root CAs.
    store = X509Store()
    roots_loaded = 0
    dirs_to_check = [roots_dir]
    if manually_managed_dir:
        dirs_to_check.append(manually_managed_dir)

    for d in dirs_to_check:
        if d.exists():
            for pem_file in sorted(d.glob("*.pem")):
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
            detail="No root CA certificates could be loaded.",
        )

    # Load intermediates (untrusted chain certs).
    intermediates = []
    dirs_to_check_int = [intermediates_dir]
    if manually_managed_dir:
        dirs_to_check_int.append(manually_managed_dir)

    for d in dirs_to_check_int:
        if d.exists():
            for pem_file in sorted(d.glob("*.pem")):
                try:
                    intermediates.append(load_certificate(FILETYPE_PEM, pem_file.read_bytes()))
                except Exception:
                    pass

    logger.info(
        "    EK chain: %d roots loaded, %d intermediates loaded (dirs: %s)",
        roots_loaded,
        len(intermediates),
        ", ".join(str(d) for d in dirs_to_check + dirs_to_check_int if d.exists()),
    )

    # AIA Chasing logic
    def _verify_with_aia_chasing(current_cert, depth=0):
        try:
            ctx = X509StoreContext(store, current_cert, chain=intermediates)
            ctx.verify_certificate()
            return True, ""
        except X509StoreContextError as e:
            if "unable to get local issuer certificate" in str(e) and depth < 3:
                # Try AIA chasing — extract the issuer cert URL from the AIA extension.
                cert_pem = OpenSSL.crypto.dump_certificate(FILETYPE_PEM, current_cert).decode("utf-8")
                result = subprocess.run(
                    ["openssl", "x509", "-noout", "-text"],
                    input=cert_pem,
                    capture_output=True,
                    text=True,
                )
                m = re.search(r"CA Issuers - URI:(https?://[^\s]+)", result.stdout)
                if not m:
                    logger.info(
                        "    AIA: openssl x509 -text returned rc=%d, stdout=%d bytes, stderr=%s",
                        result.returncode,
                        len(result.stdout),
                        result.stderr.strip()[:200] if result.stderr else "(empty)",
                    )
                    return False, (
                        f"{e} — cert has no AIA extension with a CA Issuers URL, "
                        "so the missing issuer cannot be fetched automatically"
                    )
                url = m.group(1)
                try:
                    logger.info("    AIA chasing: fetching issuer cert from %s", url)
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=10) as response:
                        cert_data = response.read()

                    try:
                        fetched_cert = load_certificate(FILETYPE_PEM, cert_data)
                    except Exception:
                        fetched_cert = load_certificate(FILETYPE_ASN1, cert_data)

                    intermediates.append(fetched_cert)

                    # Retry verification with the newly fetched intermediate in the chain.
                    return _verify_with_aia_chasing(current_cert, depth + 1)
                except Exception as fetch_err:
                    return False, (f"{e} — AIA fetch from {url} failed: {fetch_err}")
            return False, str(e)

    success, err_msg = _verify_with_aia_chasing(ek_cert)

    if not success:
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=f"EK certificate chain verification failed: {err_msg}",
        )

    return AttestationCheck(
        name="EK certificate chain verified",
        passed=True,
        detail=(
            "EK certificate verified against tpm-ca-certificates bundle "
            "(https://github.com/loicsikidi/tpm-ca-certificates)"
        ),
    )


def verify_ek_chain(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs.

    Shared by Linux and Windows attestation modules. Loads root and
    intermediate CA PEMs from the ``roots/`` directory tree (sourced from
    https://github.com/loicsikidi/tpm-ca-certificates) and verifies the
    EK cert chain using OpenSSL's X509StoreContext via pyOpenSSL.

    Includes AIA chasing for intermediates not bundled locally.
    """
    # In PyInstaller builds, data files are extracted under sys._MEIPASS
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        certs_dir = Path(sys._MEIPASS) / "wif_bunker" / "attestation" / "roots"
    else:
        certs_dir = Path(__file__).parent / "roots"
    roots_dir = certs_dir / "roots"
    intermediates_dir = certs_dir / "intermediates"
    manually_managed_dir = certs_dir / "manually-managed"

    if not roots_dir.exists() or not any(roots_dir.glob("*.pem")):
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail="No manufacturer root CA certificates bundled. Chain verification skipped.",
        )

    return _verify_ek_chain_openssl(ek_pem, roots_dir, intermediates_dir, manually_managed_dir)


# TPM Manufacturer IDs — the ManufacturerId from Get-Tpm is a 32-bit int
# encoding 4 ASCII bytes (the TCG-registered vendor ID).
# See: https://trustedcomputinggroup.org/resource/vendor-id-registry/
_TPM_MANUFACTURERS: dict[int, tuple[str, str]] = {
    # decimal: (short_name, full_name)
    1095582720: ("AMD", "Advanced Micro Devices"),
    1096043852: ("ATML", "Atmel"),
    1112687437: ("BRCM", "Broadcom"),
    1213220096: ("HPE", "HPE"),
    1229081856: ("IBM", "IBM"),
    1229346816: ("IFX", "Infineon"),
    1229870147: ("INTC", "Intel"),
    1280398708: ("LEN", "Lenovo"),
    1314145024: ("NTC", "Nuvoton Technology"),
    1314406208: ("NTZ", "Nationz Technologies"),
    1363365956: ("QCOM", "Qualcomm"),
    1397576515: ("SMSC", "SMSC"),
    1398033696: ("STM", "STMicroelectronics"),
    1398895469: ("SMSN", "Samsung"),
    1413828608: ("TXN", "Texas Instruments"),
    1464156928: ("WEC", "Winbond"),
    1380926275: ("ROCC", "Futurex"),
    1196379975: ("GOOG", "Google"),
    1297302852: ("MSFT", "Microsoft"),
}

# TCG EK certificate OIDs for TPM hardware attributes.
# These appear in the Subject Alternative Name or Subject Directory Attributes.
_TCG_OID_TPM_MANUFACTURER = "2.23.133.2.1"
_TCG_OID_TPM_MODEL = "2.23.133.2.2"
_TCG_OID_TPM_VERSION = "2.23.133.2.3"


def _parse_tcg_attributes(cert_obj: x509.Certificate) -> dict[str, str]:
    """Extract TCG hardware attributes from an EK certificate.

    TCG EK certificates encode TPM manufacturer, model, and firmware
    version in the Subject Alternative Name (SAN) extension using
    OIDs under 2.23.133.2.

    Returns a dict with keys like 'tpm_manufacturer', 'tpm_model',
    'tpm_version' when found.
    """
    attrs: dict[str, str] = {}
    tcg_oid_map = {
        _TCG_OID_TPM_MANUFACTURER: "tpm_manufacturer",
        _TCG_OID_TPM_MODEL: "tpm_model",
        _TCG_OID_TPM_VERSION: "tpm_version",
    }

    # Try Subject Directory Attributes first, then SAN.
    # Both are used by different manufacturers.
    for ext in cert_obj.extensions:
        oid_str = ext.oid.dotted_string

        # Check if this is a TCG attribute extension directly
        if oid_str in tcg_oid_map:
            try:
                raw = ext.value.value if hasattr(ext.value, "value") else bytes(ext.value)
                decoded = raw.decode("utf-8", errors="replace").strip("\x00").strip()
                if decoded:
                    attrs[tcg_oid_map[oid_str]] = decoded
            except Exception:  # pylint: disable=broad-except
                pass
            continue

        # Check SubjectAlternativeName — TCG attributes may be in
        # directoryName entries within the SAN
        if oid_str == "2.5.29.17":  # subjectAltName
            try:
                san = ext.value
                for name in san:
                    if isinstance(name, x509.DirectoryName):
                        for attr in name.value:
                            attr_oid = attr.oid.dotted_string
                            if attr_oid in tcg_oid_map:
                                attrs[tcg_oid_map[attr_oid]] = attr.value
            except Exception:  # pylint: disable=broad-except
                pass

    return attrs


def _decode_manufacturer_id(mfr_id: int | str) -> str:
    """Decode a TPM ManufacturerId to a human-readable name.

    The ManufacturerId from Get-Tpm is a 32-bit integer encoding
    4 ASCII bytes — the TCG-registered vendor ID.
    e.g. 1314145024 = 0x4E544300 = 'NTC\0' = Nuvoton Technology.
    """
    try:
        mfr_int = int(mfr_id)
    except (TypeError, ValueError):
        return str(mfr_id)

    entry = _TPM_MANUFACTURERS.get(mfr_int)
    if entry:
        short, full = entry
        return f"{full} ({short})"

    # Fallback: try to decode as ASCII
    try:
        ascii_str = mfr_int.to_bytes(4, "big").decode("ascii").rstrip("\x00").strip()
        if ascii_str:
            return f"{ascii_str} (0x{mfr_int:08X})"
    except (UnicodeDecodeError, OverflowError):
        pass
    return f"0x{mfr_int:08X}"


def parse_ek_details(ek_pem: str) -> dict:
    """Extract details from an EK PEM certificate."""
    details: dict[str, str] = {}
    try:
        cert_obj = x509.load_pem_x509_certificate(ek_pem.encode())
        details["issuer"] = cert_obj.issuer.rfc4514_string()
        details["serial"] = format(cert_obj.serial_number, "X")
        details["not_before"] = cert_obj.not_valid_before_utc.strftime("%Y-%m-%d")
        details["not_after"] = cert_obj.not_valid_after_utc.strftime("%Y-%m-%d")

        tcg_attrs = _parse_tcg_attributes(cert_obj)
        details.update(tcg_attrs)
    except Exception:  # pylint: disable=broad-except
        # Strict parser failed (e.g. Intel non-standard ASN.1).
        # Fall back to pyOpenSSL for basic fields.
        try:
            from OpenSSL.crypto import FILETYPE_PEM, load_certificate  # pylint: disable=import-outside-toplevel

            ossl_cert = load_certificate(FILETYPE_PEM, ek_pem.encode())
            details["issuer"] = ", ".join(
                f"{k.decode()}={v.decode()}" for k, v in ossl_cert.get_issuer().get_components()
            )
            details["serial"] = format(ossl_cert.get_serial_number(), "X")
        except Exception:  # pylint: disable=broad-except
            details.setdefault("issuer", "unknown")
    return details
