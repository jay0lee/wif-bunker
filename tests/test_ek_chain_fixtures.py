"""Tests using real hardware EK certificates and crafted bogus certificates.

These tests validate chain verification against actual production certs
from real hardware, not just dynamically generated test certs. This catches
real-world issues like:
- AIA chasing for Intel TPMs
- DER encoding quirks (e.g. Nuvoton InvalidSetOrdering)
- Manually-managed root CA loading
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wif_bunker.attestation.base import verify_ek_chain

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestRealHardwareCerts:
    """Tests using real EK certificates extracted from production hardware."""

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "nuc_intel_ek.pem").exists(),
        reason="Intel NUC EK cert fixture not available",
    )
    def test_intel_nuc_ek_verifies(self):
        """Real Intel NUC8 EK cert should verify against bundled + manually-managed certs.

        Chain: EK → CNL intermediate (manually-managed) → Intel TPM EK Root (manually-managed).
        No AIA chasing needed — all certs are bundled locally.
        """
        ek_pem = (FIXTURES_DIR / "nuc_intel_ek.pem").read_text()
        result = verify_ek_chain(ek_pem)
        assert result.passed is True, f"Intel NUC EK should verify: {result.detail}"

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "nuc_intel_ek.pem").exists(),
        reason="Intel NUC EK cert fixture not available",
    )
    def test_intel_nuc_ek_has_aia_extension(self):
        """Verify the Intel NUC EK cert actually has an AIA extension.

        This is a smoke test to ensure our fixture is the right cert.
        Note: Intel EK certs have non-canonical DER encoding that
        cryptography's strict parser rejects, so we use openssl CLI.
        """
        import subprocess

        ek_pem = (FIXTURES_DIR / "nuc_intel_ek.pem").read_text()
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=ek_pem,
            capture_output=True,
            text=True,
        )
        assert "CA Issuers - URI:" in result.stdout, "Intel NUC EK cert should have AIA CA Issuers"
        assert "intel.com" in result.stdout, "AIA URI should reference intel.com"

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "nuc_intel_ek.pem").exists(),
        reason="Intel NUC EK cert fixture not available",
    )
    def test_intel_nuc_ek_issuer_is_intel(self):
        """Verify the Intel NUC EK cert issuer is Intel Corporation."""
        import subprocess

        ek_pem = (FIXTURES_DIR / "nuc_intel_ek.pem").read_text()
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer"],
            input=ek_pem,
            capture_output=True,
            text=True,
        )
        assert "Intel" in result.stdout

    # --- Dell Nuvoton (InvalidSetOrdering DER) ---

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "dell_nuvoton_ek.pem").exists(),
        reason="Dell Nuvoton EK cert fixture not available",
    )
    def test_dell_nuvoton_ek_triggers_pyopenssl_fallback(self):
        """Dell Nuvoton EK cert has InvalidSetOrdering — cryptography rejects it.

        This MUST trigger the pyOpenSSL fallback path. If cryptography ever
        starts accepting it, this test documents that the cert works either way.
        """
        from cryptography import x509 as cx509

        ek_pem = (FIXTURES_DIR / "dell_nuvoton_ek.pem").read_text()

        # Confirm cryptography's strict parser still rejects this cert
        with pytest.raises(ValueError, match="InvalidSetOrdering"):
            cx509.load_pem_x509_certificate(ek_pem.encode())

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "dell_nuvoton_ek.pem").exists(),
        reason="Dell Nuvoton EK cert fixture not available",
    )
    def test_dell_nuvoton_ek_verifies(self):
        """Dell Nuvoton EK cert should verify against bundled roots.

        The Nuvoton TPM Root CA 2111 is in our bundled roots, so this
        should succeed without AIA chasing — pure local verification.
        """
        ek_pem = (FIXTURES_DIR / "dell_nuvoton_ek.pem").read_text()
        result = verify_ek_chain(ek_pem)
        assert result.passed is True, f"Dell Nuvoton EK should verify: {result.detail}"

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "dell_nuvoton_ek.pem").exists(),
        reason="Dell Nuvoton EK cert fixture not available",
    )
    def test_dell_nuvoton_ek_issuer_is_nuvoton(self):
        """Verify the Dell EK cert issuer is Nuvoton."""
        import subprocess

        ek_pem = (FIXTURES_DIR / "dell_nuvoton_ek.pem").read_text()
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer"],
            input=ek_pem,
            capture_output=True,
            text=True,
        )
        assert "Nuvoton" in result.stdout


class TestBogusCerts:
    """Tests using crafted bogus certificates that MUST fail verification."""

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "bogus_self_signed.pem").exists(),
        reason="Bogus cert fixtures not generated — run tests/generate_bogus_certs.py",
    )
    def test_self_signed_ek_rejected(self):
        """A self-signed cert pretending to be an EK must be rejected."""
        ek_pem = (FIXTURES_DIR / "bogus_self_signed.pem").read_text()
        result = verify_ek_chain(ek_pem)
        assert result.passed is False, "Self-signed bogus EK should not verify"

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "bogus_wrong_signer.pem").exists(),
        reason="Bogus cert fixtures not generated — run tests/generate_bogus_certs.py",
    )
    def test_wrong_signer_rejected(self):
        """A cert signed by an untrusted CA must be rejected."""
        ek_pem = (FIXTURES_DIR / "bogus_wrong_signer.pem").read_text()
        result = verify_ek_chain(ek_pem)
        assert result.passed is False, "Cert signed by rogue CA should not verify"

    @pytest.mark.skipif(
        not (FIXTURES_DIR / "bogus_expired.pem").exists(),
        reason="Bogus cert fixtures not generated — run tests/generate_bogus_certs.py",
    )
    def test_expired_cert_rejected(self):
        """An expired cert must be rejected."""
        ek_pem = (FIXTURES_DIR / "bogus_expired.pem").read_text()
        result = verify_ek_chain(ek_pem)
        assert result.passed is False, "Expired bogus EK should not verify"

    def test_garbage_pem_rejected(self):
        """Completely invalid PEM data must be rejected."""
        result = verify_ek_chain("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----")
        assert result.passed is False

    def test_empty_string_rejected(self):
        """Empty string must be rejected."""
        result = verify_ek_chain("")
        assert result.passed is False

    def test_non_pem_text_rejected(self):
        """Plain text that isn't PEM must be rejected."""
        result = verify_ek_chain("this is not a certificate at all")
        assert result.passed is False
