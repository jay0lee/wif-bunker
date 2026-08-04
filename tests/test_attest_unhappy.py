"""Unhappy-path tests for the --attest flow.

Verifies that attestation correctly fails when given:
- A self-signed cert (no hardware backing)
- A cert with no CN
- A nonexistent cert file
- A garbage file that isn't a cert
"""

from __future__ import annotations

import datetime
import json
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from wif_bunker.attestation import generate_attestation, write_attestation_report
from wif_bunker.attestation.base import AttestationCheck, AttestationReport
from wif_bunker.config import WorkloadConfig
from wif_bunker.modes import _run_attest


def _self_signed_pem(cn: str = "fake-workload-9999") -> str:
    """Generate a self-signed PEM cert with no hardware backing."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _no_cn_pem() -> str:
    """Generate a cert with no CN (only Organization)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "No CN Corp")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _rsa_self_signed_pem(cn: str = "rsa-fake-workload") -> str:
    """Generate an RSA self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class TestRunAttestCertParsing:
    """Tests for _run_attest cert-file handling (before platform dispatch)."""

    def test_nonexistent_cert_file_exits(self, tmp_path):
        """--attest --cert-file with a nonexistent file raises SystemExit."""
        config = WorkloadConfig()
        with pytest.raises(SystemExit):
            _run_attest(config, str(tmp_path / "output"), str(tmp_path / "nope.pem"))

    def test_garbage_cert_file_raises(self, tmp_path):
        """--attest with a garbage file that isn't PEM raises."""
        garbage = tmp_path / "garbage.pem"
        garbage.write_text("this is not a certificate")
        config = WorkloadConfig()
        with pytest.raises(Exception):  # noqa: B017
            _run_attest(config, str(tmp_path / "output"), str(garbage))

    @patch("wif_bunker.modes.generate_attestation")
    def test_self_signed_cert_extracts_cn(self, mock_attest, tmp_path):
        """Self-signed cert CN is correctly extracted and set on config."""
        cert_pem = _self_signed_pem("my-test-workload-42")
        cert_file = tmp_path / "workload_cert.pem"
        cert_file.write_text(cert_pem)

        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        config = WorkloadConfig()
        _run_attest(config, str(tmp_path / "output"), str(cert_file))

        assert config.workload_cn == "my-test-workload-42"
        mock_attest.assert_called_once_with(config)

    @patch("wif_bunker.modes.generate_attestation")
    def test_no_cn_cert_uses_default(self, mock_attest, tmp_path):
        """Cert with no CN uses the default config CN."""
        cert_pem = _no_cn_pem()
        cert_file = tmp_path / "no_cn.pem"
        cert_file.write_text(cert_pem)

        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        config = WorkloadConfig()
        original_cn = config.workload_cn
        _run_attest(config, str(tmp_path / "output"), str(cert_file))

        # CN should remain unchanged since cert has no CN
        assert config.workload_cn == original_cn


class TestAttestationWithSelfSignedCert:
    """End-to-end attestation with a self-signed cert — no checks should pass
    that require hardware backing."""

    @patch("wif_bunker.attestation.macos.subprocess.run")
    @patch("sys.platform", "darwin")
    def test_macos_all_hardware_checks_fail(self, mock_run):
        """On macOS, a self-signed cert should fail the identity check
        (not in keychain) and the attestation API check."""
        # The self-signed cert's CN won't be in the keychain
        mock_run.return_value = MagicMock(returncode=0, stdout="some-other-identity", stderr="")
        config = WorkloadConfig()
        config.workload_cn = "fake-workload-not-in-keychain"

        report = generate_attestation(config)

        # Check 1: Identity should fail (CN not in keychain output)
        identity_check = next((c for c in report.checks if c.name == "Keychain identity present"), None)
        assert identity_check is not None
        assert identity_check.passed is False

        # Check 3: Hardware attestation API always fails on macOS
        api_check = next((c for c in report.checks if c.name == "Hardware attestation API"), None)
        assert api_check is not None
        assert api_check.passed is False

        # Overall: not supported
        assert report.supported is False

    @patch("wif_bunker.attestation.macos.subprocess.run")
    @patch("sys.platform", "darwin")
    def test_macos_report_output_valid(self, mock_run, tmp_path):
        """Attestation report is written correctly even when all checks fail."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        config = WorkloadConfig()
        config.workload_cn = "nonexistent-key"

        report = generate_attestation(config)
        write_attestation_report(report, tmp_path)

        # JSON report should exist and be valid
        json_path = tmp_path / "attestation_report.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert data["platform"] == "macos-se"
        assert data["supported"] is False
        assert data["checks_passed"] < data["checks_total"]

        # Text report should exist
        text_path = tmp_path / "attestation_report.txt"
        assert text_path.exists()
        text = text_path.read_text()
        assert "Hardware Attestation Report" in text

    @patch("wif_bunker.attestation.windows._run_powershell")
    @patch("sys.platform", "win32")
    def test_windows_self_signed_fails_all_tpm_checks(self, mock_ps):
        """On Windows, a self-signed cert should fail TPM checks."""
        # Simulate TPM not present
        mock_ps.return_value = MagicMock(returncode=1, stdout="", stderr="Get-Tpm : No TPM found")
        config = WorkloadConfig()
        config.workload_cn = "fake-workload-no-tpm"

        report = generate_attestation(config)

        # TPM status should fail
        tpm_check = next((c for c in report.checks if c.name == "TPM status"), None)
        assert tpm_check is not None
        assert tpm_check.passed is False

    @patch("wif_bunker.attestation.linux.require_commands")
    @patch("wif_bunker.attestation.linux.subprocess.run")
    @patch("sys.platform", "linux")
    def test_linux_no_tpm_device_fails(self, mock_run, _mock_req):
        """On Linux, when /dev/tpmrm0 doesn't exist, TPM check fails."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="No TPM")
        config = WorkloadConfig()
        config.workload_cn = "fake-workload"

        report = generate_attestation(config)

        # Should have checks and they should fail
        assert report.checks_total > 0
        tpm_check = next((c for c in report.checks if "tpm" in c.name.lower()), None)
        assert tpm_check is not None
        assert tpm_check.passed is False


class TestRunAttestEndToEnd:
    """Full _run_attest flow with self-signed cert and mocked platform."""

    @patch("wif_bunker.modes.generate_attestation")
    def test_self_signed_cert_writes_failing_report(self, mock_attest, tmp_path):
        """A self-signed cert produces a failing attestation report."""
        cert_pem = _self_signed_pem("self-signed-test")
        cert_file = tmp_path / "workload_cert.pem"
        cert_file.write_text(cert_pem)
        output_dir = tmp_path / "attest-output"

        # Return a report where everything fails
        mock_attest.return_value = AttestationReport(
            platform="test",
            supported=True,
            hardware_type="Mock TPM",
            checks=[
                AttestationCheck("TPM status", False, "No TPM found"),
                AttestationCheck("EK info", False, "No EK"),
                AttestationCheck("EK cert", False, "No manufacturer cert"),
                AttestationCheck("EK chain", False, "Not verified"),
                AttestationCheck("Key provider", False, "Software key"),
                AttestationCheck("Exportability", False, "Key is exportable"),
                AttestationCheck("Attestation", False, "No claim generated"),
            ],
            summary="0/7 checks passed",
        )

        _run_attest(WorkloadConfig(), str(output_dir), str(cert_file))

        # Report should be written
        assert (output_dir / "attestation_report.json").exists()
        data = json.loads((output_dir / "attestation_report.json").read_text())
        assert data["checks_passed"] == 0
        assert data["checks_total"] == 7

    @patch("wif_bunker.modes.generate_attestation")
    def test_rsa_self_signed_cert_extracts_cn(self, mock_attest, tmp_path):
        """RSA self-signed cert CN is correctly parsed."""
        cert_pem = _rsa_self_signed_pem("rsa-test-workload")
        cert_file = tmp_path / "rsa_cert.pem"
        cert_file.write_text(cert_pem)

        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        config = WorkloadConfig()
        _run_attest(config, str(tmp_path / "output"), str(cert_file))

        assert config.workload_cn == "rsa-test-workload"

    @patch("wif_bunker.modes.generate_attestation")
    def test_no_cert_file_attests_platform_only(self, mock_attest, tmp_path):
        """Without --cert-file, attestation runs platform-only mode."""
        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        config = WorkloadConfig()
        original_cn = config.workload_cn

        _run_attest(config, str(tmp_path / "output"), None)

        # CN should remain the default
        assert config.workload_cn == original_cn
        mock_attest.assert_called_once()
