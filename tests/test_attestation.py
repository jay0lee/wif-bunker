"""Tests for the attestation module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from wif_bunker.attestation.base import (
    AttestationArtifact,
    AttestationCheck,
    AttestationReport,
)


class TestAttestationCheck:
    """Tests for AttestationCheck dataclass."""

    def test_basic_creation(self):
        """Create a passing check."""
        check = AttestationCheck(name="EK cert", passed=True, detail="Found")
        assert check.name == "EK cert"
        assert check.passed is True
        assert check.detail == "Found"

    def test_failing_check(self):
        """Create a failing check."""
        check = AttestationCheck(name="Chain", passed=False, detail="No root CA")
        assert check.passed is False


class TestAttestationArtifact:
    """Tests for AttestationArtifact dataclass."""

    def test_text_artifact(self):
        """Create a text artifact."""
        art = AttestationArtifact(filename="ek.pem", content="---PEM---", description="EK cert")
        assert art.filename == "ek.pem"
        assert art.is_binary is False

    def test_binary_artifact(self):
        """Create a binary artifact."""
        art = AttestationArtifact(
            filename="attest.bin",
            content=b"\x00\x01",
            description="Attest blob",
            is_binary=True,
        )
        assert art.is_binary is True
        assert isinstance(art.content, bytes)


class TestAttestationReport:
    """Tests for AttestationReport dataclass."""

    def test_empty_report(self):
        """Report with no checks."""
        report = AttestationReport(platform="test", supported=True, hardware_type="Test")
        assert report.checks_passed == 0
        assert report.checks_total == 0

    def test_mixed_checks(self):
        """Report with mixed pass/fail checks."""
        report = AttestationReport(
            platform="linux-tpm2",
            supported=True,
            hardware_type="TPM 2.0",
            checks=[
                AttestationCheck("A", True, "ok"),
                AttestationCheck("B", False, "fail"),
                AttestationCheck("C", True, "ok"),
            ],
        )
        assert report.checks_passed == 2
        assert report.checks_total == 3

    def test_unsupported_report(self):
        """Report for unsupported platform."""
        report = AttestationReport(
            platform="macos-se",
            supported=False,
            hardware_type="Secure Enclave",
            not_supported_reason="No API",
        )
        assert report.supported is False
        assert report.not_supported_reason == "No API"

    def test_to_dict(self):
        """Serialization to dict."""
        report = AttestationReport(
            platform="linux-tpm2",
            supported=True,
            hardware_type="TPM 2.0",
            checks=[AttestationCheck("EK", True, "found")],
            artifacts=[AttestationArtifact("ek.pem", "content", "EK cert")],
            summary="1/1 passed",
            documentation_urls=["https://example.com"],
            verification_steps=["Step 1"],
        )
        data = report.to_dict()
        assert data["platform"] == "linux-tpm2"
        assert data["checks_passed"] == 1
        assert data["checks_total"] == 1
        assert len(data["artifacts"]) == 1
        assert data["artifacts"][0]["filename"] == "ek.pem"
        # Ensure it's JSON-serializable
        json_str = json.dumps(data)
        assert "linux-tpm2" in json_str


class TestMacOSAttestation:
    """Tests for macOS attestation stub."""

    @patch("wif_bunker.attestation.macos.subprocess.run")
    def test_returns_unsupported(self, mock_run):
        """macOS attestation always returns supported=False."""
        from wif_bunker.attestation.macos import _attest_macos

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        config = MagicMock()
        config.workload_cn = "test-workload"

        report = _attest_macos(config)

        assert report.supported is False
        assert report.platform == "macos-se"
        assert report.hardware_type == "Secure Enclave"
        assert report.not_supported_reason is not None
        assert "Apple" in report.not_supported_reason or "attestation" in report.not_supported_reason.lower()

    @patch("wif_bunker.attestation.macos.subprocess.run")
    def test_documentation_urls(self, mock_run):
        """macOS stub includes Apple documentation URLs."""
        from wif_bunker.attestation.macos import _attest_macos

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        config = MagicMock()
        config.workload_cn = "test"

        report = _attest_macos(config)

        assert len(report.documentation_urls) >= 3
        assert any("developer.apple.com" in url for url in report.documentation_urls)
        assert any("devicecheck" in url for url in report.documentation_urls)

    @patch("wif_bunker.attestation.macos.subprocess.run")
    def test_hardware_attestation_check_fails(self, mock_run):
        """The 'Hardware attestation API' check always fails."""
        from wif_bunker.attestation.macos import _attest_macos

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        config = MagicMock()
        config.workload_cn = "test"

        report = _attest_macos(config)

        api_check = next((c for c in report.checks if c.name == "Hardware attestation API"), None)
        assert api_check is not None
        assert api_check.passed is False
        assert "DCAppAttestService" in api_check.detail

    @patch("wif_bunker.attestation.macos.subprocess.run")
    def test_keychain_identity_found(self, mock_run):
        """Keychain check passes when identity is found."""
        from wif_bunker.attestation.macos import _attest_macos

        def side_effect(args, **kwargs):
            if "find-identity" in args:
                return MagicMock(returncode=0, stdout="my-workload-cn", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        config = MagicMock()
        config.workload_cn = "my-workload-cn"

        report = _attest_macos(config)

        identity_check = next((c for c in report.checks if c.name == "Keychain identity present"), None)
        assert identity_check is not None
        assert identity_check.passed is True


class TestAttestationDispatcher:
    """Tests for the platform dispatcher."""

    @patch("sys.platform", "darwin")
    @patch("wif_bunker.attestation.macos._attest_macos")
    def test_dispatches_to_macos(self, mock_attest):
        """Dispatcher routes darwin to macOS attestation."""
        from wif_bunker.attestation import generate_attestation

        mock_report = AttestationReport(platform="macos-se", supported=False, hardware_type="Secure Enclave")
        mock_attest.return_value = mock_report
        config = MagicMock()
        config.use_yubikey = False

        result = generate_attestation(config)
        assert result.platform == "macos-se"
        mock_attest.assert_called_once_with(config)


class TestReportWriter:
    """Tests for report writing functionality."""

    def test_write_text_artifacts(self, tmp_path):
        """Text artifacts are written correctly."""
        from wif_bunker.attestation import write_attestation_report

        report = AttestationReport(
            platform="test",
            supported=True,
            hardware_type="Test",
            artifacts=[
                AttestationArtifact("test.pem", "PEM CONTENT", "Test cert"),
            ],
            checks=[AttestationCheck("Test", True, "ok")],
            summary="All good",
        )

        write_attestation_report(report, tmp_path)

        assert (tmp_path / "test.pem").read_text() == "PEM CONTENT"
        assert (tmp_path / "attestation_report.json").exists()
        assert (tmp_path / "attestation_report.txt").exists()

        # Verify JSON report
        json_data = json.loads((tmp_path / "attestation_report.json").read_text())
        assert json_data["platform"] == "test"
        assert json_data["checks_passed"] == 1

    def test_write_binary_artifacts(self, tmp_path):
        """Binary artifacts are written correctly."""
        from wif_bunker.attestation import write_attestation_report

        report = AttestationReport(
            platform="test",
            supported=True,
            hardware_type="Test",
            artifacts=[
                AttestationArtifact("blob.bin", b"\x00\x01\x02", "Binary blob", is_binary=True),
            ],
        )

        write_attestation_report(report, tmp_path)

        assert (tmp_path / "blob.bin").read_bytes() == b"\x00\x01\x02"

    def test_creates_output_directory(self, tmp_path):
        """Output directory is created if it doesn't exist."""
        from wif_bunker.attestation import write_attestation_report

        output = tmp_path / "nested" / "dir"
        report = AttestationReport(platform="test", supported=True, hardware_type="Test")

        write_attestation_report(report, output)
        assert output.exists()
        assert (output / "attestation_report.json").exists()
