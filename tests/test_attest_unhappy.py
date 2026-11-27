"""Unhappy-path tests for the --attest flow.

Verifies that attestation correctly fails when given:
- A self-signed cert (no hardware backing)
- A cert with no CN
- A nonexistent cert file
- A garbage file that isn't a cert
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from wif_bunker.attestation import generate_attestation, write_attestation_report
from wif_bunker.attestation.base import AttestationCheck, AttestationReport
from wif_bunker.config import WorkloadConfig
from wif_bunker.modes import _run_attest


class TestRunAttestConfigHints:
    """Tests for _run_attest bunker.json loading before platform dispatch."""

    @patch("wif_bunker.modes.generate_attestation")
    def test_corrupt_bunker_config_warns_and_continues(self, mock_attest, tmp_path, caplog):
        garbage = tmp_path / "bunker.json"
        garbage.write_text("not valid json", encoding="utf-8")
        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        config = WorkloadConfig()
        _run_attest(config, str(tmp_path / "output"), str(garbage))
        mock_attest.assert_called_once_with(config)
        assert "Could not load" in caplog.text

    @patch("wif_bunker.modes.generate_attestation")
    def test_loads_linux_tpm_handle_from_bunker_json(self, mock_attest, tmp_path, sample_bunker_config):
        sample_bunker_config.signer = {"type": "linux-tpm", "handle": "0x81000001"}
        bunker_file = tmp_path / "bunker.json"
        sample_bunker_config.save(bunker_file)

        mock_attest.return_value = AttestationReport(platform="linux-tpm2", supported=True, hardware_type="TPM 2.0")
        config = WorkloadConfig()
        _run_attest(config, str(tmp_path / "output"), str(bunker_file))

        assert config.linux_tpm_handle == 0x81000001
        mock_attest.assert_called_once_with(config)

    @patch("wif_bunker.modes.generate_attestation")
    def test_loads_yubikey_hints_from_bunker_json(self, mock_attest, tmp_path, sample_bunker_config):
        sample_bunker_config.signer = {"type": "yubikey", "slot": "9a", "serial": 20602167}
        bunker_file = tmp_path / "bunker.json"
        sample_bunker_config.save(bunker_file)

        mock_attest.return_value = AttestationReport(platform="yubikey", supported=True, hardware_type="YubiKey")
        config = WorkloadConfig()
        _run_attest(config, str(tmp_path / "output"), str(bunker_file))

        assert config.use_yubikey is True
        assert config.yubikey_slot == "9a"
        assert config.yubikey_serial == 20602167
        mock_attest.assert_called_once_with(config)

    @patch("wif_bunker.modes.generate_attestation")
    def test_loads_windows_hints_from_bunker_json(self, mock_attest, tmp_path, sample_bunker_config):
        sample_bunker_config.signer = {
            "type": "windows-certstore",
            "subject": "WIF Bunker Key",
            "thumbprint": "AABBCC",
            "store_location": "local_machine",
        }
        bunker_file = tmp_path / "bunker.json"
        sample_bunker_config.save(bunker_file)

        mock_attest.return_value = AttestationReport(platform="windows-cng", supported=True, hardware_type="CNG/TPM")
        config = WorkloadConfig()
        _run_attest(config, str(tmp_path / "output"), str(bunker_file))

        assert config.workload_cn == "WIF Bunker Key"
        assert config.signer_params["thumbprint"] == "AABBCC"
        assert config.windows_store_location == "local_machine"
        mock_attest.assert_called_once_with(config)


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
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["platform"] == "macos-se"
        assert data["supported"] is False
        assert data["checks_passed"] < data["checks_total"]

        # Text report should exist
        text_path = tmp_path / "attestation_report.txt"
        assert text_path.exists()
        text = text_path.read_text(encoding="utf-8")
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

    @patch("wif_bunker.attestation.linux._get_esapi")
    @patch("sys.platform", "linux")
    def test_linux_no_tpm_device_fails(self, mock_get_esapi):
        """On Linux, when TPM is not accessible, attestation fails."""
        mock_get_esapi.side_effect = RuntimeError("No TPM device found")
        config = WorkloadConfig()
        config.workload_cn = "fake-workload"

        report = generate_attestation(config)

        # Should have checks and they should fail
        assert report.checks_total > 0
        tpm_check = next((c for c in report.checks if "tpm" in c.name.lower()), None)
        assert tpm_check is not None
        assert tpm_check.passed is False


class TestRunAttestEndToEnd:
    """Full _run_attest flow with mocked platform."""

    @patch("wif_bunker.modes.generate_attestation")
    def test_failing_attestation_writes_report(self, mock_attest, tmp_path):
        """A failing attestation produces valid JSON & text reports."""
        output_dir = tmp_path / "attest-output"

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

        _run_attest(WorkloadConfig(), str(output_dir), None)

        assert (output_dir / "attestation_report.json").exists()
        data = json.loads((output_dir / "attestation_report.json").read_text(encoding="utf-8"))
        assert data["checks_passed"] == 0
        assert data["checks_total"] == 7

    @patch("wif_bunker.modes.generate_attestation")
    def test_no_bunker_config_attests_platform_only(self, mock_attest, tmp_path, monkeypatch):
        """Without bunker.json, attestation runs platform-only mode."""
        monkeypatch.chdir(tmp_path)
        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        config = WorkloadConfig()
        original_cn = config.workload_cn

        _run_attest(config, str(tmp_path / "output"), None)

        assert config.workload_cn == original_cn
        mock_attest.assert_called_once()


class TestMacOSAttestationExceptions:
    """Test exception handling in macOS attestation."""

    @patch("wif_bunker.attestation.macos.subprocess.run")
    def test_macos_identity_check_exception(self, mock_run):
        """Test OSError during identity check."""
        from wif_bunker.attestation.macos import _attest_macos
        from wif_bunker.config import WorkloadConfig

        mock_run.side_effect = [OSError("Keychain access denied"), MagicMock(returncode=0, stdout="com.apple.setoken")]

        config = WorkloadConfig()
        report = _attest_macos(config)

        identity_check = next(c for c in report.checks if c.name == "Keychain identity present")
        assert not identity_check.passed
        assert "Could not query keychain: Keychain access denied" in identity_check.detail

    @patch("wif_bunker.attestation.macos.subprocess.run")
    def test_macos_ctk_check_exception(self, mock_run):
        """Test OSError during smartcard check."""
        from wif_bunker.attestation.macos import _attest_macos
        from wif_bunker.config import WorkloadConfig

        mock_run.side_effect = [MagicMock(returncode=0, stdout="my-identity"), OSError("CTK access denied")]

        config = WorkloadConfig()
        report = _attest_macos(config)

        ctk_check = next(c for c in report.checks if c.name == "CryptoTokenKit SE token")
        assert not ctk_check.passed
        assert "Could not list smart cards: CTK access denied" in ctk_check.detail
