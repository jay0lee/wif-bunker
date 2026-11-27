"""Tests for wif_bunker.modes (status, attest, versions)."""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock, patch

import requests

from wif_bunker.attestation.base import AttestationReport
from wif_bunker.config import WorkloadConfig
from wif_bunker.modes import _check_agent_health, _default_attest_dir, _run_all_versions, _run_attest, _run_status


class TestDefaultAttestDir:
    @patch("sys.platform", "win32")
    def test_windows_path(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake/appdata")
        result = _default_attest_dir()
        assert "wif-bunker" in result
        assert "attestation" in result

    @patch("sys.platform", "linux")
    def test_non_windows_path(self):
        result = _default_attest_dir()
        assert ".config/wif-bunker/attestation" in result.replace("\\", "/")


class TestCheckAgentHealth:
    def test_missing_adc_file(self, tmp_path, caplog):
        with caplog.at_level(logging.INFO):
            _check_agent_health(tmp_path / "adc.json")
        assert "not generated yet" in caplog.text

    def test_invalid_adc_json(self, tmp_path, caplog):
        adc = tmp_path / "adc.json"
        adc.write_text("{bad", encoding="utf-8")
        with caplog.at_level(logging.ERROR):
            _check_agent_health(adc)
        assert "Invalid JSON" in caplog.text

    def test_agent_running(self, tmp_path, caplog):
        adc = tmp_path / "adc.json"
        adc.write_text(json.dumps({"token_url": "http://127.0.0.1:41234/v1/token"}), encoding="utf-8")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok", "hardware_signs": 1, "cache_hits": 42}
        with patch("wif_bunker.modes.requests.get", return_value=mock_resp), caplog.at_level(logging.INFO):
            _check_agent_health(adc)
        assert "hardware_signs=1" in caplog.text
        assert "cache_hits=42" in caplog.text

    def test_agent_not_running(self, tmp_path, caplog):
        adc = tmp_path / "adc.json"
        adc.write_text(json.dumps({"token_url": "http://127.0.0.1:41234/v1/token"}), encoding="utf-8")

        with (
            patch("wif_bunker.modes.requests.get", side_effect=requests.ConnectionError("refused")),
            caplog.at_level(logging.WARNING),
        ):
            _check_agent_health(adc)
        assert "Not running" in caplog.text

    def test_executable_adc_mode(self, tmp_path, caplog):
        adc = tmp_path / "adc.json"
        adc.write_text(
            json.dumps({"credential_source": {"executable": {"command": "wif-bunker sign-jwt"}}}),
            encoding="utf-8",
        )
        with caplog.at_level(logging.INFO):
            _check_agent_health(adc)
        assert "Executable" in caplog.text


class TestRunStatusSuccess:
    def test_full_status_success(self, tmp_path, sample_bunker_config, caplog):
        bunker_file = tmp_path / "bunker.json"
        adc_file = tmp_path / "adc.json"
        sample_bunker_config.save(bunker_file)
        adc_file.write_text(json.dumps({"type": "external_account"}), encoding="utf-8")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"name": "Test Project"}

        with (
            patch("wif_bunker.modes.mint_google_access_token", return_value=("ya29.tok", 9999999999)),
            patch("wif_bunker.oidc.requests.get", return_value=mock_resp),
            caplog.at_level(logging.INFO),
        ):
            _run_status(config_path=str(bunker_file), adc_path=str(adc_file))

        assert "Token minted successfully" in caplog.text
        assert "Project call succeeded (Test Project)" in caplog.text


class TestRunAttestMacosHint:
    @patch("wif_bunker.modes.generate_attestation")
    def test_loads_macos_label_from_bunker_json(self, mock_attest, tmp_path, sample_bunker_config):
        sample_bunker_config.signer = {"type": "macos-secureenclave", "label": "my-se-key"}
        bunker_file = tmp_path / "bunker.json"
        sample_bunker_config.save(bunker_file)

        mock_attest.return_value = AttestationReport(platform="macos-se", supported=False, hardware_type="SE")
        cfg = WorkloadConfig()
        _run_attest(cfg, output_dir=str(tmp_path / "out"), bunker_config_path=str(bunker_file))
        assert cfg.workload_cn == "my-se-key"


class TestRunAllVersions:
    def test_prints_core_sections(self, monkeypatch, tmp_path, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bunker.json").write_text("{}", encoding="utf-8")
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "adc.json"))

        _run_all_versions()
        out = capsys.readouterr().out
        assert "WIF Bunker" in out
        assert "Core Dependencies" in out
        assert "Hardware Signer Backends (dpop-signers)" in out
        assert "GOOGLE_APPLICATION_CREDENTIALS" in out
        assert "bunker.json" in out
        assert "adc.json" in out

    def test_frozen_linux_no_env_vars_and_broken_module(self, monkeypatch, tmp_path, capsys):
        monkeypatch.chdir(tmp_path)
        for key in (
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
            "GOOGLE_CLOUD_PROJECT",
            "XDG_RUNTIME_DIR",
            "TPM2TOOLS_TCTI",
            "PKCS11_MODULE",
        ):
            monkeypatch.delenv(key, raising=False)

        monkeypatch.setattr("sys.frozen", True, raising=False)
        monkeypatch.setattr("sys.platform", "linux")

        orig_import = __import__

        def flaky_import(name, *args, **kwargs):
            if name == "dpop_signer_yubikey":
                raise RuntimeError("broken driver")
            return orig_import(name, *args, **kwargs)

        with patch("wif_bunker.modes.importlib.import_module", side_effect=flaky_import):
            _run_all_versions()

        out = capsys.readouterr().out
        assert "PyInstaller bundle" in out
        assert "tpm2-pytss:" in out
        assert "(error: broken driver)" in out
        assert "(none of the relevant variables are set)" in out
