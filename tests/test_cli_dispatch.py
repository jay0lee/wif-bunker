"""Tests for WIF Bunker v2 CLI argument parsing and subcommand dispatch."""

from __future__ import annotations

import json
import logging
import os
import sys
from unittest.mock import patch

import pytest

from wif_bunker.cli import _main_impl
from wif_bunker.utils import preflight_check_write_access


class TestSubcommandDispatch:
    @patch("wif_bunker.cli._run_status")
    def test_status_subcommand(self, mock_status):
        with patch("sys.argv", ["wif-bunker", "status", "--config", "b.json", "--adc-file", "a.json"]):
            _main_impl()
        mock_status.assert_called_once_with(config_path="b.json", adc_path="a.json")

    @patch("wif_bunker.cli._run_all_versions")
    def test_versions_subcommand(self, mock_versions):
        with patch("sys.argv", ["wif-bunker", "versions"]):
            _main_impl()
        mock_versions.assert_called_once()

    @patch("wif_bunker.cli._run_all_versions")
    def test_all_versions_flag(self, mock_versions):
        with patch("sys.argv", ["wif-bunker", "--all-versions"]):
            _main_impl()
        mock_versions.assert_called_once()

    @patch("wif_bunker.cli._run_attest")
    def test_attest_subcommand_flags(self, mock_attest, tmp_path):
        with patch(
            "sys.argv",
            [
                "wif-bunker",
                "attest",
                "--tpm-handle",
                "0x81000001",
                "--output-dir",
                str(tmp_path),
            ],
        ):
            _main_impl()
        cfg = mock_attest.call_args[0][0]
        assert cfg.linux_tpm_handle == 0x81000001
        assert mock_attest.call_args.kwargs["output_dir"] == str(tmp_path)

    @patch("wif_bunker.cli._run_attest")
    def test_attest_yubikey_flags(self, mock_attest):
        with patch(
            "sys.argv",
            ["wif-bunker", "attest", "--use-yubikey", "--yubikey-slot", "9a", "--yubikey-serial", "12345"],
        ):
            _main_impl()
        cfg = mock_attest.call_args[0][0]
        assert cfg.use_yubikey is True
        assert cfg.yubikey_slot == "9a"
        assert cfg.yubikey_serial == 12345

    @patch("wif_bunker.cli.run_agent_foreground")
    def test_agent_subcommand(self, mock_run_agent, tmp_path, sample_bunker_config):
        bunker_file = tmp_path / "bunker.json"
        sample_bunker_config.save(bunker_file)
        with patch(
            "sys.argv",
            [
                "wif-bunker",
                "agent",
                "--config",
                str(bunker_file),
                "--port",
                "8765",
                "--warm",
            ],
        ):
            _main_impl()
        mock_run_agent.assert_called_once()
        assert mock_run_agent.call_args.kwargs["port"] == 8765
        assert mock_run_agent.call_args.kwargs["eager_warm"] is True

    def test_sign_jwt_subcommand_json_and_raw(self, tmp_path, sample_bunker_config, capsys):
        bunker_file = tmp_path / "bunker.json"
        cache_file = tmp_path / "cache.json"
        sample_bunker_config.save(bunker_file)

        with patch(
            "sys.argv",
            ["wif-bunker", "sign-jwt", "--config", str(bunker_file), "--output-file", str(cache_file)],
        ):
            _main_impl()

        out = json.loads(capsys.readouterr().out)
        assert out["version"] == 1
        assert out["success"] is True
        assert out["id_token"].count(".") == 2
        assert json.loads(cache_file.read_text(encoding="utf-8")) == out

        with patch("sys.argv", ["wif-bunker", "sign-jwt", "--config", str(bunker_file), "--raw"]):
            _main_impl()
        raw = capsys.readouterr().out.strip()
        assert raw.count(".") == 2

    @patch("wif_bunker.cli.logging.basicConfig")
    @patch("wif_bunker.cli._run_status")
    def test_debug_flag_before_or_after_subcommand(self, mock_status, mock_basic_config):
        with patch("sys.argv", ["wif-bunker", "status", "--debug"]):
            _main_impl()
        mock_status.assert_called_once()
        assert mock_basic_config.call_args.kwargs["level"] == logging.DEBUG


class TestSetupArgValidation:
    def test_missing_signer_errors(self):
        with patch("sys.argv", ["wif-bunker", "setup", "--use-project", "p"]), pytest.raises(SystemExit) as exc:
            _main_impl()
        assert exc.value.code == 2

    def test_use_adc_and_client_secrets_mutually_exclusive(self):
        with (
            patch(
                "sys.argv",
                ["wif-bunker", "setup", "--signer", "yubikey", "--use-adc", "--client-secrets-file", "f.json"],
            ),
            pytest.raises(SystemExit) as exc,
        ):
            _main_impl()
        assert exc.value.code == 2

    def test_issuer_uri_must_be_https(self):
        with (
            patch("sys.argv", ["wif-bunker", "setup", "--signer", "yubikey", "--issuer-uri", "http://bad"]),
            pytest.raises(SystemExit) as exc,
        ):
            _main_impl()
        assert exc.value.code == 2

    def test_windows_certstore_requires_selector(self):
        with (
            patch("sys.argv", ["wif-bunker", "setup", "--signer", "windows-certstore"]),
            pytest.raises(SystemExit) as exc,
        ):
            _main_impl()
        assert exc.value.code == 2

    def test_macos_se_requires_selector(self):
        with (
            patch("sys.argv", ["wif-bunker", "setup", "--signer", "macos-secureenclave"]),
            pytest.raises(SystemExit) as exc,
        ):
            _main_impl()
        assert exc.value.code == 2


class TestPreflightWriteAccess:
    def test_writable_dir_passes(self, tmp_path):
        preflight_check_write_access(tmp_path)

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod 0o444 behavior varies on Windows")
    def test_readonly_dir_exits(self, tmp_path):
        os.chmod(tmp_path, 0o444)
        try:
            with pytest.raises(SystemExit) as exc_info:
                preflight_check_write_access(tmp_path)
            assert exc_info.value.code == 1
        finally:
            os.chmod(tmp_path, 0o755)

    def test_probe_file_cleaned_up(self, tmp_path):
        preflight_check_write_access(tmp_path)
        probe = tmp_path / ".wif-bunker-write-test"
        assert not probe.exists()


class TestResolveSelfCommand:
    def test_python_module_invocation_uses_sys_executable_dash_m(self):
        from wif_bunker.cli import _resolve_self_command

        with patch("sys.argv", ["/repo/wif_bunker/__main__.py"]):
            cmd = _resolve_self_command()
        assert cmd.endswith('" -m wif_bunker')
        assert "__main__.py" not in cmd
