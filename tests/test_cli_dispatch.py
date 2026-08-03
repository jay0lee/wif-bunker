"""Tests for CLI argument parsing and config dispatch."""

import logging
import os
import sys
from unittest.mock import patch

import pytest

from wif_bunker.cli import _main_impl, _preflight_check_write_access


class TestArgumentParsing:
    @patch("wif_bunker.cli._run_cert_only")
    def test_cert_only_flag(self, mock_run_cert_only, tmp_path):
        with patch("sys.argv", ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path)]):
            _main_impl()
        mock_run_cert_only.assert_called_once()

    @patch("wif_bunker.cli._run_status")
    @patch("sys.argv", ["wif-bunker", "--status"])
    def test_status_flag(self, mock_run_status):
        _main_impl()
        mock_run_status.assert_called_once()

    @patch("wif_bunker.cli._run_attest")
    @patch("sys.argv", ["wif-bunker", "--attest"])
    def test_attest_flag(self, mock_run_attest):
        _main_impl()
        mock_run_attest.assert_called_once()

    @patch("sys.argv", ["wif-bunker", "--cert-file", "foo.pem"])
    def test_cert_file_without_attest_errors(self):
        with pytest.raises(SystemExit) as exc_info:
            _main_impl()
        assert exc_info.value.code == 2

    @patch("sys.argv", ["wif-bunker", "--output-dir", "/tmp"])
    def test_output_dir_without_mode_errors(self):
        with pytest.raises(SystemExit) as exc_info:
            _main_impl()
        assert exc_info.value.code == 2

    @patch("sys.argv", ["wif-bunker", "--use-adc", "--client-secrets-file", "f.json"])
    def test_use_adc_with_client_secrets_errors(self):
        with pytest.raises(SystemExit) as exc_info:
            _main_impl()
        assert exc_info.value.code == 2

    @patch("sys.platform", "darwin")
    @patch("sys.argv", ["wif-bunker", "--soft-key"])
    def test_soft_key_on_non_windows_errors(self):
        with pytest.raises(SystemExit) as exc_info:
            _main_impl()
        assert exc_info.value.code == 2

    @patch("sys.argv", ["wif-bunker", "--cert-lifetime", "999"])
    def test_cert_lifetime_too_high(self):
        with pytest.raises(SystemExit) as exc_info:
            _main_impl()
        assert exc_info.value.code == 2

    @patch("sys.argv", ["wif-bunker", "--cert-lifetime", "0"])
    def test_cert_lifetime_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            _main_impl()
        assert exc_info.value.code == 2

    @patch("wif_bunker.cli.logging.basicConfig")
    @patch("wif_bunker.cli._run_status")
    @patch("sys.argv", ["wif-bunker", "--status", "--debug"])
    def test_debug_flag_sets_debug_level(self, mock_run_status, mock_basic_config):
        _main_impl()
        mock_run_status.assert_called_once()
        mock_basic_config.assert_called_once()
        assert mock_basic_config.call_args[1]["level"] == logging.DEBUG


class TestConfigOverrides:
    @patch("wif_bunker.cli._run_cert_only")
    def test_use_project_sets_config(self, mock_run_cert_only, tmp_path):
        with patch(
            "sys.argv",
            ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path), "--use-project", "my-proj"],
        ):
            _main_impl()
        config = mock_run_cert_only.call_args[0][0]
        assert config.project_id == "my-proj"

    @patch("wif_bunker.cli._run_cert_only")
    def test_create_project_sets_config(self, mock_run_cert_only, tmp_path):
        with patch(
            "sys.argv",
            ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path), "--create-project", "my-proj-new"],
        ):
            _main_impl()
        config = mock_run_cert_only.call_args[0][0]
        assert config.project_id == "my-proj-new"

    @patch("wif_bunker.cli._run_cert_only")
    def test_use_pool_sets_config(self, mock_run_cert_only, tmp_path):
        with patch(
            "sys.argv",
            ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path), "--use-pool", "my-pool"],
        ):
            _main_impl()
        config = mock_run_cert_only.call_args[0][0]
        assert config.pool_id == "my-pool"

    @patch("wif_bunker.cli._run_cert_only")
    def test_create_pool_sets_config(self, mock_run_cert_only, tmp_path):
        with patch(
            "sys.argv",
            ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path), "--create-pool", "my-pool-new"],
        ):
            _main_impl()
        config = mock_run_cert_only.call_args[0][0]
        assert config.pool_id == "my-pool-new"

    @patch("wif_bunker.cli._run_cert_only")
    def test_key_algorithm_override(self, mock_run_cert_only, tmp_path):
        with patch(
            "sys.argv",
            ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path), "--key-algorithm", "es384"],
        ):
            _main_impl()
        config = mock_run_cert_only.call_args[0][0]
        assert config.key_algorithm == "es384"

    @patch("wif_bunker.cli._run_cert_only")
    def test_cert_lifetime_sets_config(self, mock_run_cert_only, tmp_path):
        with patch(
            "sys.argv",
            ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path), "--cert-lifetime", "30"],
        ):
            _main_impl()
        config = mock_run_cert_only.call_args[0][0]
        assert config.cert_lifetime_days == 30


class TestPreflightWriteAccess:
    def test_writable_dir_passes(self, tmp_path):
        _preflight_check_write_access(tmp_path)

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod 0o444 behavior varies on Windows")
    def test_readonly_dir_exits(self, tmp_path):
        os.chmod(tmp_path, 0o444)
        try:
            with pytest.raises(SystemExit) as exc_info:
                _preflight_check_write_access(tmp_path)
            assert exc_info.value.code == 1
        finally:
            os.chmod(tmp_path, 0o755)

    def test_probe_file_cleaned_up(self, tmp_path):
        _preflight_check_write_access(tmp_path)
        probe = tmp_path / ".wif-bunker-write-test"
        assert not probe.exists()
