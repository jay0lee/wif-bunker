"""Tests to cover uncovered lines in wif_bunker/cli.py.

Covers:
- _validate_and_configure: yubikey_serial without use_yubikey (line 276, 293-299)
- _main_impl: cert-only with existing config files (334-335, 355-357, 364)
- _main_impl: full GCP workflow with mocked GCPClient (377-789)
- main(): HTTP error with request info (line 819)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

# ---------------------------------------------------------------------------
# _validate_and_configure edge cases
# ---------------------------------------------------------------------------


class TestValidateAndConfigureExtended:
    """Tests for _validate_and_configure edge cases."""

    def test_yubikey_serial_without_use_yubikey_errors(self):
        """Covers line 276, 279-280: --yubikey-serial without --use-yubikey."""
        with patch("sys.argv", ["wif-bunker", "--cert-only", "--yubikey-serial", "12345", "--output-dir", "/tmp"]):
            from wif_bunker.cli import _main_impl

            with pytest.raises(SystemExit) as exc_info:
                _main_impl()
            assert exc_info.value.code == 2

    @patch("sys.platform", "darwin")
    def test_unsupported_algo_on_platform_errors(self):
        """Covers lines 293-299: algorithm not supported on current platform."""
        with patch("sys.argv", ["wif-bunker", "--cert-only", "--output-dir", "/tmp", "--key-algorithm", "rsa2048"]):
            from wif_bunker.cli import _main_impl

            with pytest.raises(SystemExit) as exc_info:
                _main_impl()
            assert exc_info.value.code == 2

    def test_unsupported_algo_on_yubikey_errors(self):
        """Covers lines 293-294: algorithm not supported on YubiKey."""
        with patch(
            "sys.argv",
            ["wif-bunker", "--cert-only", "--output-dir", "/tmp", "--use-yubikey", "--key-algorithm", "rsa3072"],
        ):
            from wif_bunker.cli import _main_impl

            with pytest.raises(SystemExit) as exc_info:
                _main_impl()
            assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# cert-only with existing config files
# ---------------------------------------------------------------------------


class TestCertOnlyExistingConfigs:
    """Tests for cert-only refusing to overwrite config files."""

    def test_cert_only_with_existing_configs_errors(self, tmp_path):
        """Covers lines 362-368: cert-only refuses when config files already exist."""
        (tmp_path / "adc.json").write_text("{}")
        with patch("sys.argv", ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path)]):
            from wif_bunker.cli import _main_impl

            with pytest.raises(SystemExit) as exc_info:
                _main_impl()
            assert exc_info.value.code == 2

    def test_cert_only_no_output_dir_with_existing_configs(self, tmp_path, monkeypatch):
        """Covers lines 360-370: cert-only in CWD with existing configs."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        with patch("sys.argv", ["wif-bunker", "--cert-only"]):
            from wif_bunker.cli import _main_impl

            with pytest.raises(SystemExit) as exc_info:
                _main_impl()
            assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# _main_impl: cert-and-mtls-test dispatch
# ---------------------------------------------------------------------------


class TestCertAndMtlsTestDispatch:
    """Tests for cert-and-mtls-test dispatch path."""

    @patch("wif_bunker.cli._run_cert_and_mtls_test")
    def test_cert_and_mtls_test_dispatch(self, mock_run, tmp_path):
        """Covers lines 354-357: dispatches to _run_cert_and_mtls_test."""
        with patch("sys.argv", ["wif-bunker", "--cert-and-mtls-test", "--output-dir", str(tmp_path)]):
            from wif_bunker.cli import _main_impl

            _main_impl()
        mock_run.assert_called_once()

    @patch("wif_bunker.cli._run_cert_and_mtls_test")
    def test_cert_and_mtls_test_debug(self, mock_run, tmp_path):
        """Covers lines 354-357: debug flag passed through."""
        with patch("sys.argv", ["wif-bunker", "--cert-and-mtls-test", "--output-dir", str(tmp_path), "--debug"]):
            from wif_bunker.cli import _main_impl

            _main_impl()
        _, kwargs = mock_run.call_args
        assert kwargs.get("debug") is True


# ---------------------------------------------------------------------------
# _main_impl: all-versions dispatch
# ---------------------------------------------------------------------------


class TestAllVersionsDispatch:
    """Tests for --all-versions dispatch path."""

    @patch("wif_bunker.cli._run_all_versions")
    @patch("sys.argv", ["wif-bunker", "--all-versions"])
    def test_all_versions_dispatch(self, mock_run):
        """Covers lines 333-335: dispatches to _run_all_versions."""
        from wif_bunker.cli import _main_impl

        _main_impl()
        mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# _main_impl: full GCP workflow (lines 377-789)
# ---------------------------------------------------------------------------


class TestMainImplFullWorkflow:
    """Tests for the full GCP workflow in _main_impl."""

    @patch("wif_bunker.cli.verify_cert_retrieval")
    @patch("wif_bunker.cli.build_adc_config")
    @patch("wif_bunker.cli.build_certificate_config")
    @patch("wif_bunker.cli._find_hardmtls_library")
    @patch("wif_bunker.cli.generate_os_keystore_cert")
    @patch("wif_bunker.cli.GCPClient")
    def test_use_project_flow(
        self,
        mock_gcp_cls,
        mock_gen_cert,
        mock_find_lib,
        mock_build_cert_config,
        mock_build_adc,
        mock_verify_cert,
        tmp_path,
        monkeypatch,
    ):
        """Covers lines 377-528: --use-project flow with hardmtls not found."""
        monkeypatch.chdir(tmp_path)
        mock_client = MagicMock()
        mock_gcp_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_gcp_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.ensure_project.return_value = "123456"
        mock_client.setup_wif_infrastructure.return_value = ("sa@proj.iam.gserviceaccount.com", "pool-id")
        mock_client.apply_iam_bindings.return_value = None
        mock_gen_cert.return_value = MagicMock(issuer_cn="test-ca", workload_cert_pem="CERT", trust_anchor_pem="CA")
        mock_find_lib.side_effect = FileNotFoundError("not found")

        with patch(
            "sys.argv", ["wif-bunker", "--use-project", "my-proj", "--use-pool", "my-pool", "--no-service-account"]
        ):
            from wif_bunker.cli import _main_impl

            _main_impl()

        mock_client.ensure_project.assert_called_once_with("my-proj")

    @patch("wif_bunker.cli.verify_cert_retrieval")
    @patch("wif_bunker.cli.build_adc_config")
    @patch("wif_bunker.cli.build_certificate_config")
    @patch("wif_bunker.cli._find_hardmtls_library")
    @patch("wif_bunker.cli.generate_os_keystore_cert")
    @patch("wif_bunker.cli.GCPClient")
    def test_create_project_with_sa_flow(
        self,
        mock_gcp_cls,
        mock_gen_cert,
        mock_find_lib,
        mock_build_cert_config,
        mock_build_adc,
        mock_verify_cert,
        tmp_path,
        monkeypatch,
    ):
        """Covers lines 400-414: --create-project flow with APIs enabled."""
        monkeypatch.chdir(tmp_path)
        mock_client = MagicMock()
        mock_gcp_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_gcp_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.ensure_project.return_value = "654321"
        mock_client.setup_wif_infrastructure.return_value = ("sa@test.iam.gserviceaccount.com", "pool-id")
        mock_client.apply_iam_bindings.return_value = None
        mock_gen_cert.return_value = MagicMock(issuer_cn="test-ca", workload_cert_pem="CERT", trust_anchor_pem="CA")
        mock_find_lib.side_effect = FileNotFoundError("not found")

        with patch(
            "sys.argv",
            [
                "wif-bunker",
                "--create-project",
                "new-proj",
                "--create-pool",
                "new-pool",
                "--create-service-account",
                "my-sa",
            ],
        ):
            from wif_bunker.cli import _main_impl

            _main_impl()

        mock_client.enable_apis.assert_called_once()


# ---------------------------------------------------------------------------
# main(): HTTP error with request info (line 800-809, 819)
# ---------------------------------------------------------------------------


class TestMainExceptionHandlersExtended:
    """Tests for main() exception handlers."""

    @patch("wif_bunker.cli._run_status")
    @patch("sys.argv", ["wif-bunker", "--status"])
    def test_http_error_with_request_info(self, mock_status):
        """Covers lines 800-808: HTTPError with request info."""
        response = MagicMock()
        response.status_code = 500
        response.text = "Internal Server Error"
        req = MagicMock()
        req.method = "GET"
        req.url = "https://api.example.com/resource"
        exc = requests.exceptions.HTTPError("HTTP Error", response=response)
        exc.request = req
        mock_status.side_effect = exc

        from wif_bunker.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("wif_bunker.cli._run_status")
    @patch("sys.argv", ["wif-bunker", "--status"])
    def test_http_error_no_response(self, mock_status):
        """Covers lines 797-798: HTTPError with None response."""
        exc = requests.exceptions.HTTPError("HTTP Error")
        exc.response = None
        exc.request = None
        mock_status.side_effect = exc

        from wif_bunker.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# _main_impl: preflight_check_write_access and yubikey preflight
# ---------------------------------------------------------------------------


class TestPreflightChecks:
    """Tests for preflight checks in _main_impl."""

    @patch("wif_bunker.cli.preflight_check_write_access")
    @patch("wif_bunker.cli.GCPClient")
    def test_write_access_called_in_default_mode(self, mock_gcp_cls, mock_write_check, tmp_path, monkeypatch):
        """Covers line 377: preflight_check_write_access called."""
        monkeypatch.chdir(tmp_path)
        mock_client = MagicMock()
        mock_gcp_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_gcp_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.ensure_project.return_value = "123"
        mock_client.setup_wif_infrastructure.return_value = ("sa@test", "pool")
        mock_client.apply_iam_bindings.return_value = None

        with (
            patch("wif_bunker.cli.generate_os_keystore_cert", return_value=MagicMock(issuer_cn="ca")),
            patch("wif_bunker.cli._find_hardmtls_library", side_effect=FileNotFoundError),
            patch("sys.argv", ["wif-bunker", "--use-project", "proj", "--no-service-account"]),
        ):
            from wif_bunker.cli import _main_impl

            _main_impl()

        mock_write_check.assert_called_once()


# ---------------------------------------------------------------------------
# YubiKey config propagation
# ---------------------------------------------------------------------------


class TestYubiKeyConfig:
    """Tests for YubiKey configuration in _validate_and_configure."""

    @patch("wif_bunker.cli._run_cert_only")
    def test_yubikey_options_set_config(self, mock_run, tmp_path):
        """Covers line 276: yubikey_serial set on config."""
        with patch(
            "sys.argv",
            [
                "wif-bunker",
                "--cert-only",
                "--output-dir",
                str(tmp_path),
                "--use-yubikey",
                "--yubikey-serial",
                "99999",
                "--yubikey-slot",
                "9c",
                "--yubikey-touch-policy",
                "always",
            ],
        ):
            from wif_bunker.cli import _main_impl

            _main_impl()
        config = mock_run.call_args[0][0]
        assert config.use_yubikey is True
        assert config.yubikey_serial == 99999
        assert config.yubikey_slot == "9c"
        assert config.yubikey_touch_policy == "always"

    @patch("wif_bunker.cli._run_cert_only")
    def test_use_yubikey_without_serial(self, mock_run, tmp_path):
        """Covers lines 271-278: --use-yubikey without serial."""
        with patch("sys.argv", ["wif-bunker", "--cert-only", "--output-dir", str(tmp_path), "--use-yubikey"]):
            from wif_bunker.cli import _main_impl

            _main_impl()
        config = mock_run.call_args[0][0]
        assert config.use_yubikey is True
        assert config.yubikey_serial is None
