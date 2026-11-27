"""Tests for full `wif-bunker setup` workflow and CLI exception handling."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import google.auth.exceptions
import pytest
import requests

from wif_bunker.cli import _main_impl, main


class TestSetupFullWorkflow:
    @patch("wif_bunker.cli.GCPClient")
    def test_setup_use_project_and_executable_adc(
        self,
        mock_gcp_cls,
        tmp_path,
        sample_software_pem_file,
    ):
        mock_client = MagicMock()
        mock_gcp_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_gcp_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.ensure_project.return_value = "123456"
        mock_client.setup_wif_infrastructure.return_value = (None, "bunker-oidc-prov-999")
        mock_client.apply_iam_bindings.return_value = None

        bunker_path = tmp_path / "bunker.json"
        adc_path = tmp_path / "adc.json"
        cache_path = tmp_path / "jwt_cache.json"

        with patch(
            "sys.argv",
            [
                "wif-bunker",
                "setup",
                "--signer",
                "software",
                "--software-key-file",
                str(sample_software_pem_file),
                "--use-project",
                "my-proj",
                "--use-pool",
                "my-pool",
                "--no-service-account",
                "--config",
                str(bunker_path),
                "--adc-file",
                str(adc_path),
                "--write-executable-adc",
                "--executable-cache-file",
                str(cache_path),
                "--skip-verify",
            ],
        ):
            _main_impl()

        mock_client.ensure_project.assert_called_once_with("my-proj")
        mock_client.enable_apis.assert_not_called()
        assert bunker_path.exists()
        assert adc_path.exists()

        bunker_data = json.loads(bunker_path.read_text(encoding="utf-8"))
        assert bunker_data["project_id"] == "my-proj"
        assert bunker_data["service_account_email"] is None
        assert bunker_data["public_jwk"]["alg"] == "ES256"

        adc_data = json.loads(adc_path.read_text(encoding="utf-8"))
        assert adc_data["type"] == "external_account"
        assert adc_data["credential_source"]["executable"]["output_file"] == str(cache_path.resolve())

    @patch("wif_bunker.cli.GCPClient")
    def test_setup_use_provider_patches_in_place(self, mock_gcp_cls, tmp_path, sample_software_pem_file):
        mock_client = MagicMock()
        mock_gcp_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_gcp_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.ensure_project.return_value = "123456"
        mock_client.setup_wif_infrastructure.return_value = ("sa@my-proj.iam.gserviceaccount.com", "bunker-ci-oidc")
        mock_client.apply_iam_bindings.return_value = None

        bunker_path = tmp_path / "bunker.json"
        with patch(
            "sys.argv",
            [
                "wif-bunker",
                "setup",
                "--software-key-file",
                str(sample_software_pem_file),
                "--use-project",
                "my-proj",
                "--use-pool",
                "bunker-ci-pool",
                "--use-provider",
                "bunker-ci-oidc",
                "--use-service-account",
                "sa@my-proj.iam.gserviceaccount.com",
                "--subject",
                "bunker-ci-workload",
                "--config",
                str(bunker_path),
                "--skip-verify",
            ],
        ):
            _main_impl()

        kwargs = mock_client.setup_wif_infrastructure.call_args.kwargs
        assert kwargs["reuse_pool"] is True
        assert kwargs["reuse_provider"] is True
        assert kwargs["config"].provider_id == "bunker-ci-oidc"
        assert kwargs["config"].issuer_uri == "https://wif-bunker.internal/bunker-ci-oidc"
        assert kwargs["config"].subject == "bunker-ci-workload"

    @patch("wif_bunker.cli.GCPClient")
    def test_setup_create_project_with_sa_and_live_verify(
        self,
        mock_gcp_cls,
        tmp_path,
        sample_software_pem_file,
    ):
        mock_client = MagicMock()
        mock_gcp_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_gcp_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.ensure_project.return_value = "654321"
        mock_client.setup_wif_infrastructure.return_value = (
            "my-sa@new-proj.iam.gserviceaccount.com",
            "bunker-oidc-prov-777",
        )
        mock_client.apply_iam_bindings.return_value = None

        bunker_path = tmp_path / "bunker.json"
        mock_proj_resp = MagicMock()
        mock_proj_resp.json.return_value = {"name": "New Project"}
        mock_authed_session = MagicMock()
        mock_authed_session.get.return_value = mock_proj_resp

        with (
            patch("wif_bunker.cli.mint_google_access_token", return_value=("ya29.tok", 9999999999)),
            patch("wif_bunker.agent.mint_google_access_token", return_value=("ya29.tok", 9999999999)),
            patch("wif_bunker.cli.requests.get", return_value=mock_proj_resp),
            patch("wif_bunker.cli.AuthorizedSession", return_value=mock_authed_session),
            patch(
                "sys.argv",
                [
                    "wif-bunker",
                    "setup",
                    "--software-key-file",
                    str(sample_software_pem_file),
                    "--create-project",
                    "new-proj",
                    "--create-pool",
                    "new-pool",
                    "--create-service-account",
                    "my-sa",
                    "--config",
                    str(bunker_path),
                ],
            ),
        ):
            _main_impl()

        mock_client.enable_apis.assert_called_once()
        assert bunker_path.exists()
        # Temporary verification ADC file should be cleaned up
        assert not (tmp_path / ".adc-verify.json").exists()


class TestMainExceptionHandlers:
    @patch("wif_bunker.cli._run_status")
    def test_http_error_with_request_info(self, mock_status):
        response = MagicMock()
        response.status_code = 500
        response.text = "Internal Server Error"
        req = MagicMock()
        req.method = "GET"
        req.url = "https://api.example.com/resource"
        exc = requests.exceptions.HTTPError("HTTP Error", response=response)
        exc.request = req
        mock_status.side_effect = exc

        with patch("sys.argv", ["wif-bunker", "status"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("wif_bunker.cli._run_status")
    def test_google_auth_error_exits_1(self, mock_status):
        mock_status.side_effect = google.auth.exceptions.RefreshError("bad token")
        with patch("sys.argv", ["wif-bunker", "status"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("wif_bunker.cli._run_status")
    def test_timeout_error_exits_1(self, mock_status):
        mock_status.side_effect = TimeoutError("timed out")
        with patch("sys.argv", ["wif-bunker", "status"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
