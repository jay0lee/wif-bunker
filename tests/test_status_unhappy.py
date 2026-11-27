"""Unhappy-path tests for `wif-bunker status`."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import requests

from wif_bunker.modes import _run_status


class TestRunStatusMissingAndCorrupt:
    def test_missing_bunker_config(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.ERROR):
            _run_status()
        assert "not found" in caplog.text

    def test_corrupt_bunker_config(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bunker.json").write_text("{corrupt", encoding="utf-8")
        with caplog.at_level(logging.ERROR):
            _run_status()
        assert "Failed to load" in caplog.text

    def test_signer_load_failure(self, monkeypatch, tmp_path, sample_bunker_config, caplog):
        monkeypatch.chdir(tmp_path)
        sample_bunker_config.signer = {"type": "software", "key_file": str(tmp_path / "nonexistent.pem")}
        sample_bunker_config.save(tmp_path / "bunker.json")

        with caplog.at_level(logging.ERROR):
            _run_status()
        assert "Signer:" in caplog.text

    def test_sts_http_error_logged(self, monkeypatch, tmp_path, sample_bunker_config, caplog):
        monkeypatch.chdir(tmp_path)
        sample_bunker_config.save(tmp_path / "bunker.json")

        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Permission denied"
        err = requests.exceptions.HTTPError("Forbidden", response=resp)

        with (
            patch("wif_bunker.modes.mint_google_access_token", side_effect=err),
            caplog.at_level(logging.ERROR),
        ):
            _run_status()
        assert "HTTP 403" in caplog.text

    def test_sts_generic_error_logged(self, monkeypatch, tmp_path, sample_bunker_config, caplog):
        monkeypatch.chdir(tmp_path)
        sample_bunker_config.save(tmp_path / "bunker.json")

        with (
            patch("wif_bunker.modes.mint_google_access_token", side_effect=RuntimeError("offline")),
            caplog.at_level(logging.ERROR),
        ):
            _run_status()
        assert "offline" in caplog.text
