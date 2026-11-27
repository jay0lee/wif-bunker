"""Tests for CLI edge cases and top-level flags."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from wif_bunker.cli import main


class TestCliExceptionHandlers:
    @patch("wif_bunker.cli._run_status")
    def test_keyboard_interrupt_exits_cleanly(self, mock_status):
        mock_status.side_effect = KeyboardInterrupt
        with patch("sys.argv", ["wif-bunker", "status"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 130

    @patch("wif_bunker.cli._run_status")
    def test_http_error_shows_message(self, mock_status):
        response = MagicMock()
        response.status_code = 403
        response.text = "Permission denied"
        mock_status.side_effect = requests.exceptions.HTTPError("HTTP Error", response=response)
        with patch("sys.argv", ["wif-bunker", "status"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("wif_bunker.cli._run_status")
    def test_runtime_error_shows_message(self, mock_status):
        mock_status.side_effect = RuntimeError("TPM not found")
        with patch("sys.argv", ["wif-bunker", "status"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


class TestCliArgumentParsing:
    def test_help_flag(self):
        with patch("sys.argv", ["wif-bunker", "--help"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_version_flag(self):
        with patch("sys.argv", ["wif-bunker", "--version"]), pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_no_subcommand_prints_help(self, capsys):
        with patch("sys.argv", ["wif-bunker"]):
            main()
        out = capsys.readouterr().out
        assert "setup" in out
        assert "agent" in out
        assert "sign-jwt" in out
