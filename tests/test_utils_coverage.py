"""Tests to cover uncovered lines in wif_bunker/utils.py.

Covers:
- _supports_unicode: Windows ctypes error branches
- _CleanFormatter: non-INFO levels
- with_retries: custom_error_text match, final attempt error logging
"""

from __future__ import annotations

import logging
import os
import time
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from wif_bunker.utils import (
    _CleanFormatter,
    _supports_unicode,
    redact_tokens,
    set_redaction,
    with_retries,
    yubikey_not_found_hint,
)

# ---------------------------------------------------------------------------
# _supports_unicode edge cases
# ---------------------------------------------------------------------------


class TestSupportsUnicodeEdgeCases:
    """Tests for _supports_unicode edge cases."""

    def test_windows_ctypes_attribute_error(self):
        """Covers lines 37: ctypes.windll raises AttributeError."""
        mock_ctypes = MagicMock()
        mock_ctypes.windll.kernel32.GetConsoleOutputCP.side_effect = AttributeError("no windll")

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.platform", "win32"),
            patch("wif_bunker.utils.ctypes", mock_ctypes),
            patch("sys.stdout") as mock_stdout,
        ):
            mock_stdout.encoding = "utf-8"
            assert _supports_unicode() is True

    def test_windows_ctypes_os_error(self):
        """Covers lines 37: ctypes.windll raises OSError."""
        mock_ctypes = MagicMock()
        mock_ctypes.windll.kernel32.GetConsoleOutputCP.side_effect = OSError("failed")

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.platform", "win32"),
            patch("wif_bunker.utils.ctypes", mock_ctypes),
            patch("sys.stdout") as mock_stdout,
        ):
            mock_stdout.encoding = "cp1252"
            assert _supports_unicode() is False

    def test_windows_no_stdout_encoding(self):
        """Covers lines 41-42: sys.stdout has no encoding attribute on Windows."""
        mock_ctypes = MagicMock()
        mock_ctypes.windll.kernel32.GetConsoleOutputCP.return_value = 1252

        mock_stdout = Mock(spec=[])  # No encoding attribute
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.platform", "win32"),
            patch("wif_bunker.utils.ctypes", mock_ctypes),
            patch("sys.stdout", mock_stdout),
        ):
            assert _supports_unicode() is False

    def test_non_windows_no_encoding(self):
        """Covers lines 45-46: non-Windows stdout without encoding."""
        mock_stdout = Mock(spec=[])
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.platform", "linux"),
            patch("sys.stdout", mock_stdout),
        ):
            assert _supports_unicode() is False

    def test_non_windows_none_encoding(self):
        """Covers line 44: encoding is None."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.platform", "linux"),
            patch("sys.stdout") as mock_stdout,
        ):
            mock_stdout.encoding = None
            assert _supports_unicode() is False


# ---------------------------------------------------------------------------
# _CleanFormatter
# ---------------------------------------------------------------------------


class TestCleanFormatterEdge:
    """Tests for _CleanFormatter edge cases."""

    def test_warning_level_includes_prefix(self):
        """Covers lines 79-81: non-INFO levels include standard prefix."""
        fmt = _CleanFormatter("%(levelname)s:%(message)s")
        record = logging.LogRecord("test", logging.WARNING, "path", 1, "warn msg", (), None)
        assert fmt.format(record).startswith("WARNING")

    def test_debug_level_includes_prefix(self):
        """Covers lines 79-81: DEBUG level includes standard prefix."""
        fmt = _CleanFormatter("%(levelname)s:%(message)s")
        record = logging.LogRecord("test", logging.DEBUG, "path", 1, "debug msg", (), None)
        assert fmt.format(record).startswith("DEBUG")

    def test_info_level_returns_message_only(self):
        """Covers lines 79-80: INFO level returns just the message."""
        fmt = _CleanFormatter("%(levelname)s:%(message)s")
        record = logging.LogRecord("test", logging.INFO, "path", 1, "info msg", (), None)
        assert fmt.format(record) == "info msg"


# ---------------------------------------------------------------------------
# with_retries: custom_error_text
# ---------------------------------------------------------------------------


class TestWithRetriesCustomErrorText:
    """Tests for with_retries custom_error_text matching."""

    @pytest.fixture(autouse=True)
    def mock_sleep(self, monkeypatch):
        """Disable sleep in retry tests."""
        monkeypatch.setattr(time, "sleep", lambda x: None)

    def test_custom_error_text_retry(self):
        """Covers lines 120-131: retry on custom error text match."""
        attempts = 0

        @with_retries(max_attempts=3, expected_errors=(), custom_error_text="PENDING")
        def my_func():
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                resp = Mock()
                resp.status_code = 400
                resp.text = "Operation PENDING"
                exc = requests.exceptions.HTTPError()
                exc.response = resp
                raise exc
            return "done"

        assert my_func() == "done"
        assert attempts == 3

    def test_custom_error_text_no_match_raises(self):
        """Covers lines 133-140: custom_error_text doesn't match — raises immediately."""

        @with_retries(max_attempts=3, expected_errors=(), custom_error_text="PENDING")
        def my_func():
            resp = Mock()
            resp.status_code = 400
            resp.text = "DIFFERENT_ERROR"
            exc = requests.exceptions.HTTPError()
            exc.response = resp
            raise exc

        with pytest.raises(requests.exceptions.HTTPError):
            my_func()

    def test_http_error_non_expected_status_raises(self):
        """Covers lines 133-140: non-expected HTTP status raises immediately."""

        @with_retries(max_attempts=3, expected_errors=(403,))
        def my_func():
            resp = Mock()
            resp.status_code = 500
            resp.text = "Server Error"
            exc = requests.exceptions.HTTPError()
            exc.response = resp
            raise exc

        with pytest.raises(requests.exceptions.HTTPError):
            my_func()

    def test_final_attempt_error_logging(self):
        """Covers lines 133-140: error logged on final attempt with expected status."""

        @with_retries(max_attempts=1, expected_errors=(403,))
        def my_func():
            resp = Mock()
            resp.status_code = 403
            resp.text = "Forbidden"
            exc = requests.exceptions.HTTPError()
            exc.response = resp
            raise exc

        with pytest.raises(requests.exceptions.HTTPError):
            my_func()


class TestRedactionAndHints:
    def test_set_redaction_toggle(self):
        sample = '{"access_token": "ya29.secret-value"}'
        try:
            set_redaction(False)
            assert redact_tokens(sample) == sample
            set_redaction(True)
            assert "***REDACTED***" in redact_tokens(sample)
        finally:
            set_redaction(True)

    @pytest.mark.parametrize(
        ("plat", "expected"),
        [
            ("linux", "pcscd"),
            ("darwin", "Privacy & Security"),
            ("win32", "Smart Card"),
            ("freebsd", "Ensure the YubiKey is plugged in."),
        ],
    )
    def test_yubikey_not_found_hint_per_platform(self, plat, expected):
        with patch("sys.platform", plat):
            assert expected in yubikey_not_found_hint()
