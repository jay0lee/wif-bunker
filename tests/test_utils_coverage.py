"""Tests to cover uncovered lines in wif_bunker/utils.py.

Covers:
- _supports_unicode: Windows ctypes error branches (lines 27, 31-42, 45-46)
- _CleanFormatter: non-INFO levels (lines 79-81)
- with_retries: custom_error_text match, final attempt error logging (lines 133-140)
- _require_command: package + install_hint in error message (lines 178, 180)
- preflight_check_openssl_shared: all platform branches, OSError (lines 268-269, 273, 277-283, 292-308, 311-322)
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from wif_bunker.utils import (
    _CleanFormatter,
    _require_command,
    _supports_unicode,
    preflight_check_openssl_shared,
    with_retries,
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
            patch.dict("sys.modules", {"ctypes": mock_ctypes}),
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
            patch.dict("sys.modules", {"ctypes": mock_ctypes}),
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
            patch.dict("sys.modules", {"ctypes": mock_ctypes}),
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


# ---------------------------------------------------------------------------
# _require_command edge cases
# ---------------------------------------------------------------------------


class TestRequireCommandEdgeCases:
    """Tests for _require_command with package and install_hint."""

    def test_missing_with_package_only(self):
        """Covers line 178: package text in error."""
        with (
            patch("shutil.which", return_value=None),
            pytest.raises(RuntimeError, match="Package: mypkg"),
        ):
            _require_command("fakecmd", package="mypkg")

    def test_missing_with_install_hint_only(self):
        """Covers line 180: install_hint text in error."""
        with (
            patch("shutil.which", return_value=None),
            pytest.raises(RuntimeError, match="Install: brew install fakecmd"),
        ):
            _require_command("fakecmd", install_hint="brew install fakecmd")

    def test_missing_with_both(self):
        """Covers lines 178, 180: both package and install_hint."""
        with patch("shutil.which", return_value=None), pytest.raises(RuntimeError) as exc_info:
            _require_command("fakecmd", package="mypkg", install_hint="brew install mypkg")
        msg = str(exc_info.value)
        assert "Package: mypkg" in msg
        assert "Install: brew install mypkg" in msg


# ---------------------------------------------------------------------------
# preflight_check_openssl_shared edge cases
# ---------------------------------------------------------------------------


class TestPreflightCheckOpensslEdgeCases:
    """Additional edge-case tests for preflight_check_openssl_shared."""

    @patch("sys.platform", "linux")
    def test_linux_subprocess_os_error(self):
        """Covers lines 307: OSError from subprocess."""
        with patch("subprocess.run", side_effect=OSError("command not found")):
            preflight_check_openssl_shared()

    @patch("sys.platform", "win32")
    def test_win32_shared_libraries(self):
        """Covers lines 292-304: Windows with dumpbin and shared libs found."""
        with (
            patch("shutil.which", return_value="/usr/bin/dumpbin"),
            patch("subprocess.run") as mock_run,
            patch("wif_bunker.utils.logger.warning") as mock_warn,
        ):
            mock_run.return_value = Mock(stdout="LIBSSL.DLL\nLIBCRYPTO.DLL")
            preflight_check_openssl_shared()
            mock_warn.assert_not_called()

    @patch("sys.platform", "darwin")
    def test_darwin_shared_libraries(self):
        """Covers lines 284-291: macOS with shared libs found."""
        with (
            patch("subprocess.run") as mock_run,
            patch("wif_bunker.utils.logger.warning") as mock_warn,
        ):
            mock_run.return_value = Mock(stdout="libssl.3.dylib\nlibcrypto.3.dylib")
            preflight_check_openssl_shared()
            mock_warn.assert_not_called()

    @patch("sys.platform", "linux")
    def test_linux_static_ssl_warns(self):
        """Covers lines 310-322: static OpenSSL warning emitted."""
        with (
            patch("subprocess.run") as mock_run,
            patch("wif_bunker.utils.logger.warning") as mock_warn,
        ):
            mock_run.return_value = Mock(stdout="libc.so.6\nlibm.so.6")
            preflight_check_openssl_shared()
            assert mock_warn.call_count >= 1

    def test_ssl_path_not_exists(self):
        """Covers lines 272: ssl_path exists check returns False."""
        with (
            patch.object(Path, "exists", return_value=False),
            patch("wif_bunker.utils.logger.warning"),
        ):
            # Path.exists returns False so should return early — shouldn't crash
            preflight_check_openssl_shared()
