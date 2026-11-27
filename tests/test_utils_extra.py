import logging
import os
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from wif_bunker.utils import (
    _CleanFormatter,
    _require_command,
    _supports_unicode,
    require_commands,
    with_retries,
)


def test_supports_unicode_gha():
    with patch.dict(os.environ, {"GITHUB_ACTIONS": "1"}):
        assert _supports_unicode() is True


def test_supports_unicode_windows_cp65001():
    mock_ctypes = MagicMock()
    mock_ctypes.windll.kernel32.GetConsoleOutputCP.return_value = 65001

    with patch.dict(os.environ, clear=True), patch("sys.platform", "win32"):
        with patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            assert _supports_unicode() is True


def test_supports_unicode_windows_no_cp65001():
    mock_ctypes = MagicMock()
    mock_ctypes.windll.kernel32.GetConsoleOutputCP.return_value = 1252

    with patch.dict(os.environ, clear=True), patch("sys.platform", "win32"):
        with patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            with patch("sys.stdout") as mock_stdout:
                mock_stdout.encoding = "utf-8"
                assert _supports_unicode() is True


def test_supports_unicode_linux_fallback():
    with patch.dict(os.environ, clear=True), patch("sys.platform", "linux"), patch("sys.stdout") as mock_stdout:
        mock_stdout.encoding = "utf-8"
        assert _supports_unicode() is True


def test_supports_unicode_no_encoding():
    with patch.dict(os.environ, clear=True), patch("sys.platform", "linux"):
        # A mock that raises AttributeError for encoding
        mock_stdout = Mock(spec=[])
        with patch("sys.stdout", mock_stdout):
            assert _supports_unicode() is False


def test_clean_formatter():
    fmt = _CleanFormatter("%(levelname)s:%(message)s")
    record_info = logging.LogRecord("name", logging.INFO, "pathname", 1, "msg", (), None)
    assert fmt.format(record_info) == "msg"
    record_error = logging.LogRecord("name", logging.ERROR, "pathname", 1, "msg", (), None)
    assert fmt.format(record_error) == "ERROR:msg"


@patch("wif_bunker.utils.logger.error")
@patch("wif_bunker.utils.time.sleep")
def test_retry_final_attempt_logging(mock_sleep, mock_error):
    @with_retries(max_attempts=2, expected_errors=(403,))
    def fail_func():
        resp = Mock()
        resp.status_code = 403
        resp.text = "forbidden text"
        exc = requests.exceptions.HTTPError()
        exc.response = resp
        raise exc

    with pytest.raises(requests.exceptions.HTTPError):
        fail_func()
    mock_error.assert_called_once_with(
        "HTTP %d from %s FAILED after %d attempts — %s", 403, "fail_func", 2, "forbidden text"
    )


def test_require_command_found():
    with patch("shutil.which", return_value="/bin/ls"):
        assert _require_command("ls") == "/bin/ls"


def test_require_command_missing():
    with patch("shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="Required command 'fake_cmd' not found on PATH."):
            _require_command("fake_cmd")
        with pytest.raises(RuntimeError, match="Package: fakepkg"):
            _require_command("fake_cmd", package="fakepkg", install_hint="apt install")


def test_require_commands():
    with patch("shutil.which", side_effect=lambda x: "/bin/" + x if x == "ls" else None):
        with pytest.raises(RuntimeError) as exc:
            require_commands([("ls", "coreutils", ""), ("fake1", "pkg1", "apt install pkg1"), ("fake2", "pkg2", "")])
        msg = str(exc.value)
        assert "Missing 2 required command" in msg

    with patch("shutil.which", return_value="/bin/ls"):
        assert require_commands([("ls", "coreutils", "")]) == {"ls": "/bin/ls"}
