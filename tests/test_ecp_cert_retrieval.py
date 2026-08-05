"""Tests for ECP cert retrieval and PKCS#11 subprocess isolation."""

from __future__ import annotations

import ctypes
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from wif_bunker.cert import (
    _ecp_get_cert_inprocess,
    _ecp_get_cert_subprocess,
    _find_system_python,
    ecp_get_cert_pem,
)

# ---------------------------------------------------------------------------
# _find_system_python
# ---------------------------------------------------------------------------


class TestFindSystemPython:
    def test_not_frozen_returns_sys_executable(self, monkeypatch):
        """When not frozen, should return sys.executable directly."""
        monkeypatch.delattr(sys, "frozen", raising=False)
        result = _find_system_python()
        assert result == sys.executable

    def test_frozen_finds_python3(self, monkeypatch):
        """When frozen, should find python3 via shutil.which."""
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/python3" if name == "python3" else None)
        result = _find_system_python()
        assert result == "/usr/bin/python3"

    def test_frozen_falls_back_to_python(self, monkeypatch):
        """When frozen and python3 not found, should try 'python'."""
        monkeypatch.setattr(sys, "frozen", True, raising=False)

        def fake_which(name):
            if name == "python":
                return "/usr/bin/python"
            return None

        monkeypatch.setattr("shutil.which", fake_which)
        result = _find_system_python()
        assert result == "/usr/bin/python"

    def test_frozen_no_python_raises(self, monkeypatch):
        """When frozen and no python found, should raise RuntimeError."""
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr("shutil.which", lambda name: None)
        with pytest.raises(RuntimeError, match="Cannot find system python3"):
            _find_system_python()


# ---------------------------------------------------------------------------
# ecp_get_cert_pem (dispatcher)
# ---------------------------------------------------------------------------


class TestEcpGetCertPemDispatch:
    @patch("wif_bunker.cert._ecp_get_cert_subprocess")
    @patch("wif_bunker.cert._ecp_get_cert_inprocess")
    def test_linux_uses_subprocess(self, mock_inprocess, mock_subprocess, monkeypatch):
        """On Linux, should dispatch to subprocess path."""
        monkeypatch.setattr(sys, "platform", "linux")
        mock_subprocess.return_value = b"---PEM---"
        result = ecp_get_cert_pem("/lib/ecp.so", "/tmp/config.json")
        mock_subprocess.assert_called_once_with("/lib/ecp.so", "/tmp/config.json")
        mock_inprocess.assert_not_called()
        assert result == b"---PEM---"

    @patch("wif_bunker.cert._ecp_get_cert_subprocess")
    @patch("wif_bunker.cert._ecp_get_cert_inprocess")
    def test_darwin_uses_inprocess(self, mock_inprocess, mock_subprocess, monkeypatch):
        """On macOS, should dispatch to in-process path."""
        monkeypatch.setattr(sys, "platform", "darwin")
        mock_inprocess.return_value = b"---PEM---"
        result = ecp_get_cert_pem("/lib/ecp.dylib", "/tmp/config.json")
        mock_inprocess.assert_called_once_with("/lib/ecp.dylib", "/tmp/config.json")
        mock_subprocess.assert_not_called()
        assert result == b"---PEM---"

    @patch("wif_bunker.cert._ecp_get_cert_subprocess")
    @patch("wif_bunker.cert._ecp_get_cert_inprocess")
    def test_win32_uses_inprocess(self, mock_inprocess, mock_subprocess, monkeypatch):
        """On Windows, should dispatch to in-process path."""
        monkeypatch.setattr(sys, "platform", "win32")
        mock_inprocess.return_value = b"---PEM---"
        result = ecp_get_cert_pem("C:\\ecp.dll", "C:\\config.json")
        mock_inprocess.assert_called_once_with("C:\\ecp.dll", "C:\\config.json")
        mock_subprocess.assert_not_called()
        assert result == b"---PEM---"


# ---------------------------------------------------------------------------
# _ecp_get_cert_inprocess
# ---------------------------------------------------------------------------


class TestEcpGetCertInprocess:
    def test_success_returns_pem(self, monkeypatch):
        """Should call GetCertPemForPython twice and return the buffer contents."""
        pem = b"-----BEGIN CERTIFICATE-----\nMIIBxyz\n-----END CERTIFICATE-----\n"
        call_count = 0

        def fake_get_cert(config, buf, size):
            nonlocal call_count
            call_count += 1
            if buf is None:
                return len(pem)
            # Simulate writing to the buffer
            ctypes.memmove(buf, pem, len(pem))
            return len(pem)

        mock_lib = MagicMock()
        mock_lib.GetCertPemForPython = MagicMock(side_effect=fake_get_cert)

        monkeypatch.setattr(ctypes, "CDLL", lambda path: mock_lib)
        result = _ecp_get_cert_inprocess("/fake/lib.so", "/fake/config.json")
        assert result == pem
        assert call_count == 2

    def test_zero_length_raises(self, monkeypatch):
        """Should raise RuntimeError when ECP returns cert_len <= 0."""
        mock_lib = MagicMock()
        mock_lib.GetCertPemForPython = MagicMock(return_value=0)
        monkeypatch.setattr(ctypes, "CDLL", lambda path: mock_lib)

        with pytest.raises(RuntimeError, match="cert_len=0"):
            _ecp_get_cert_inprocess("/fake/lib.so", "/fake/config.json")

    def test_negative_length_raises(self, monkeypatch):
        """Should raise RuntimeError when ECP returns negative cert_len."""
        mock_lib = MagicMock()
        mock_lib.GetCertPemForPython = MagicMock(return_value=-1)
        monkeypatch.setattr(ctypes, "CDLL", lambda path: mock_lib)

        with pytest.raises(RuntimeError, match="cert_len=-1"):
            _ecp_get_cert_inprocess("/fake/lib.so", "/fake/config.json")


# ---------------------------------------------------------------------------
# _ecp_get_cert_subprocess
# ---------------------------------------------------------------------------


class TestEcpGetCertSubprocess:
    @patch("wif_bunker.cert._find_system_python", return_value=sys.executable)
    def test_success_returns_stdout(self, _mock_python, monkeypatch):
        """Should return subprocess stdout on success."""
        pem = b"-----BEGIN CERTIFICATE-----\nMIIBxyz\n-----END CERTIFICATE-----\n"
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, stdout=pem, stderr=b""),
        )
        result = _ecp_get_cert_subprocess("/fake/lib.so", "/fake/config.json")
        assert result == pem

    @patch("wif_bunker.cert._find_system_python", return_value=sys.executable)
    def test_nonzero_exit_raises(self, _mock_python, monkeypatch):
        """Should raise RuntimeError when subprocess exits non-zero."""
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(a[0], 1, stdout=b"", stderr=b"some error"),
        )
        with pytest.raises(RuntimeError, match="some error"):
            _ecp_get_cert_subprocess("/fake/lib.so", "/fake/config.json")

    @patch("wif_bunker.cert._find_system_python", return_value=sys.executable)
    def test_timeout_propagates(self, _mock_python, monkeypatch):
        """Should let TimeoutExpired propagate."""

        def fake_run(*a, **kw):
            raise subprocess.TimeoutExpired(cmd=a[0], timeout=30)

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(subprocess.TimeoutExpired):
            _ecp_get_cert_subprocess("/fake/lib.so", "/fake/config.json")

    @patch("wif_bunker.cert._find_system_python", return_value="/usr/bin/python3")
    def test_uses_found_python(self, _mock_python, monkeypatch):
        """Should invoke the python returned by _find_system_python."""
        invocations = []

        def capture_run(cmd, **kw):
            invocations.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout=b"pem", stderr=b"")

        monkeypatch.setattr(subprocess, "run", capture_run)
        _ecp_get_cert_subprocess("/fake/lib.so", "/fake/config.json")
        assert invocations[0][0] == "/usr/bin/python3"
        assert invocations[0][1] == "-c"
