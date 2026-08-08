"""Tests for hardmTLS cert retrieval."""

from __future__ import annotations

import ctypes
from unittest.mock import MagicMock

import pytest

from wif_bunker.cert import hardmtls_get_cert_pem

# ---------------------------------------------------------------------------
# hardmtls_get_cert_pem
# ---------------------------------------------------------------------------


class TestHardmtlsGetCertPem:
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
        result = hardmtls_get_cert_pem("/fake/lib.so", "/fake/config.json")
        assert result == pem
        assert call_count == 2

    def test_zero_length_raises(self, monkeypatch):
        """Should raise RuntimeError when hardmTLS returns cert_len <= 0."""
        mock_lib = MagicMock()
        mock_lib.GetCertPemForPython = MagicMock(return_value=0)
        monkeypatch.setattr(ctypes, "CDLL", lambda path: mock_lib)

        with pytest.raises(RuntimeError, match="cert_len=0"):
            hardmtls_get_cert_pem("/fake/lib.so", "/fake/config.json")

    def test_negative_length_raises(self, monkeypatch):
        """Should raise RuntimeError when hardmTLS returns negative cert_len."""
        mock_lib = MagicMock()
        mock_lib.GetCertPemForPython = MagicMock(return_value=-1)
        monkeypatch.setattr(ctypes, "CDLL", lambda path: mock_lib)

        with pytest.raises(RuntimeError, match="cert_len=-1"):
            hardmtls_get_cert_pem("/fake/lib.so", "/fake/config.json")
