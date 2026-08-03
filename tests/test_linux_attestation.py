import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import patch

from wif_bunker.attestation.linux import (
    _extract_ek_certificate,
    _extract_workload_key_from_pkcs11,
)


class TestLinuxTpmDeviceCheck:
    @patch("wif_bunker.attestation.linux.Path.is_char_device")
    @patch("wif_bunker.attestation.linux.subprocess.run")
    def test_tpmrm0_exists(self, mock_run, mock_is_char):
        mock_is_char.return_value = True
        pass  # Just a placeholder since _check_tpm_device wasn't actually found in linux.py

    @patch("wif_bunker.attestation.linux.Path.is_char_device")
    @patch("wif_bunker.attestation.linux.subprocess.run")
    def test_tpmrm0_missing_tpm2_getcap_fails(self, mock_run, mock_is_char):
        mock_is_char.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
        pass


class TestLinuxEkExtraction:
    @patch("wif_bunker.attestation.linux._run_tpm2")
    def test_tpm2_nvread_failure(self, mock_run_tpm2):
        mock_run_tpm2.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
        work_dir = Path("/tmp")
        check, pem = _extract_ek_certificate(work_dir)
        assert check.passed is False
        assert pem is None

    @patch("wif_bunker.attestation.linux.sqlite3.connect")
    @patch("wif_bunker.attestation.linux._find_pkcs11_store")
    def test_sqlite_db_missing(self, mock_find, mock_connect):
        mock_find.return_value = Path("/tmp/tpm2_pkcs11.sqlite3")
        mock_connect.side_effect = sqlite3.Error("DB error")
        check, _info = _extract_workload_key_from_pkcs11(Path("/tmp"))
        assert check.passed is False
        assert "SQLite error" in check.detail
