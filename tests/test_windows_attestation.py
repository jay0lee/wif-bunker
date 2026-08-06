"""Tests for the Windows attestation module."""

import datetime
import json
import subprocess
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from wif_bunker.attestation.base import _decode_manufacturer_id, _parse_tcg_attributes
from wif_bunker.attestation.windows import (
    _PS_PREAMBLE,
    _check_ek_info,
    _check_exportability,
    _check_key_provider,
    _check_tpm_status,
    _extract_ek_certificate,
    _ncrypt_create_claim,
    _run_powershell,
)


def _generate_self_signed_cert() -> str:
    """Generate a self-signed cert for testing EK extraction."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Manufacturer")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class TestRunPowershell:
    """Tests for _run_powershell."""

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_preamble_prepended_by_default(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _run_powershell("Get-Test")
        cmd_string = mock_run.call_args[0][0][-1]
        assert "Microsoft.PowerShell.Security" in cmd_string
        assert "Import-Module PKI" in cmd_string
        assert "Get-Test" in cmd_string

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_preamble_skipped_when_false(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _run_powershell("Get-Test", preamble=False)
        cmd_string = mock_run.call_args[0][0][-1]
        assert "Microsoft.PowerShell.Security" not in cmd_string
        assert "Get-Test" in cmd_string

    def test_preamble_does_not_contain_old_import(self):
        assert _PS_PREAMBLE != "Import-Module PKI -ErrorAction SilentlyContinue; "
        assert "Microsoft.PowerShell.Security" in _PS_PREAMBLE
        assert "Import-Module PKI" in _PS_PREAMBLE


class TestCheckTpmStatus:
    """Tests for _check_tpm_status."""

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_parses_valid_tpm_json(self, mock_run):
        tpm_output = json.dumps(
            {"TpmPresent": True, "TpmReady": True, "ManufacturerId": 1095582720, "ManufacturerVersion": "1.2.3"}
        )
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=tpm_output, stderr="")

        check, info = _check_tpm_status()

        assert check.passed is True
        assert "Manufacturer: Advanced Micro Devices (AMD)" in check.detail
        assert info is not None
        assert info["TpmPresent"] is True

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_handles_tpm_not_present(self, mock_run):
        tpm_output = json.dumps({"TpmPresent": False})
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=tpm_output, stderr="")

        check, _info = _check_tpm_status()

        assert check.passed is False

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_handles_powershell_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")

        check, info = _check_tpm_status()

        assert check.passed is False
        assert "error" in check.detail
        assert info is None

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_no_preamble_on_tpm_command(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")
        _check_tpm_status()
        cmd_string = mock_run.call_args[0][0][-1]
        assert "Microsoft.PowerShell.Security" not in cmd_string


class TestCheckEkInfo:
    """Tests for _check_ek_info."""

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_parses_valid_ek_info(self, mock_run):
        ek_output = json.dumps({"PublicKeyHash": "deadbeef", "ManufacturerCertificates": ["cert1"]})
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=ek_output, stderr="")

        check, info = _check_ek_info()

        assert check.passed is True
        assert info is not None
        assert "deadbeef" in check.detail
        assert "present" in check.detail

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_no_preamble_on_ek_command(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")
        _check_ek_info()
        cmd_string = mock_run.call_args[0][0][-1]
        assert "Microsoft.PowerShell.Security" not in cmd_string


class TestExtractEkCertificate:
    """Tests for _extract_ek_certificate."""

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_extracts_pem_and_issuer(self, mock_run):
        pem_cert = _generate_self_signed_cert()
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=pem_cert, stderr="")

        check, cert_out, _details = _extract_ek_certificate()

        assert check.passed is True
        assert "Test Manufacturer" in check.detail
        assert cert_out == pem_cert.strip()

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_handles_no_cert(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="NO_CERT", stderr="")

        check, cert_out, _details = _extract_ek_certificate()

        assert check.passed is False
        assert cert_out is None

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_no_preamble_on_ek_extract(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="NO_CERT", stderr="")
        _extract_ek_certificate()
        cmd_string = mock_run.call_args[0][0][-1]
        assert "Microsoft.PowerShell.Security" not in cmd_string


class TestCheckKeyProvider:
    """Tests for _check_key_provider."""

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_finds_platform_provider(self, mock_run, sample_config):
        sample_config.workload_cn = "test"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Microsoft Platform Crypto Provider|{GUID-123}", stderr=""
        )

        check, info = _check_key_provider(sample_config)

        assert check.passed is True
        assert info["provider"] == "Microsoft Platform Crypto Provider"
        assert info["key_name"] == "{GUID-123}"

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_finds_software_provider(self, mock_run, sample_config):
        sample_config.workload_cn = "test"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Microsoft Software Key Storage Provider|{GUID-123}", stderr=""
        )

        check, info = _check_key_provider(sample_config)

        assert check.passed is False
        assert "not TPM-backed" in check.detail
        assert info["provider"] == "Microsoft Software Key Storage Provider"
        assert info["key_name"] == "{GUID-123}"

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_handles_cert_not_found(self, mock_run, sample_config):
        sample_config.workload_cn = "test"
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="CERT_NOT_FOUND", stderr="")

        check, info = _check_key_provider(sample_config)

        assert check.passed is False
        assert "not found" in check.detail
        assert info is None

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_handles_no_private_key(self, mock_run, sample_config):
        sample_config.workload_cn = "test"
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="NO_PRIVATE_KEY", stderr="")

        check, info = _check_key_provider(sample_config)

        assert check.passed is False
        assert "Could not determine CNG key provider" in check.detail
        assert info is None

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_uses_preamble_for_cert_store(self, mock_run, sample_config):
        sample_config.workload_cn = "test"
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="CERT_NOT_FOUND", stderr="")
        _check_key_provider(sample_config)
        cmd_string = mock_run.call_args[0][0][-1]
        assert "Microsoft.PowerShell.Security" in cmd_string


class TestCheckExportability:
    """Tests for _check_exportability."""

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_non_exportable_key(self, mock_run, sample_config):
        sample_config.workload_cn = "test"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="HasPrivateKey=True\n", stderr=""
        )

        check = _check_exportability(sample_config)

        assert check.passed is True
        assert "non-exportable" in check.detail

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_cert_not_found(self, mock_run, sample_config):
        sample_config.workload_cn = "test"
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="NOT_FOUND", stderr="")

        check = _check_exportability(sample_config)

        assert check.passed is False
        assert "not found" in check.detail


class TestNcryptCreateClaim:
    """Tests for _ncrypt_create_claim."""

    @patch.dict("sys.modules", {"ctypes": MagicMock(), "ctypes.wintypes": MagicMock()})
    def test_skips_without_key_info(self, sample_config):
        check, blob = _ncrypt_create_claim(sample_config, key_info=None)

        assert check.passed is False
        assert "Skipped" in check.detail
        assert blob is None

    @patch.dict("sys.modules", {"ctypes": MagicMock(), "ctypes.wintypes": MagicMock()})
    def test_uses_key_name_from_info(self, sample_config):
        sample_config.workload_cn = "test"
        key_info = {"provider": "Microsoft Platform Crypto Provider", "key_name": "{THE-KEY-NAME}"}

        import sys

        mock_ctypes = sys.modules["ctypes"]
        mock_ncrypt = MagicMock()
        mock_ctypes.windll.ncrypt = mock_ncrypt
        mock_ncrypt.NCryptOpenStorageProvider.return_value = 0
        # First NCryptOpenKey is for the subject key — make it fail to return early
        mock_ncrypt.NCryptOpenKey.return_value = 1

        check, _blob = _ncrypt_create_claim(sample_config, key_info=key_info)

        assert check.passed is False

        # First NCryptOpenKey call should be for the subject key name
        first_call_args = mock_ncrypt.NCryptOpenKey.call_args_list[0][0]
        assert first_call_args[2] == "{THE-KEY-NAME}"


class TestCheckTpmStatusMalformedJson:
    """Tests for edge cases in _check_tpm_status JSON parsing."""

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_malformed_json_returns_failed(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="not json", stderr="")
        check, info = _check_tpm_status()
        assert check.passed is False
        assert "Could not parse" in check.detail
        assert info is None

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_partial_json_missing_keys(self, mock_run):
        tpm_output = '{"TpmPresent": true}'
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=tpm_output, stderr="")
        check, info = _check_tpm_status()
        assert check.passed is False  # TpmReady is missing/false
        assert "TPM Present: True" in check.detail
        assert info is not None

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_empty_stdout(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        check, info = _check_tpm_status()
        assert check.passed is False
        assert "Could not parse" in check.detail
        assert info is None

    @patch("wif_bunker.attestation.windows.subprocess.run")
    def test_json_string_instead_of_dict(self, mock_run):
        """Reproduce the Dell crash: json.loads returns str, not dict."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='"some string output"', stderr=""
        )
        check, info = _check_tpm_status()
        assert check.passed is False
        assert "Unexpected" in check.detail
        assert info is None


class TestNcryptCreateClaimEdgeCases:
    """Additional edge cases for _ncrypt_create_claim."""

    @patch.dict("sys.modules", {"ctypes": None, "ctypes.wintypes": None})
    def test_skips_when_no_ctypes(self, sample_config):
        check, blob = _ncrypt_create_claim(sample_config, key_info={"provider": "p", "key_name": "k"})
        assert check.passed is False
        assert "ctypes.wintypes not available" in check.detail
        assert blob is None

    @patch.dict("sys.modules", {"ctypes": MagicMock(), "ctypes.wintypes": MagicMock()})
    def test_skips_with_empty_key_info(self, sample_config):
        check, blob = _ncrypt_create_claim(sample_config, key_info={})
        assert check.passed is False
        assert "Skipped" in check.detail
        assert blob is None


class TestDecodeManufacturerId:
    """Tests for _decode_manufacturer_id."""

    def test_known_nuvoton(self):
        assert _decode_manufacturer_id(1314145024) == "Nuvoton Technology (NTC)"

    def test_known_infineon(self):
        assert _decode_manufacturer_id(1229346816) == "Infineon (IFX)"

    def test_known_intel(self):
        assert _decode_manufacturer_id(1229870147) == "Intel (INTC)"

    def test_known_amd(self):
        assert _decode_manufacturer_id(1095582720) == "Advanced Micro Devices (AMD)"

    def test_known_stm(self):
        assert _decode_manufacturer_id(1398033696) == "STMicroelectronics (STM)"

    def test_unknown_fallback_ascii(self):
        # 0x58595A00 = 'XYZ\0'
        result = _decode_manufacturer_id(0x58595A00)
        assert "XYZ" in result

    def test_string_input(self):
        assert _decode_manufacturer_id("1314145024") == "Nuvoton Technology (NTC)"

    def test_invalid_input(self):
        result = _decode_manufacturer_id("not_a_number")
        assert result == "not_a_number"


class TestParseTcgAttributes:
    """Tests for _parse_tcg_attributes."""

    def test_returns_empty_for_standard_cert(self):
        """A standard self-signed cert has no TCG attributes."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")]))
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .public_key(key.public_key())
            .sign(key, hashes.SHA256())
        )
        attrs = _parse_tcg_attributes(cert)
        assert attrs == {}
