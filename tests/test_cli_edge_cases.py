"""Tests for CLI edge cases and exotic certificate types."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from wif_bunker.cli import main
from wif_bunker.config import WorkloadConfig
from wif_bunker.modes import _run_attest, _run_status


class TestAttestWithDerCert:
    def test_der_encoded_cert_raises(self, tmp_path):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "der-test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        cert_file = tmp_path / "cert.der"
        cert_file.write_bytes(der_bytes)

        config = WorkloadConfig()
        with pytest.raises(ValueError):
            _run_attest(config, str(tmp_path), str(cert_file))


class TestAttestWithExoticKeyTypes:
    @patch("wif_bunker.modes.print_attestation_summary")
    @patch("wif_bunker.modes.write_attestation_report")
    @patch("wif_bunker.modes.generate_attestation")
    def test_ed25519_cert(self, mock_attest, _mock_write, _mock_print, tmp_path):
        from wif_bunker.attestation.base import AttestationReport

        key = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed25519-test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .sign(key, None)
        )
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_bytes(pem_bytes)

        config = WorkloadConfig()
        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        _run_attest(config, str(tmp_path), str(cert_file))
        assert config.workload_cn == "ed25519-test"
        mock_attest.assert_called_once()

    @patch("wif_bunker.modes.print_attestation_summary")
    @patch("wif_bunker.modes.write_attestation_report")
    @patch("wif_bunker.modes.generate_attestation")
    def test_rsa4096_cert(self, mock_attest, _mock_write, _mock_print, tmp_path):
        from wif_bunker.attestation.base import AttestationReport

        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsa4096-test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_bytes(pem_bytes)

        config = WorkloadConfig()
        mock_attest.return_value = AttestationReport(platform="test", supported=False, hardware_type="Test")
        _run_attest(config, str(tmp_path), str(cert_file))
        assert config.workload_cn == "rsa4096-test"
        mock_attest.assert_called_once()


class TestStatusWithExoticCerts:
    def test_status_with_ed25519_cert(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        # Write cert
        key = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed25519-status")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .sign(key, None)
        )
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        (tmp_path / "workload_cert.pem").write_bytes(pem_bytes)

        # Write config files
        (tmp_path / "adc.json").write_text("{}")
        (tmp_path / "certificate_config.json").write_text('{"libs": {}}')
        (tmp_path / "trust_chain.pem").write_text("dummy")

        # Call _run_status. It shouldn't crash.
        _run_status()


class TestCliExceptionHandlers:
    @patch("wif_bunker.cli._run_status")
    @patch("sys.argv", ["wif-bunker", "--status"])
    def test_keyboard_interrupt_exits_cleanly(self, mock_status):
        mock_status.side_effect = KeyboardInterrupt
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 130

    @patch("wif_bunker.cli._run_status")
    @patch("sys.argv", ["wif-bunker", "--status"])
    def test_http_error_shows_message(self, mock_status):
        response = MagicMock()
        response.status_code = 403
        response.text = "Permission denied"
        mock_status.side_effect = requests.exceptions.HTTPError("HTTP Error", response=response)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("wif_bunker.cli._run_status")
    @patch("sys.argv", ["wif-bunker", "--status"])
    def test_runtime_error_shows_message(self, mock_status):
        mock_status.side_effect = RuntimeError("TPM not found")
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


class TestCliArgumentParsing:
    @patch("sys.argv", ["wif-bunker", "--help"])
    def test_help_flag(self):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    @patch("sys.argv", ["wif-bunker", "--attest", "--cert-file", "/nonexistent/path.pem"])
    def test_attest_with_nonexistent_cert(self):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("sys.argv", ["wif-bunker", "--version"])
    def test_version_flag(self):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
