"""Unhappy-path tests for the --status flow."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wif_bunker.modes import _run_status


def _generate_test_cert_pem(days_valid: int) -> bytes:
    """Generate a self-signed PEM cert valid for `days_valid` days from now."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-workload")])
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=min(-10, days_valid - 10)))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class TestRunStatusMissingFiles:
    def test_missing_all_config_files(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        _run_status()
        assert "Missing config files" in caplog.text

    def test_missing_workload_cert_only(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        (tmp_path / "certificate_config.json").write_text("{}")
        (tmp_path / "trust_chain.pem").write_text("dummy")
        _run_status()
        assert "Missing config files: workload_cert.pem" in caplog.text


class TestRunStatusExpiredCert:
    def test_expired_cert_shows_expired_warning(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        (tmp_path / "certificate_config.json").write_text("{}")
        (tmp_path / "trust_chain.pem").write_text("dummy")
        cert_bytes = _generate_test_cert_pem(days_valid=-1)
        (tmp_path / "workload_cert.pem").write_bytes(cert_bytes)

        _run_status()

        assert "Certificate has EXPIRED" in caplog.text

    def test_nearly_expired_cert_shows_warning(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        (tmp_path / "certificate_config.json").write_text("{}")
        (tmp_path / "trust_chain.pem").write_text("dummy")
        cert_bytes = _generate_test_cert_pem(days_valid=5)
        (tmp_path / "workload_cert.pem").write_bytes(cert_bytes)

        _run_status()

        assert "WARNING: Certificate expires in " in caplog.text

    def test_valid_cert_no_warnings(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        (tmp_path / "certificate_config.json").write_text("{}")
        (tmp_path / "trust_chain.pem").write_text("dummy")
        cert_bytes = _generate_test_cert_pem(days_valid=90)
        (tmp_path / "workload_cert.pem").write_bytes(cert_bytes)

        _run_status()

        assert "Certificate has EXPIRED" not in caplog.text
        assert "WARNING: Certificate expires in" not in caplog.text


class TestRunStatusBadCert:
    def test_corrupt_cert_file(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        (tmp_path / "certificate_config.json").write_text("{}")
        (tmp_path / "trust_chain.pem").write_text("dummy")
        (tmp_path / "workload_cert.pem").write_bytes(b"garbage data")

        _run_status()

        assert "Failed to parse certificate" in caplog.text

    def test_empty_cert_file(self, monkeypatch, tmp_path, caplog):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        (tmp_path / "certificate_config.json").write_text("{}")
        (tmp_path / "trust_chain.pem").write_text("dummy")
        (tmp_path / "workload_cert.pem").write_bytes(b"")

        _run_status()

        assert "Failed to parse certificate" in caplog.text
