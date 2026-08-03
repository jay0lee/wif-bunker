"""Tests for attestation base module — EK chain verification and cert loading."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wif_bunker.attestation.base import AttestationCheck, _load_certs, verify_ek_chain


def _generate_ca_and_signed_cert() -> tuple[str, str]:
    """Generate a self-signed CA cert and a cert signed by that CA.

    Returns (ca_pem, signed_cert_pem) as strings.
    """
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TPM Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    ek_key = ec.generate_private_key(ec.SECP256R1())
    ek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test EK Certificate")])
    ek_cert = (
        x509.CertificateBuilder()
        .subject_name(ek_name)
        .issuer_name(ca_name)
        .public_key(ek_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ek_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ek_pem = ek_cert.public_bytes(serialization.Encoding.PEM).decode()

    return ca_pem, ek_pem


def _generate_self_signed_cert() -> str:
    """Generate a self-signed certificate not in any trust bundle."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Self-Signed")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class TestLoadCerts:
    """Tests for _load_certs helper."""

    def test_loads_pem_files_from_directory(self, tmp_path):
        """Loads all .pem files from a directory."""
        ca_pem, _ = _generate_ca_and_signed_cert()
        (tmp_path / "root1.pem").write_text(ca_pem)
        (tmp_path / "root2.pem").write_text(_generate_self_signed_cert())

        certs = _load_certs(tmp_path)
        assert len(certs) == 2
        assert all(isinstance(c, x509.Certificate) for c in certs)

    def test_ignores_non_pem_files(self, tmp_path):
        """Non-.pem files are not loaded."""
        ca_pem, _ = _generate_ca_and_signed_cert()
        (tmp_path / "root.pem").write_text(ca_pem)
        (tmp_path / "readme.txt").write_text("not a cert")
        (tmp_path / "cert.der").write_bytes(b"\x00\x01")

        certs = _load_certs(tmp_path)
        assert len(certs) == 1

    def test_empty_directory(self, tmp_path):
        """Empty directory returns empty list."""
        certs = _load_certs(tmp_path)
        assert certs == []


class TestVerifyEkChain:
    """Tests for verify_ek_chain using cryptography library."""

    def test_no_roots_returns_failed(self, tmp_path, monkeypatch):
        """Returns failed check when roots directory doesn't exist."""
        monkeypatch.setattr(
            "wif_bunker.attestation.base.__file__",
            str(tmp_path / "base.py"),
        )
        result = verify_ek_chain("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")
        assert isinstance(result, AttestationCheck)
        assert result.passed is False

    def test_valid_chain_passes(self, tmp_path, monkeypatch):
        """EK cert signed by a bundled root CA passes verification."""
        ca_pem, ek_pem = _generate_ca_and_signed_cert()

        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "test_ca.pem").write_text(ca_pem)

        monkeypatch.setattr(
            "wif_bunker.attestation.base.__file__",
            str(tmp_path / "base.py"),
        )
        result = verify_ek_chain(ek_pem)
        assert isinstance(result, AttestationCheck)
        assert result.passed is True
        assert "verified" in result.detail.lower()

    def test_untrusted_cert_fails(self, tmp_path, monkeypatch):
        """Self-signed cert not in bundle fails verification."""
        ca_pem, _ = _generate_ca_and_signed_cert()
        untrusted_pem = _generate_self_signed_cert()

        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "test_ca.pem").write_text(ca_pem)

        monkeypatch.setattr(
            "wif_bunker.attestation.base.__file__",
            str(tmp_path / "base.py"),
        )
        result = verify_ek_chain(untrusted_pem)
        assert isinstance(result, AttestationCheck)
        assert result.passed is False

    def test_malformed_pem_fails(self, tmp_path, monkeypatch):
        """Garbage PEM data fails gracefully."""
        ca_pem, _ = _generate_ca_and_signed_cert()
        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "test_ca.pem").write_text(ca_pem)

        monkeypatch.setattr(
            "wif_bunker.attestation.base.__file__",
            str(tmp_path / "base.py"),
        )
        result = verify_ek_chain("not-a-certificate")
        assert isinstance(result, AttestationCheck)
        assert result.passed is False

    def test_does_not_call_openssl(self, tmp_path, monkeypatch):
        """verify_ek_chain uses cryptography library, not openssl CLI."""
        import subprocess

        original_run = subprocess.run

        def fail_on_openssl(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            if isinstance(cmd, list) and cmd and cmd[0] == "openssl":
                pytest.fail("verify_ek_chain should not call openssl CLI")
            return original_run(*args, **kwargs)

        ca_pem, ek_pem = _generate_ca_and_signed_cert()
        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "test_ca.pem").write_text(ca_pem)

        monkeypatch.setattr(
            "wif_bunker.attestation.base.__file__",
            str(tmp_path / "base.py"),
        )
        monkeypatch.setattr(subprocess, "run", fail_on_openssl)

        result = verify_ek_chain(ek_pem)
        assert result.passed is True


def _generate_3_cert_chain() -> tuple[str, str, str]:
    """Generate a root, intermediate, and EK certificate."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_name)
        .issuer_name(root_name)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    ek_key = ec.generate_private_key(ec.SECP256R1())
    ek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EK Cert")])
    ek_cert = (
        x509.CertificateBuilder()
        .subject_name(ek_name)
        .issuer_name(inter_name)
        .public_key(ek_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ek_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()), critical=False)
        .sign(inter_key, hashes.SHA256())
    )

    return (
        root_cert.public_bytes(serialization.Encoding.PEM).decode(),
        inter_cert.public_bytes(serialization.Encoding.PEM).decode(),
        ek_cert.public_bytes(serialization.Encoding.PEM).decode(),
    )


class TestVerifyEkChainIntermediates:
    """Tests for intermediate CA handling in verify_ek_chain."""

    def test_chain_through_intermediate(self, tmp_path, monkeypatch):
        root_pem, inter_pem, ek_pem = _generate_3_cert_chain()
        roots_dir = tmp_path / "roots" / "roots"
        inter_dir = tmp_path / "roots" / "intermediates"
        roots_dir.mkdir(parents=True)
        inter_dir.mkdir(parents=True)

        (roots_dir / "root.pem").write_text(root_pem)
        (inter_dir / "inter.pem").write_text(inter_pem)

        monkeypatch.setattr("wif_bunker.attestation.base.__file__", str(tmp_path / "base.py"))
        result = verify_ek_chain(ek_pem)
        assert result.passed is True

    def test_intermediate_only_no_root_fails(self, tmp_path, monkeypatch):
        _, inter_pem, ek_pem = _generate_3_cert_chain()
        roots_dir = tmp_path / "roots" / "roots"
        inter_dir = tmp_path / "roots" / "intermediates"
        roots_dir.mkdir(parents=True)
        inter_dir.mkdir(parents=True)

        # Put a dummy root in roots to bypass the empty check
        (roots_dir / "dummy_root.pem").write_text(_generate_self_signed_cert())

        # Put intermediate in intermediates
        (inter_dir / "inter.pem").write_text(inter_pem)

        monkeypatch.setattr("wif_bunker.attestation.base.__file__", str(tmp_path / "base.py"))
        result = verify_ek_chain(ek_pem)
        assert result.passed is False


class TestPyOpenSSLFallback:
    """Tests for the pyOpenSSL-based fallback when cryptography's strict parser rejects a cert."""

    def test_load_cert_lenient_normal_path(self):
        """_load_cert_lenient succeeds via cryptography for well-formed certs."""
        from wif_bunker.attestation.base import _load_cert_lenient

        _, ek_pem = _generate_ca_and_signed_cert()
        cert = _load_cert_lenient(ek_pem.encode())
        assert cert.subject is not None

    def test_load_cert_lenient_pyopenssl_fallback(self):
        """_load_cert_lenient falls back to pyOpenSSL when strict parser fails."""
        from unittest.mock import patch

        from wif_bunker.attestation.base import _load_cert_lenient

        _, ek_pem = _generate_ca_and_signed_cert()

        # Make cryptography's parser fail on first call, succeed on second
        original_load = x509.load_pem_x509_certificate
        call_count = 0

        def fail_then_succeed(data, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Simulated InvalidSetOrdering")
            return original_load(data, *args, **kwargs)

        with patch(
            "wif_bunker.attestation.base.x509.load_pem_x509_certificate",
            side_effect=fail_then_succeed,
        ):
            cert = _load_cert_lenient(ek_pem.encode())

        assert cert.subject is not None
        assert call_count == 2

    def test_pyopenssl_fallback_verifies_chain(self, tmp_path, monkeypatch):
        """When strict parser fails for EK cert, pyOpenSSL re-encode allows chain verification."""
        from unittest.mock import patch

        ca_pem, ek_pem = _generate_ca_and_signed_cert()

        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "ca.pem").write_text(ca_pem)
        monkeypatch.setattr("wif_bunker.attestation.base.__file__", str(tmp_path / "base.py"))

        # Make _load_cert_lenient's first attempt (strict) fail for the EK cert.
        # pyOpenSSL will re-encode it, and the second load attempt will succeed.
        original_load = x509.load_pem_x509_certificate
        call_count = 0

        def strict_fails_first_time(data, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            # First call is for the EK cert — simulate strict parser rejection
            if call_count == 1:
                raise ValueError("Simulated InvalidSetOrdering")
            # All subsequent calls succeed (re-encoded EK cert, CA certs)
            return original_load(data, *args, **kwargs)

        with patch(
            "wif_bunker.attestation.base.x509.load_pem_x509_certificate",
            side_effect=strict_fails_first_time,
        ):
            result = verify_ek_chain(ek_pem)

        assert result.passed is True

    def test_both_parsers_fail_gives_clear_error(self, tmp_path, monkeypatch):
        """When both cryptography and pyOpenSSL fail, error is clear."""

        ca_pem, _ = _generate_ca_and_signed_cert()
        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "ca.pem").write_text(ca_pem)
        monkeypatch.setattr("wif_bunker.attestation.base.__file__", str(tmp_path / "base.py"))

        garbage_pem = "-----BEGIN CERTIFICATE-----\nbm90YWNlcnQ=\n-----END CERTIFICATE-----"

        result = verify_ek_chain(garbage_pem)

        assert result.passed is False
        assert "Could not parse EK certificate" in result.detail
