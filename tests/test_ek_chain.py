"""Tests for attestation base module — EK chain verification and cert loading."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wif_bunker.attestation.base import (
    AttestationCheck,
    _load_certs,
    _verify_ek_chain_openssl,
    verify_ek_chain,
)


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


class TestMissingIntermediateFallback:
    """Tests for chain verification when intermediate is missing from bundled certs."""

    def test_manually_managed_roots_loaded(self, tmp_path, monkeypatch):
        """Certs in manually-managed/ are loaded as both roots and intermediates."""
        root_pem, inter_pem, ek_pem = _generate_3_cert_chain()

        # Put root in manually-managed instead of roots/
        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        manually_managed = tmp_path / "roots" / "manually-managed"
        manually_managed.mkdir(parents=True)

        # Need at least one cert in roots dir to pass the empty check
        (roots_dir / "dummy.pem").write_text(_generate_self_signed_cert())
        # Put the actual root in manually-managed
        (manually_managed / "custom_root.pem").write_text(root_pem)

        # Also need the intermediate for the 3-cert chain
        inter_dir = tmp_path / "roots" / "intermediates"
        inter_dir.mkdir(parents=True)
        (inter_dir / "inter.pem").write_text(inter_pem)

        monkeypatch.setattr("wif_bunker.attestation.base.__file__", str(tmp_path / "base.py"))
        result = verify_ek_chain(ek_pem)
        assert result.passed is True, f"Failed with manually-managed root: {result.detail}"

    def test_missing_intermediate_no_aia_still_fails(self, tmp_path, monkeypatch):
        """When intermediate is missing and AIA chasing can't help, check fails cleanly."""
        root_pem, _inter_pem, ek_pem = _generate_3_cert_chain()

        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "root.pem").write_text(root_pem)
        (tmp_path / "roots" / "intermediates").mkdir(parents=True)

        monkeypatch.setattr("wif_bunker.attestation.base.__file__", str(tmp_path / "base.py"))

        # EK cert has no AIA extension, so AIA chasing has nothing to fetch
        result = verify_ek_chain(ek_pem)
        assert result.passed is False


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


class TestOpenSSLVerification:
    """Tests for _verify_ek_chain_openssl (the sole chain verification path)."""

    def test_verifies_valid_chain(self, tmp_path):
        """_verify_ek_chain_openssl verifies a properly-signed cert."""
        ca_pem, ek_pem = _generate_ca_and_signed_cert()

        roots_dir = tmp_path / "roots"
        roots_dir.mkdir()
        (roots_dir / "ca.pem").write_text(ca_pem)
        intermediates_dir = tmp_path / "intermediates"

        result = _verify_ek_chain_openssl(ek_pem, roots_dir, intermediates_dir)
        assert result.passed is True

    def test_rejects_unrelated_cert(self, tmp_path):
        """_verify_ek_chain_openssl fails when cert is not signed by any root."""
        ca_pem, _ = _generate_ca_and_signed_cert()
        _, unrelated_ek_pem = _generate_ca_and_signed_cert()  # different CA

        roots_dir = tmp_path / "roots"
        roots_dir.mkdir()
        (roots_dir / "ca.pem").write_text(ca_pem)
        intermediates_dir = tmp_path / "intermediates"

        result = _verify_ek_chain_openssl(unrelated_ek_pem, roots_dir, intermediates_dir)
        assert result.passed is False
        assert "verification failed" in result.detail

    def test_garbage_cert(self, tmp_path):
        """_verify_ek_chain_openssl gives clear error on garbage input."""
        ca_pem, _ = _generate_ca_and_signed_cert()
        roots_dir = tmp_path / "roots"
        roots_dir.mkdir()
        (roots_dir / "ca.pem").write_text(ca_pem)
        intermediates_dir = tmp_path / "intermediates"

        garbage_pem = "-----BEGIN CERTIFICATE-----\nbm90YWNlcnQ=\n-----END CERTIFICATE-----"
        result = _verify_ek_chain_openssl(garbage_pem, roots_dir, intermediates_dir)
        assert result.passed is False
        assert "could not parse" in result.detail.lower()

    def test_garbage_pem_via_verify_ek_chain(self, tmp_path, monkeypatch):
        """Garbage PEM through the public API gives clear error."""
        ca_pem, _ = _generate_ca_and_signed_cert()
        roots_dir = tmp_path / "roots" / "roots"
        roots_dir.mkdir(parents=True)
        (roots_dir / "ca.pem").write_text(ca_pem)
        monkeypatch.setattr("wif_bunker.attestation.base.__file__", str(tmp_path / "base.py"))

        garbage_pem = "-----BEGIN CERTIFICATE-----\nbm90YWNlcnQ=\n-----END CERTIFICATE-----"
        result = verify_ek_chain(garbage_pem)

        assert result.passed is False
        assert "could not parse" in result.detail.lower()
