"""Generate bogus test certificates for negative testing of EK chain verification."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _write_pem(cert, path):
    path.write_text(cert.public_bytes(serialization.Encoding.PEM).decode())
    print(f"  Wrote {path}")


def generate_fixtures(fixtures_dir):
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Self-signed cert pretending to be an EK
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake EK Certificate")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=36500))
        .sign(key, hashes.SHA256())
    )
    _write_pem(cert, fixtures_dir / "bogus_self_signed.pem")

    # 2. Cert signed by unrelated CA (CA not in any trust store)
    rogue_ca_key = ec.generate_private_key(ec.SECP256R1())
    rogue_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")])
    rogue_ca_cert = (  # noqa: F841 — built for completeness, only key used
        x509.CertificateBuilder()
        .subject_name(rogue_ca_name)
        .issuer_name(rogue_ca_name)
        .public_key(rogue_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=36500))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    ek_key = ec.generate_private_key(ec.SECP256R1())
    ek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EK from rogue CA")])
    ek_cert = (
        x509.CertificateBuilder()
        .subject_name(ek_name)
        .issuer_name(rogue_ca_name)
        .public_key(ek_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=36500))
        .sign(rogue_ca_key, hashes.SHA256())
    )
    _write_pem(ek_cert, fixtures_dir / "bogus_wrong_signer.pem")

    # 3. Expired cert (signed by a "valid" CA but cert itself expired)
    expired_key = ec.generate_private_key(ec.SECP256R1())
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired EK")]))
        .issuer_name(rogue_ca_name)
        .public_key(expired_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=365))
        .not_valid_after(now - datetime.timedelta(days=1))
        .sign(rogue_ca_key, hashes.SHA256())
    )
    _write_pem(expired_cert, fixtures_dir / "bogus_expired.pem")

    print("All bogus fixtures generated.")


if __name__ == "__main__":
    from pathlib import Path

    fixtures_dir = Path(__file__).parent / "fixtures"
    fixtures_dir.mkdir(exist_ok=True)
    generate_fixtures(fixtures_dir)
