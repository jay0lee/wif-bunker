import json

from cryptography import x509

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import _DEFAULT_CERT_LIFETIME_DAYS, CertificateBundle


def test_create_ca_and_sign_returns_bundle(sample_config, sample_csr_pem):
    bundle, workload_pem = _create_ca_and_sign(sample_csr_pem, sample_config)
    assert isinstance(bundle, CertificateBundle)
    assert isinstance(workload_pem, str)
    assert "BEGIN CERTIFICATE" in workload_pem


def test_create_ca_and_sign_chain_valid(sample_config, sample_csr_pem):
    bundle, workload_pem = _create_ca_and_sign(sample_csr_pem, sample_config)
    ca_cert = x509.load_pem_x509_certificate(bundle.trust_anchor_pem.encode())
    workload_cert = x509.load_pem_x509_certificate(workload_pem.encode())
    assert workload_cert.issuer == ca_cert.subject


def test_create_ca_and_sign_bundle_fields(sample_config, sample_csr_pem):
    bundle, _workload_pem = _create_ca_and_sign(sample_csr_pem, sample_config)
    assert bundle.trust_anchor_pem.startswith("-----BEGIN CERTIFICATE")
    assert bundle.workload_cert_pem.startswith("-----BEGIN CERTIFICATE")
    assert bundle.issuer_cn == sample_config.ca_cn
    assert bundle.serial_number_hex
    assert bundle.sha256_fingerprint


def test_create_ca_and_sign_adc_json(sample_config, sample_csr_pem):
    bundle, _workload_pem = _create_ca_and_sign(sample_csr_pem, sample_config)
    # verify that bundle fields can be json dumped
    data = {
        "trust_anchor": bundle.trust_anchor_pem,
        "workload_cert": bundle.workload_cert_pem,
    }
    assert json.dumps(data)


def test_create_ca_and_sign_lifetime(sample_config, sample_csr_pem):
    _bundle, workload_pem = _create_ca_and_sign(sample_csr_pem, sample_config)
    cert = x509.load_pem_x509_certificate(workload_pem.encode())
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    # allow some seconds of difference, around the default lifetime
    assert lifetime.days == _DEFAULT_CERT_LIFETIME_DAYS


def test_create_ca_and_sign_rsa_ca_for_rsa_workload(sample_rsa_config, sample_rsa_csr_pem):
    """RSA workload keys should get an RSA CA, not ECC."""
    bundle, _workload_pem = _create_ca_and_sign(sample_rsa_csr_pem, sample_rsa_config)
    ca_cert = x509.load_pem_x509_certificate(bundle.trust_anchor_pem.encode())
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    assert isinstance(ca_cert.public_key(), RSAPublicKey)


def test_create_ca_and_sign_es384_ca_for_es384_workload(sample_es384_config, sample_es384_csr_pem):
    """ES384 workload keys should get a P-384 CA."""
    bundle, _workload_pem = _create_ca_and_sign(sample_es384_csr_pem, sample_es384_config)
    ca_cert = x509.load_pem_x509_certificate(bundle.trust_anchor_pem.encode())
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

    ca_pub = ca_cert.public_key()
    assert isinstance(ca_pub, EllipticCurvePublicKey)
    assert ca_pub.curve.name == "secp384r1"


def test_create_ca_and_sign_es256_ca_for_es256_workload(sample_config, sample_csr_pem):
    """ES256 (default) should get a P-256 CA."""
    bundle, _workload_pem = _create_ca_and_sign(sample_csr_pem, sample_config)
    ca_cert = x509.load_pem_x509_certificate(bundle.trust_anchor_pem.encode())
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

    ca_pub = ca_cert.public_key()
    assert isinstance(ca_pub, EllipticCurvePublicKey)
    assert ca_pub.curve.name == "secp256r1"
