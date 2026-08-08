import datetime
import sys
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from OpenSSL.crypto import X509StoreContextError

from wif_bunker.attestation.base import (
    _decode_manufacturer_id,
    _load_certs,
    _parse_tcg_attributes,
    _verify_ek_chain_openssl,
    parse_ek_details,
    verify_ek_chain,
)


def _generate_test_cert_pem():
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test cert"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def test_load_certs_skips_bad_files(tmp_path):
    good_pem = _generate_test_cert_pem()

    (tmp_path / "good.pem").write_bytes(good_pem)
    (tmp_path / "bad.pem").write_text("this is not a cert")

    certs = _load_certs(tmp_path)
    assert len(certs) == 1


def test_verify_ek_chain_openssl_no_roots(tmp_path):
    roots_dir = tmp_path / "roots"
    roots_dir.mkdir()
    (roots_dir / "bad.pem").write_text("not a cert")

    ek_pem = _generate_test_cert_pem().decode("utf-8")
    check = _verify_ek_chain_openssl(ek_pem, roots_dir, tmp_path)
    assert not check.passed
    assert "No root CA certificates could be loaded" in check.detail


def test_verify_ek_chain_openssl_loads_intermediates(tmp_path):
    roots_dir = tmp_path / "roots"
    roots_dir.mkdir()
    (roots_dir / "good.pem").write_bytes(_generate_test_cert_pem())

    intermediates_dir = tmp_path / "intermediates"
    intermediates_dir.mkdir()
    (intermediates_dir / "bad.pem").write_text("not a cert")

    ek_pem = _generate_test_cert_pem().decode("utf-8")
    check = _verify_ek_chain_openssl(ek_pem, roots_dir, intermediates_dir)
    # The chain validation should fail because it's a self-signed cert
    # not in the store (unless the self-signed was generated as root)
    assert not check.passed


def test_verify_ek_chain_frozen_path(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    # Just verify it doesn't crash and returns the skipping message
    check = verify_ek_chain("dummy")
    assert not check.passed
    assert "No manufacturer root CA certificates bundled" in check.detail


def test_decode_manufacturer_id_fallback():
    # Test fallback to ASCII decoding
    # 0x41424344 = ABCD
    res = _decode_manufacturer_id(0x41424344)
    assert "ABCD" in res

    # Test un-decodable bytes
    res2 = _decode_manufacturer_id(0xFFFFFFFF)
    assert "0xFFFFFFFF" in res2


@patch("wif_bunker.attestation.base.x509.load_pem_x509_certificate")
@patch("OpenSSL.crypto.load_certificate")
def test_parse_ek_details_fallback(mock_ossl_load, mock_load, tmp_path):
    # Make standard cryptography parser raise Exception to trigger fallback
    mock_load.side_effect = Exception("Strict parse failed")

    mock_ossl_cert = MagicMock()
    mock_ossl_cert.get_serial_number.return_value = 1234
    mock_issuer = MagicMock()
    mock_issuer.get_components.return_value = [(b"CN", b"Test Issuer")]
    mock_ossl_cert.get_issuer.return_value = mock_issuer

    mock_ossl_load.return_value = mock_ossl_cert

    details = parse_ek_details("fake pem")
    assert details["serial"] == "4D2"  # hex of 1234
    assert details["issuer"] == "CN=Test Issuer"


@patch("wif_bunker.attestation.base.x509.load_pem_x509_certificate")
def test_parse_ek_details_fallback_completely_fails(mock_load):
    mock_load.side_effect = Exception("Strict parse failed")

    with patch("OpenSSL.crypto.load_certificate", side_effect=Exception("OpenSSL parse failed")):
        details = parse_ek_details("fake pem")
        assert details["issuer"] == "unknown"


@patch("OpenSSL.crypto.X509StoreContext.verify_certificate")
@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_aia_chasing_success(mock_urlopen, mock_run, mock_verify, tmp_path):
    # Setup directories
    roots_dir = tmp_path / "roots"
    roots_dir.mkdir()
    (roots_dir / "root.pem").write_bytes(_generate_test_cert_pem())
    intermediates_dir = tmp_path / "intermediates"
    intermediates_dir.mkdir()

    # First verify fails with 'unable to get local issuer certificate', second succeeds
    mock_verify.side_effect = [X509StoreContextError("unable to get local issuer certificate", [], None), None]

    # Subprocess run returns a dummy AIA URL
    mock_run.return_value = MagicMock(returncode=0, stdout="CA Issuers - URI:http://test.com/cert.cer")

    # urllib returns a cert
    cm = MagicMock()
    cm.__enter__.return_value.read.return_value = _generate_test_cert_pem()
    mock_urlopen.return_value = cm

    ek_pem = _generate_test_cert_pem().decode("utf-8")
    check = _verify_ek_chain_openssl(ek_pem, roots_dir, intermediates_dir)
    assert check.passed


@patch("OpenSSL.crypto.X509StoreContext.verify_certificate")
@patch("subprocess.run")
def test_aia_chasing_no_url(mock_run, mock_verify, tmp_path):
    roots_dir = tmp_path / "roots"
    roots_dir.mkdir()
    (roots_dir / "root.pem").write_bytes(_generate_test_cert_pem())
    intermediates_dir = tmp_path / "intermediates"
    intermediates_dir.mkdir()

    mock_verify.side_effect = X509StoreContextError("unable to get local issuer certificate", [], None)
    mock_run.return_value = MagicMock(returncode=0, stdout="No AIA extension here")

    ek_pem = _generate_test_cert_pem().decode("utf-8")
    check = _verify_ek_chain_openssl(ek_pem, roots_dir, intermediates_dir)
    assert not check.passed
    assert "no AIA extension" in check.detail


def test_parse_tcg_attributes():
    # Build a cert with TCG attributes
    # subject = x509.Name([])

    # Subject Directory Attributes
    # We will just inject it into the builder
    # TCG_OID_TPM_MANUFACTURER = "2.23.133.2.1"
    # Actually it's easier to mock x509.Certificate for this test
    mock_cert = MagicMock(spec=x509.Certificate)

    # Extension 1: Direct OID
    ext1 = MagicMock()
    ext1.oid.dotted_string = "2.23.133.2.1"
    ext1.value.value = b"NTC"

    # Extension 2: SAN with directoryName
    ext2 = MagicMock()
    ext2.oid.dotted_string = "2.5.29.17"
    dir_name = MagicMock(spec=x509.DirectoryName)
    attr = MagicMock()
    attr.oid.dotted_string = "2.23.133.2.2"
    attr.value = "NPCT75x"
    dir_name.value = [attr]
    ext2.value = [dir_name]

    mock_cert.extensions = [ext1, ext2]

    attrs = _parse_tcg_attributes(mock_cert)
    assert attrs["tpm_manufacturer"] == "NTC"
    assert attrs["tpm_model"] == "NPCT75x"


def test_parse_tcg_attributes_exceptions():
    mock_cert = MagicMock(spec=x509.Certificate)

    ext1 = MagicMock()
    ext1.oid.dotted_string = "2.23.133.2.1"
    type(ext1.value).value = property(lambda self: (_ for _ in ()).throw(Exception("Error")))

    ext2 = MagicMock()
    ext2.oid.dotted_string = "2.5.29.17"
    type(ext2).value = property(lambda self: (_ for _ in ()).throw(Exception("Error")))

    mock_cert.extensions = [ext1, ext2]
    attrs = _parse_tcg_attributes(mock_cert)
    assert attrs == {}


def test_parse_ek_details_success():
    good_pem = _generate_test_cert_pem()
    details = parse_ek_details(good_pem.decode("utf-8"))
    assert "serial" in details
    assert "issuer" in details
    assert "not_before" in details


@patch("OpenSSL.crypto.X509StoreContext.verify_certificate")
@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_aia_chasing_fetch_error(mock_urlopen, mock_run, mock_verify, tmp_path):
    roots_dir = tmp_path / "roots"
    roots_dir.mkdir()
    (roots_dir / "root.pem").write_bytes(_generate_test_cert_pem())
    intermediates_dir = tmp_path / "intermediates"
    intermediates_dir.mkdir()

    mock_verify.side_effect = X509StoreContextError("unable to get local issuer certificate", [], None)
    mock_run.return_value = MagicMock(returncode=0, stdout="CA Issuers - URI:http://test.com/cert.cer")

    mock_urlopen.side_effect = Exception("Network error")

    ek_pem = _generate_test_cert_pem().decode("utf-8")
    check = _verify_ek_chain_openssl(ek_pem, roots_dir, intermediates_dir)
    assert not check.passed
    assert "AIA fetch from http://test.com/cert.cer failed: Network error" in check.detail


def test_verify_ek_chain_openssl_bad_ek(tmp_path):
    check = _verify_ek_chain_openssl("BAD PEM", tmp_path, tmp_path)
    assert not check.passed
    assert "Could not parse EK certificate" in check.detail


def test_decode_manufacturer_id_errors():
    res1 = _decode_manufacturer_id("not an int")
    assert res1 == "not an int"

    # Int without matching ASCII or dict entry
    # 0x01020304
    res2 = _decode_manufacturer_id(0x01020304)
    assert res2 == "\x01\x02\x03\x04 (0x01020304)"


@patch("wif_bunker.attestation.base.verify_ek_chain")
def test_fix_asn1(mock_verify):
    pass
