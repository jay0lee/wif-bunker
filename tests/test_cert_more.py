import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from wif_bunker.cert import (
    _add_lib_to_path,
    _create_ca_and_sign,
    _find_hardmtls_library,
    build_adc_config,
    build_certificate_config,
    run_hardmtls_diagnostics,
    verify_cert_retrieval,
)
from wif_bunker.config import CertificateBundle


def test_create_ca_and_sign_with_public_key(sample_config):
    # generate a raw public key
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    bundle, workload_pem = _create_ca_and_sign(pub_pem, sample_config)
    assert bundle is not None
    assert "BEGIN CERTIFICATE" in workload_pem


def test_create_ca_and_sign_with_certificate(sample_config):
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    _bundle, workload_pem = _create_ca_and_sign(pub_pem, sample_config)

    # now pass the cert
    bundle2, _workload_pem2 = _create_ca_and_sign(workload_pem, sample_config)
    assert bundle2 is not None


def test_find_hardmtls_library_frozen(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "executable"))

    # create the fake hardmtls library
    target_dir = tmp_path / "bin" / "hardmtls"
    target_dir.mkdir(parents=True)
    lib_name = (
        "hardmtls.dll"
        if sys.platform == "win32"
        else ("libhardmtls.dylib" if sys.platform == "darwin" else "libhardmtls.so")
    )
    (target_dir / lib_name).touch()

    with patch("wif_bunker.cert._get_hardmtls_lib_name", return_value=lib_name):
        lib = _find_hardmtls_library()
        assert lib.name == lib_name


def test_find_hardmtls_library_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    with patch("wif_bunker.cert.Path.exists", return_value=False), pytest.raises(FileNotFoundError):
        _find_hardmtls_library()


def test_add_lib_to_path_win32(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    with patch("os.add_dll_directory", create=True) as mock_add_dll:
        mock_path = MagicMock()
        mock_path.is_dir.return_value = True
        mock_path.__str__.return_value = "fake_path"
        _add_lib_to_path(mock_path)
        mock_add_dll.assert_called_with("fake_path")


@patch("wif_bunker.cert.write_secure_file")
def test_build_certificate_config_yubikey(mock_write, sample_config):
    sample_config.use_yubikey = True
    bundle = CertificateBundle("ta", "wl", "issuer", "serial", "sha")
    with patch("sys.platform", "win32"):
        cfg, cfg_path, wl_path, tc_path = build_certificate_config(sample_config, bundle, Path("fake_lib"))
        assert "windows_store" in cfg["cert_configs"]

    with patch("sys.platform", "linux"):
        with patch("wif_bunker.keystore.yubikey.build_ecp_pkcs11_config", return_value={"pkcs11": {}}):
            cfg, _cfg_path, _wl_path, _tc_path = build_certificate_config(sample_config, bundle, Path("fake_lib"))
            assert "pkcs11" in cfg["cert_configs"]


@patch("wif_bunker.cert.write_secure_file")
@patch("subprocess.run")
def test_build_certificate_config_linux_pkcs11(mock_run, mock_write, sample_config):
    sample_config.use_yubikey = False
    bundle = CertificateBundle("ta", "wl", "issuer", "serial", "sha")

    mock_run.return_value = MagicMock(stdout="Slot 0 (0x123): bunker-wif\n")

    with patch("sys.platform", "linux"), patch("wif_bunker.cert.Path.exists", return_value=True):
        cfg, _cfg_path, _wl_path, _tc_path = build_certificate_config(sample_config, bundle, Path("fake_lib"))
        assert "pkcs11" in cfg["cert_configs"]
        assert cfg["cert_configs"]["pkcs11"]["slot"] == "123"


@patch("wif_bunker.cert.write_secure_file")
@patch("subprocess.run")
def test_build_certificate_config_linux_pkcs11_fallback_slot(mock_run, mock_write, sample_config):
    sample_config.use_yubikey = False
    bundle = CertificateBundle("ta", "wl", "issuer", "serial", "sha")

    mock_run.return_value = MagicMock(stdout="Slot 0 (0x123): other\n")

    with patch("sys.platform", "linux"), patch("wif_bunker.cert.Path.exists", return_value=True):
        cfg, _cfg_path, _wl_path, _tc_path = build_certificate_config(sample_config, bundle, Path("fake_lib"))
        assert cfg["cert_configs"]["pkcs11"]["slot"] == "1"


@patch("wif_bunker.cert.write_secure_file")
def test_build_adc_config(mock_write, sample_config):
    cfg, _cfg_path = build_adc_config(sample_config, "123", Path("cert_cfg"), Path("tc_cfg"), "sa@e.com", True)
    assert cfg["type"] == "external_account"
    assert "service_account_impersonation_url" in cfg


@patch("wif_bunker.cert.write_secure_file")
def test_build_adc_config_no_sa(mock_write, sample_config):
    cfg, _cfg_path = build_adc_config(sample_config, "123", Path("cert_cfg"), Path("tc_cfg"), None, False)
    assert "service_account_impersonation_url" not in cfg


def test_run_hardmtls_diagnostics(tmp_path):
    log = MagicMock()

    cfg_file = tmp_path / "cert_config.json"
    cfg_file.write_text('{"libs": {"ecp_client": "nonexistent"}}')
    run_hardmtls_diagnostics(cfg_file, log)

    run_hardmtls_diagnostics("nonexistent", log)


@patch("wif_bunker.cert.hardmtls_get_cert_pem")
def test_verify_cert_retrieval(mock_get_pem, sample_config):
    mock_get_pem.return_value = b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"
    res = verify_cert_retrieval("cfg", "lib", False)
    assert res == "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"


@patch("wif_bunker.cert.hardmtls_get_cert_pem")
def test_verify_cert_retrieval_fail(mock_get_pem):
    mock_get_pem.side_effect = RuntimeError("err")
    with pytest.raises(RuntimeError):
        verify_cert_retrieval("cfg", "lib", True)
