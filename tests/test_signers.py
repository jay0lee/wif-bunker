"""Tests for wif_bunker.signers."""

from __future__ import annotations

import json
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from wif_bunker.oidc import build_jwks_from_signer
from wif_bunker.signers import load_signer


class TestSoftwareSigner:
    def test_loads_ec_pem_file(self, sample_software_pem_file):
        signer = load_signer({"type": "software", "key_file": str(sample_software_pem_file)})
        assert signer.algorithm == "ES256"
        assert signer.public_jwk["kty"] == "EC"
        sig = signer.sign(b"hello world")
        assert len(sig) == 64

    def test_loads_rsa_pem_file(self, tmp_path, sample_rsa_key):
        pem_path = tmp_path / "rsa.pem"
        pem_path.write_bytes(
            sample_rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        signer = load_signer({"type": "software", "key_file": str(pem_path), "key_id": "rsa-1"})
        assert signer.algorithm == "RS256"
        assert signer.key_id == "rsa-1"
        assert signer.public_jwk["kty"] == "RSA"

    def test_missing_key_file_param_raises(self):
        with pytest.raises(ValueError, match="requires 'key_file'"):
            load_signer({"type": "software"})

    def test_nonexistent_key_file_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Software private key file not found"):
            load_signer({"type": "software", "key_file": str(tmp_path / "nope.pem")})

    def test_unsupported_ed25519_key_raises(self, tmp_path):
        key = ed25519.Ed25519PrivateKey.generate()
        pem_path = tmp_path / "ed25519.pem"
        pem_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        with pytest.raises(ValueError, match="Unsupported private key type"):
            load_signer({"type": "software", "key_file": str(pem_path)})

    def test_p384_rejected_by_oidc_jwks_builder(self, tmp_path):
        key = ec.generate_private_key(ec.SECP384R1())
        pem_path = tmp_path / "p384.pem"
        pem_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        signer = load_signer({"type": "software", "key_file": str(pem_path)})
        assert signer.algorithm == "ES384"
        with pytest.raises(ValueError, match="ES256, RS256"):
            build_jwks_from_signer(signer)


class TestHardwareSignerDispatch:
    def test_unknown_signer_raises(self):
        with pytest.raises(ValueError, match="Unknown signer type"):
            load_signer({"type": "quantum-hsm"})

    def test_missing_type_raises(self):
        with pytest.raises(ValueError, match="must be a dict containing a 'type'"):
            load_signer({})

    def test_linux_tpm_dispatches_and_parses_hex_handle(self, monkeypatch):
        fake_mod = ModuleType("dpop_signer_linux_tpm")
        mock_cls = MagicMock()
        fake_mod.LinuxTPMDPoPSigner = mock_cls
        monkeypatch.setitem(sys.modules, "dpop_signer_linux_tpm", fake_mod)

        load_signer({"type": "linux-tpm", "handle": "0x81000001", "tcti": "swtpm:port=2321", "auth": "pw"})
        mock_cls.assert_called_once_with(handle=0x81000001, tcti="swtpm:port=2321", auth="pw", key_id=None)

    def test_linux_tpm_inherits_tpm2tools_tcti_env(self, monkeypatch):
        fake_mod = ModuleType("dpop_signer_linux_tpm")
        mock_cls = MagicMock()
        fake_mod.LinuxTPMDPoPSigner = mock_cls
        monkeypatch.setitem(sys.modules, "dpop_signer_linux_tpm", fake_mod)
        monkeypatch.setenv("TPM2TOOLS_TCTI", "tabrmd:bus_type=session")

        load_signer({"type": "linux-tpm", "handle": "0x81000001"})
        mock_cls.assert_called_once_with(handle=0x81000001, tcti="tabrmd:bus_type=session", auth=None, key_id=None)

    def test_windows_certstore_dispatches(self, monkeypatch):
        fake_mod = ModuleType("dpop_signer_windows_certstore")
        mock_cls = MagicMock()
        fake_mod.WindowsCertStoreDPoPSigner = mock_cls
        monkeypatch.setitem(sys.modules, "dpop_signer_windows_certstore", fake_mod)

        load_signer({"type": "windows-certstore", "subject": "WIF Bunker", "store_location": "local_machine"})
        mock_cls.assert_called_once_with(
            subject="WIF Bunker",
            thumbprint=None,
            key_id=None,
            store_location="local_machine",
        )

    def test_macos_secureenclave_dispatches(self, monkeypatch):
        fake_mod = ModuleType("dpop_signer_macos_secureenclave")
        mock_cls = MagicMock()
        fake_mod.SecureEnclaveDPoPSigner = mock_cls
        monkeypatch.setitem(sys.modules, "dpop_signer_macos_secureenclave", fake_mod)

        load_signer({"type": "macos-secureenclave", "label": "WIF Bunker Key"})
        mock_cls.assert_called_once_with(label="WIF Bunker Key")

    def test_yubikey_dispatches(self, monkeypatch):
        fake_mod = ModuleType("dpop_signer_yubikey")
        mock_cls = MagicMock()
        fake_mod.YubiKeyDPoPSigner = mock_cls
        monkeypatch.setitem(sys.modules, "dpop_signer_yubikey", fake_mod)

        load_signer({"type": "yubikey", "slot": "9c", "serial": 20602167, "pin": "123456"})
        mock_cls.assert_called_once_with(slot="9c", serial=20602167, pin="123456")

    def test_pkcs11_dispatches(self, monkeypatch):
        fake_mod = ModuleType("dpop_signer_pkcs11")
        mock_cls = MagicMock()
        fake_mod.PKCS11DPoPSigner = mock_cls
        monkeypatch.setitem(sys.modules, "dpop_signer_pkcs11", fake_mod)

        load_signer({"type": "pkcs11", "uri": "pkcs11:token=bunker;id=%02", "pin": "0000"})
        mock_cls.assert_called_once_with("pkcs11:token=bunker;id=%02", pin="0000")

    def test_fido2_dispatches(self, monkeypatch, tmp_path):
        fake_mod = ModuleType("dpop_signer_fido2_previewsign")
        mock_cls = MagicMock()
        fake_mod.Fido2PreviewSignDPoPSigner = mock_cls
        monkeypatch.setitem(sys.modules, "dpop_signer_fido2_previewsign", fake_mod)

        cred_file = tmp_path / "cred.json"
        cred_file.write_text(json.dumps({"credential_id": "abc123", "rp_id": "example.com"}), encoding="utf-8")

        load_signer({"type": "fido2-previewsign", "credential_file": str(cred_file), "pin": "1234"})
        mock_cls.from_dict.assert_called_once_with({"credential_id": "abc123", "rp_id": "example.com", "pin": "1234"})

    def test_missing_signer_package_raises_clear_error(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "dpop_signer_linux_tpm", None)
        with pytest.raises(RuntimeError, match="not installed"):
            load_signer({"type": "linux-tpm", "handle": "0x81000001"})
