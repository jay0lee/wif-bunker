"""Tests for the YubiKey modules."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wif_bunker.cli import _main_impl
from wif_bunker.config import CertificateBundle, WorkloadConfig


# Utility to generate test certificates
def generate_test_cert(common_name: str, extensions: list[tuple[str, bytes]] | None = None) -> cx509.Certificate:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    builder = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .public_key(public_key)
        .serial_number(cx509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
    )
    if extensions:
        for oid_str, val in extensions:
            builder = builder.add_extension(
                cx509.UnrecognizedExtension(cx509.ObjectIdentifier(oid_str), val),
                critical=False,
            )
    return builder.sign(private_key, hashes.SHA256())


@pytest.fixture
def config():
    cfg = MagicMock(spec=WorkloadConfig)
    cfg.workload_cn = "test-bunker"
    cfg.use_yubikey = True
    cfg.yubikey_serial = None
    cfg.key_algorithm = "es256"
    cfg.yubikey_slot = "9a"
    cfg.yubikey_touch_policy = "never"
    return cfg


class TestYubiKeyKeystore:
    @patch("ykman.device.list_all_devices", create=True)
    def test_no_yubikey_found(self, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        mock_list.return_value = iter([])
        with pytest.raises(RuntimeError, match="pcscd"):
            generate_cert_yubikey(config)

    @patch("ykman.device.list_all_devices", create=True)
    def test_multiple_yubikeys_no_serial(self, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev1, info1 = MagicMock(), MagicMock(serial=1111)
        dev2, info2 = MagicMock(), MagicMock(serial=2222)
        mock_list.return_value = iter([(dev1, info1), (dev2, info2)])
        config.yubikey_serial = None
        with pytest.raises(RuntimeError, match="--yubikey-serial"):
            generate_cert_yubikey(config)

    @patch("ykman.device.list_all_devices", create=True)
    @patch("wif_bunker.keystore.yubikey._yubikey_config_path")
    @patch("wif_bunker.keystore.yubikey._create_ca_and_sign")
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    def test_multiple_yubikeys_with_serial(self, mock_piv, mock_conn, mock_ca, mock_path, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev1, info1 = MagicMock(), MagicMock(serial=1111, version=(5, 4, 3))
        dev2, info2 = MagicMock(), MagicMock(serial=2222, version=(5, 4, 3))
        mock_list.return_value = iter([(dev1, info1), (dev2, info2)])
        config.yubikey_serial = 2222

        mock_ca.return_value = (
            MagicMock(),
            generate_test_cert("test").public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        )

        generate_cert_yubikey(config)
        dev2.open_connection.assert_called_once()
        dev1.open_connection.assert_not_called()

    @patch("ykman.device.list_all_devices", create=True)
    def test_firmware_too_old(self, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(4, 2, 0))
        mock_list.return_value = iter([(dev, info)])
        with pytest.raises(RuntimeError, match="4\\.3\\.0"):
            generate_cert_yubikey(config)

    @patch("ykman.device.list_all_devices", create=True)
    def test_unsupported_algorithm(self, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = iter([(dev, info)])
        config.key_algorithm = "rsa3072"
        with pytest.raises(RuntimeError, match="not supported"):
            generate_cert_yubikey(config)

    @patch("ykman.device.list_all_devices", create=True)
    def test_rsa4096_old_firmware(self, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 6, 0))
        mock_list.return_value = iter([(dev, info)])
        config.key_algorithm = "rsa4096"
        with pytest.raises(RuntimeError, match="5\\.7\\+"):
            generate_cert_yubikey(config)

    @patch("ykman.device.list_all_devices", create=True)
    @patch("wif_bunker.keystore.yubikey._yubikey_config_path")
    @patch("wif_bunker.keystore.yubikey._create_ca_and_sign")
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    def test_security_init_randomizes_defaults(
        self, mock_piv_class, mock_conn, mock_ca, mock_path, mock_list, config, tmp_path
    ):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = iter([(dev, info)])

        cfg_path = tmp_path / "yubikey_1234.json"
        mock_path.return_value = cfg_path

        piv_inst = mock_piv_class.return_value
        piv_inst.authenticate.return_value = None

        mock_ca.return_value = (
            MagicMock(),
            generate_test_cert("test").public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        )

        generate_cert_yubikey(config)

        piv_inst.change_pin.assert_called_once()
        piv_inst.change_puk.assert_called_once()
        piv_inst.set_management_key.assert_called_once()

        assert cfg_path.exists()
        cfg_data = json.loads(cfg_path.read_text())
        assert "pin" in cfg_data
        assert "puk" in cfg_data
        assert "management_key" in cfg_data

    @patch("ykman.device.list_all_devices", create=True)
    @patch("wif_bunker.keystore.yubikey._yubikey_config_path")
    @patch("wif_bunker.keystore.yubikey._create_ca_and_sign")
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    def test_existing_config_loaded(self, mock_piv_class, mock_conn, mock_ca, mock_path, mock_list, config, tmp_path):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = iter([(dev, info)])

        cfg_path = tmp_path / "yubikey_1234.json"
        cfg_path.write_text(json.dumps({"pin": "mypin", "puk": "mypuk", "management_key": "00112233" * 6}))
        mock_path.return_value = cfg_path

        piv_inst = mock_piv_class.return_value

        def auth_side_effect(key):
            from yubikit.piv import DEFAULT_MANAGEMENT_KEY

            if key == DEFAULT_MANAGEMENT_KEY:
                raise Exception("Not default")
            return None

        piv_inst.authenticate.side_effect = auth_side_effect

        mock_ca.return_value = (
            MagicMock(),
            generate_test_cert("test").public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        )

        generate_cert_yubikey(config)

        piv_inst.verify_pin.assert_called_with("mypin")
        piv_inst.authenticate.assert_any_call(bytes.fromhex("00112233" * 6))

    @patch("ykman.device.list_all_devices", create=True)
    @patch("wif_bunker.keystore.yubikey._yubikey_config_path")
    @patch("wif_bunker.keystore.yubikey._create_ca_and_sign")
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    def test_generates_key_and_imports_cert(
        self, mock_piv_class, mock_conn, mock_ca, mock_path, mock_list, config, tmp_path
    ):
        from yubikit.piv import KEY_TYPE, PIN_POLICY, SLOT, TOUCH_POLICY

        from wif_bunker.keystore.yubikey import generate_cert_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = iter([(dev, info)])

        cfg_path = tmp_path / "yubikey_1234.json"
        cfg_path.write_text(json.dumps({"pin": "mypin", "puk": "mypuk", "management_key": "00112233" * 6}))
        mock_path.return_value = cfg_path

        piv_inst = mock_piv_class.return_value

        def auth_side_effect(key):
            from yubikit.piv import DEFAULT_MANAGEMENT_KEY

            if key == DEFAULT_MANAGEMENT_KEY:
                raise Exception("Not default")
            return None

        piv_inst.authenticate.side_effect = auth_side_effect

        mock_pubkey = MagicMock()
        mock_pubkey.public_bytes.return_value = b"mock_pubkey_pem"
        piv_inst.generate_key.return_value = mock_pubkey

        mock_bundle = CertificateBundle("ca", "leaf", "issuer", "01", "sha")
        mock_cert_pem = generate_test_cert("test").public_bytes(serialization.Encoding.PEM).decode("utf-8")
        mock_ca.return_value = (mock_bundle, mock_cert_pem)

        res = generate_cert_yubikey(config)

        piv_inst.generate_key.assert_called_once_with(
            SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, pin_policy=PIN_POLICY.ONCE, touch_policy=TOUCH_POLICY.NEVER
        )
        piv_inst.put_certificate.assert_called_once()
        assert piv_inst.put_certificate.call_args[0][0] == SLOT.AUTHENTICATION
        assert res == mock_bundle


class TestYubiKeyAttestation:
    @patch("ykman.device.list_all_devices", create=True)
    def test_no_yubikey_returns_report(self, mock_list, config):
        from wif_bunker.attestation.yubikey import attest_yubikey

        mock_list.return_value = []
        report = attest_yubikey(config)
        assert report.supported is True
        assert report.platform == "yubikey"
        assert "pcscd" in report.checks[0].detail

    @patch("ykman.device.list_all_devices", create=True)
    def test_firmware_too_old_report(self, mock_list, config):
        from wif_bunker.attestation.yubikey import attest_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(4, 2, 0))
        mock_list.return_value = [(dev, info)]
        report = attest_yubikey(config)
        assert any(not c.passed and "requires >= 4.3.0" in c.detail for c in report.checks)

    @patch("ykman.device.list_all_devices", create=True)
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    def test_attest_key_fails_imported(self, mock_piv_class, mock_conn, mock_list, config):
        from wif_bunker.attestation.yubikey import attest_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = [(dev, info)]
        piv_inst = mock_piv_class.return_value
        piv_inst.attest_key.side_effect = Exception("Not generated on device")

        report = attest_yubikey(config)
        assert "imported" in report.summary

    @patch("ykman.device.list_all_devices", create=True)
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    @patch("wif_bunker.attestation.yubikey._verify_yubico_chain")
    def test_full_attestation_happy_path(self, mock_verify, mock_piv_class, mock_conn, mock_list, config):
        from wif_bunker.attestation.base import AttestationCheck
        from wif_bunker.attestation.yubikey import attest_yubikey

        dev, info = MagicMock(), MagicMock(serial=12345678, version=(5, 4, 3))
        mock_list.return_value = [(dev, info)]

        piv_inst = mock_piv_class.return_value
        piv_inst.attest_key.return_value = generate_test_cert("attest")
        piv_inst.get_certificate.return_value = generate_test_cert("f9")

        mock_verify.return_value = AttestationCheck("Attestation chain verified", passed=True, detail="ok")

        report = attest_yubikey(config)

        assert len(report.checks) == 5
        assert all(c.passed for c in report.checks)
        assert "Cryptographically proven" in report.summary

    @patch("ykman.device.list_all_devices", create=True)
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    @patch("wif_bunker.attestation.yubikey._verify_yubico_chain")
    def test_chain_verification_fails(self, mock_verify, mock_piv_class, mock_conn, mock_list, config):
        from wif_bunker.attestation.base import AttestationCheck
        from wif_bunker.attestation.yubikey import attest_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = [(dev, info)]

        piv_inst = mock_piv_class.return_value
        piv_inst.attest_key.return_value = generate_test_cert("attest")
        piv_inst.get_certificate.return_value = generate_test_cert("f9")

        mock_verify.return_value = AttestationCheck("Attestation chain verified", passed=False, detail="fail")

        report = attest_yubikey(config)
        assert "could not be verified" in report.summary

    @patch("ykman.device.list_all_devices", create=True)
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    @patch("wif_bunker.attestation.yubikey._verify_yubico_chain")
    def test_attested_properties_parsed(self, mock_verify, mock_piv_class, mock_conn, mock_list, config):
        """All Yubico attestation cert extensions are extracted into one check."""
        from wif_bunker.attestation.yubikey import attest_yubikey

        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = [(dev, info)]

        piv_inst = mock_piv_class.return_value

        mock_attest_cert = generate_test_cert(
            "attest",
            extensions=[
                ("1.3.6.1.4.1.41482.3.3", bytes([5, 4, 3])),  # Firmware 5.4.3
                ("1.3.6.1.4.1.41482.3.7", bytes([0x02, 0x02, 0x04, 0xD2])),  # Serial 1234 (DER INTEGER)
                ("1.3.6.1.4.1.41482.3.9", bytes([0x03])),  # USB-C Keychain
                ("1.3.6.1.4.1.41482.3.8", bytes([0x02, 0x01])),  # PIN=Once, Touch=Never
            ],
        )
        piv_inst.attest_key.return_value = mock_attest_cert
        piv_inst.get_certificate.return_value = generate_test_cert("f9")

        report = attest_yubikey(config)
        props_check = next(c for c in report.checks if c.name == "Attested device properties")
        assert props_check.passed
        assert "Firmware: 5.4.3" in props_check.detail
        assert "Serial: 1234" in props_check.detail
        assert "USB-C Keychain" in props_check.detail
        assert "PIN policy: Once" in props_check.detail
        assert "Touch policy: Never" in props_check.detail


class TestYubiKeyCLI:
    @patch("wif_bunker.cli._run_cert_only")
    def test_use_yubikey_sets_config(self, mock_run, tmp_path):
        with patch("sys.argv", ["wif-bunker", "--use-yubikey", "--cert-only", "--output-dir", str(tmp_path)]):
            _main_impl()
        config = mock_run.call_args[0][0]
        assert config.use_yubikey is True

    @patch("sys.argv", ["wif-bunker", "--yubikey-serial", "1234", "--cert-only"])
    def test_yubikey_serial_requires_use_yubikey(self, capsys):
        with pytest.raises(SystemExit):
            _main_impl()
        captured = capsys.readouterr()
        assert "--yubikey-serial" in captured.err

    @patch("sys.platform", "win32")
    @patch("wif_bunker.cli.preflight_check_openssl_shared")
    def test_soft_key_and_yubikey_exclusive(self, _mock_preflight, capsys):
        with patch("sys.argv", ["wif-bunker", "--soft-key", "--use-yubikey", "--cert-only"]), pytest.raises(SystemExit):
            _main_impl()
        captured = capsys.readouterr()
        assert "exclusive" in captured.err


class TestRealYubiKeyCerts:
    """Tests using real YubiKey attestation certificates from production devices.

    These certs were extracted from 4 different YubiKeys:
      - 20602167: YubiKey 5 NFC, firmware 5.4.3, USB-A Keychain
      - 15770189: YubiKey 5C, firmware 5.2.7, USB-C Keychain
      - 35270891: YubiKey 5C, firmware 5.7.4, USB-C Keychain
      - 15614260: YubiKey 5Ci, firmware 5.2.7, USB-C/Lightning
    """

    FIXTURES = Path(__file__).parent / "fixtures" / "yubikey"

    # Expected properties extracted from each real attestation cert
    DEVICES: ClassVar[list[dict]] = [
        {
            "serial": 20602167,
            "firmware": "5.4.3",
            "form_factor": "USB-A Keychain",
            "pin_policy": "Once",
            "touch_policy": "Never",
        },
        {
            "serial": 15770189,
            "firmware": "5.2.7",
            "form_factor": "USB-C Keychain",
            "pin_policy": "Once",
            "touch_policy": "Never",
        },
        {
            "serial": 35270891,
            "firmware": "5.7.4",
            "form_factor": "USB-C Keychain",
            "pin_policy": "Never",
            "touch_policy": "Never",
        },
        {
            "serial": 15614260,
            "firmware": "5.2.7",
            "form_factor": "USB-C/Lightning",
            "pin_policy": "Once",
            "touch_policy": "Never",
        },
    ]

    @pytest.fixture(params=[d["serial"] for d in DEVICES], ids=[str(d["serial"]) for d in DEVICES])
    def device(self, request):
        serial = request.param
        props = next(d for d in self.DEVICES if d["serial"] == serial)
        attest_pem = (self.FIXTURES / f"yk_{serial}_attest.pem").read_bytes()
        f9_pem = (self.FIXTURES / f"yk_{serial}_f9.pem").read_bytes()
        return {**props, "attest_pem": attest_pem, "f9_pem": f9_pem}

    def test_attested_properties_from_real_cert(self, device):
        """Parse real attestation cert extensions and verify all proven properties."""
        from wif_bunker.attestation.yubikey import _parse_attested_properties

        cert = cx509.load_pem_x509_certificate(device["attest_pem"])
        props = _parse_attested_properties(cert)

        assert f"Firmware: {device['firmware']}" in props
        assert f"Serial: {device['serial']}" in props
        assert device["form_factor"] in props
        assert f"PIN policy: {device['pin_policy']}" in props
        assert f"Touch policy: {device['touch_policy']}" in props

    def test_chain_verification_against_bundled_roots(self, device):
        """Verify real attestation cert chains to Yubico's bundled root CA."""
        from wif_bunker.attestation.yubikey import _verify_yubico_chain

        attest_cert = cx509.load_pem_x509_certificate(device["attest_pem"])
        f9_cert = cx509.load_pem_x509_certificate(device["f9_pem"])

        result = _verify_yubico_chain(attest_cert, f9_cert)
        assert result.passed, f"Chain verification failed for S/N {device['serial']}: {result.detail}"
        assert "Yubico Root CA" in result.detail
