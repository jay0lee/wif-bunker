"""Tests for YubiKey PIV hardware attestation."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wif_bunker.config import WorkloadConfig


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
    cfg = WorkloadConfig()
    cfg.workload_cn = "test-bunker"
    cfg.use_yubikey = True
    cfg.yubikey_serial = None
    cfg.yubikey_slot = "9c"
    return cfg


class TestYubiKeyAttestation:
    @patch("ykman.device.list_all_devices", create=True)
    def test_no_yubikey_returns_report(self, mock_list, config):
        from wif_bunker.attestation.yubikey import attest_yubikey

        mock_list.return_value = []
        report = attest_yubikey(config)
        assert report.supported is True
        assert report.platform == "yubikey"
        assert "No YubiKey detected" in report.checks[0].detail

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
                ("1.3.6.1.4.1.41482.3.3", bytes([5, 4, 3])),
                ("1.3.6.1.4.1.41482.3.7", bytes([0x02, 0x02, 0x04, 0xD2])),
                ("1.3.6.1.4.1.41482.3.9", bytes([0x03])),
                ("1.3.6.1.4.1.41482.3.8", bytes([0x02, 0x01])),
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


class TestRealYubiKeyCerts:
    """Tests using real YubiKey attestation certificates from production devices."""

    FIXTURES = Path(__file__).parent / "fixtures" / "yubikey"

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
        from wif_bunker.attestation.yubikey import _parse_attested_properties

        cert = cx509.load_pem_x509_certificate(device["attest_pem"])
        props = _parse_attested_properties(cert)

        assert f"Firmware: {device['firmware']}" in props
        assert f"Serial: {device['serial']}" in props
        assert device["form_factor"] in props
        assert f"PIN policy: {device['pin_policy']}" in props
        assert f"Touch policy: {device['touch_policy']}" in props

    def test_chain_verification_against_bundled_roots(self, device):
        from wif_bunker.attestation.yubikey import _verify_yubico_chain

        attest_cert = cx509.load_pem_x509_certificate(device["attest_pem"])
        f9_cert = cx509.load_pem_x509_certificate(device["f9_pem"])

        result = _verify_yubico_chain(attest_cert, f9_cert)
        assert result.passed, f"Chain verification failed for S/N {device['serial']}: {result.detail}"
        assert "Yubico Root CA" in result.detail
