"""Tests for Linux TPM attestation via tpm2-pytss ESAPI."""

import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

# Mock tpm2_pytss if not available (macOS/Windows dev environments)
if "tpm2_pytss" not in sys.modules:
    _mock_tpm2_pytss = ModuleType("tpm2_pytss")
    _mock_tpm2_pytss.ESAPI = MagicMock
    _mock_tpm2_pytss.ESYS_TR = MagicMock()
    _mock_tpm2_pytss.TPM2_ALG = MagicMock()
    _mock_tpm2_pytss.TPM2_CAP = MagicMock()
    _mock_tpm2_pytss.TPM2_PT = MagicMock()
    _mock_tpm2_pytss.TPM2_PT.MANUFACTURER = 0x105
    _mock_tpm2_pytss.TPM2_PT.FIRMWARE_VERSION_1 = 0x111
    _mock_tpm2_pytss.TPM2_PT.FAMILY_INDICATOR = 0x100
    _mock_tpm2_pytss.TPM2_SE = MagicMock()
    _mock_tpm2_pytss.TPM2B_DIGEST = MagicMock
    _mock_tpm2_pytss.TPM2B_NONCE = MagicMock
    _mock_tpm2_pytss.TPM2B_PUBLIC = MagicMock()
    _mock_tpm2_pytss.TPM2B_SENSITIVE_CREATE = MagicMock
    _mock_tpm2_pytss.TPM2_RC = MagicMock()
    _mock_tpm2_pytss.TPMT_SYM_DEF = MagicMock
    sys.modules["tpm2_pytss"] = _mock_tpm2_pytss

    _mock_types = ModuleType("tpm2_pytss.types")
    _mock_types.TPMT_SIG_SCHEME = MagicMock()
    _mock_types.TPM2B_PUBLIC = MagicMock()
    sys.modules["tpm2_pytss.types"] = _mock_types

    _mock_utils = ModuleType("tpm2_pytss.utils")
    _mock_utils.make_credential = MagicMock()
    sys.modules["tpm2_pytss.utils"] = _mock_utils

    _mock_internal = ModuleType("tpm2_pytss.internal")
    sys.modules["tpm2_pytss.internal"] = _mock_internal

    _mock_crypto = ModuleType("tpm2_pytss.internal.crypto")
    _mock_crypto._public_to_pem = MagicMock()
    sys.modules["tpm2_pytss.internal.crypto"] = _mock_crypto

from wif_bunker.attestation.linux import (
    _certify_key,
    _extract_ek_certificate,
    _get_tpm_info,
)


class TestLinuxEkExtraction:
    @patch("wif_bunker.attestation.linux._extract_ek_certificate_cli_fallback", return_value=(None, None))
    @patch("wif_bunker.attestation.linux._extract_ek_certificate_esapi", return_value=(None, None))
    def test_no_ek_certificate(self, mock_esapi, mock_cli):
        """Neither ESAPI nor CLI finds an EK cert -> failure check."""
        work_dir = Path("/tmp")
        mock_ectx = MagicMock()
        check, pem = _extract_ek_certificate(work_dir, mock_ectx)
        assert check.passed is False
        assert pem is None
        assert "No EK certificate" in check.detail


class TestLinuxTpmInfo:
    def test_get_tpm_info_failure(self):
        """get_capability raises -> returns None."""
        mock_ectx = MagicMock()
        mock_ectx.get_capability.side_effect = RuntimeError("no TPM")
        result = _get_tpm_info(mock_ectx)
        assert result is None

    def test_get_tpm_info_success(self):
        """get_capability succeeds -> parses Manufacturer and FW version."""
        mock_ectx = MagicMock()
        mock_prop = MagicMock()
        mock_prop.property = 0x105  # _PT_MANUFACTURER
        mock_prop.value = int.from_bytes(b"INTC", "big")

        mock_prop2 = MagicMock()
        mock_prop2.property = 0x111  # _PT_FIRMWARE_VERSION_1
        mock_prop2.value = 0x00010002

        mock_prop3 = MagicMock()
        mock_prop3.property = 0x100  # _PT_FAMILY_INDICATOR
        mock_prop3.value = int.from_bytes(b"2.0\x00", "big")

        mock_props = MagicMock()
        mock_props.data.tpmProperties = [mock_prop, mock_prop2, mock_prop3]
        mock_ectx.get_capability.return_value = (None, mock_props)

        result = _get_tpm_info(mock_ectx)
        assert result is not None
        assert result["manufacturer"] == "INTC"
        assert result["firmware"] == "1.2"
        assert result["family"] == "2.0"


class TestExtractEkCertificateEsapi:
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.dump_certificate")
    def test_success(self, mock_dump, mock_load):
        mock_dump.return_value = b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
        mock_load.return_value.get_issuer.return_value.get_components.return_value = [(b"CN", b"MOCK_CA")]

        mock_ectx = MagicMock()
        mock_ectx.tr_from_tpmpublic.return_value = 123
        mock_pub = MagicMock()
        mock_pub.nvPublic.dataSize = 100
        mock_ectx.nv_read_public.return_value = (mock_pub, None)
        mock_ectx.nv_read.return_value = b"mock der data"

        from wif_bunker.attestation.linux import _extract_ek_certificate_esapi

        check, pem = _extract_ek_certificate_esapi(mock_ectx)

        assert check.passed is True
        assert "MOCK_CA" in check.detail
        assert pem == "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"

    def test_failure(self):
        mock_ectx = MagicMock()
        mock_ectx.tr_from_tpmpublic.side_effect = Exception("failed")

        from wif_bunker.attestation.linux import _extract_ek_certificate_esapi

        check, pem = _extract_ek_certificate_esapi(mock_ectx)
        assert check is None
        assert pem is None


class TestCertifyKey:
    def test_certifies_persistent_handle_without_flushing(self):
        mock_ectx = MagicMock()
        mock_ectx.tr_from_tpmpublic.return_value = "PERSISTENT_TR"
        mock_ectx.certify.return_value = (b"attest-blob", b"sig-blob")

        check, ok, attest_bytes, sig_bytes = _certify_key(mock_ectx, "AK_HANDLE", tpm_handle=0x81000001)

        assert ok is True
        assert check.passed is True
        assert "0x81000001" in check.detail
        assert attest_bytes == b"attest-blob"
        assert sig_bytes == b"sig-blob"
        mock_ectx.tr_from_tpmpublic.assert_called_once_with(0x81000001)
        mock_ectx.create_primary.assert_not_called()
        mock_ectx.flush_context.assert_not_called()

    def test_certifies_ephemeral_primary_when_no_handle_and_flushes(self):
        mock_ectx = MagicMock()
        mock_ectx.create_primary.return_value = ("TMP_PRIMARY", None, None, None, None)
        mock_ectx.certify.return_value = (b"attest-blob", b"sig-blob")

        check, ok, attest_bytes, sig_bytes = _certify_key(mock_ectx, "AK_HANDLE", tpm_handle=None)

        assert ok is True
        assert check.passed is True
        assert attest_bytes == b"attest-blob"
        assert sig_bytes == b"sig-blob"
        mock_ectx.create_primary.assert_called_once()
        mock_ectx.flush_context.assert_called_once_with("TMP_PRIMARY")

    def test_certify_error_returns_failed_check(self):
        mock_ectx = MagicMock()
        mock_ectx.tr_from_tpmpublic.side_effect = RuntimeError("TPM_RC_HANDLE")

        check, ok, attest_bytes, sig_bytes = _certify_key(mock_ectx, "AK_HANDLE", tpm_handle=0x81000099)

        assert ok is False
        assert check.passed is False
        assert "TPM_RC_HANDLE" in check.detail
        assert attest_bytes is None
        assert sig_bytes is None
