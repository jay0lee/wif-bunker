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
    _mock_tpm2_pytss.TPM2_CAP = MagicMock()
    _mock_tpm2_pytss.TPM2_PT = MagicMock()
    _mock_tpm2_pytss.TPM2_SE = MagicMock()
    _mock_tpm2_pytss.TPM2B_DIGEST = MagicMock
    _mock_tpm2_pytss.TPM2B_NONCE = MagicMock
    _mock_tpm2_pytss.TPM2B_PUBLIC = MagicMock()
    _mock_tpm2_pytss.TPM2B_SENSITIVE_CREATE = MagicMock
    _mock_tpm2_pytss.TPM2_RC = MagicMock()
    _mock_tpm2_pytss.TPMT_SYM_DEF = MagicMock
    sys.modules["tpm2_pytss"] = _mock_tpm2_pytss

    # Mock sub-modules
    _mock_utils = ModuleType("tpm2_pytss.utils")
    _mock_utils.make_credential = MagicMock()
    sys.modules["tpm2_pytss.utils"] = _mock_utils

    _mock_internal = ModuleType("tpm2_pytss.internal")
    sys.modules["tpm2_pytss.internal"] = _mock_internal

    _mock_crypto = ModuleType("tpm2_pytss.internal.crypto")
    _mock_crypto.public_to_crypto_key = MagicMock()
    sys.modules["tpm2_pytss.internal.crypto"] = _mock_crypto

from wif_bunker.attestation.linux import (
    _extract_ek_certificate,
    _extract_workload_key_from_pkcs11,
    _get_tpm_info,
)


class TestLinuxEkExtraction:
    @patch("wif_bunker.attestation.linux._extract_ek_certificate_cli_fallback", return_value=(None, None))
    @patch("wif_bunker.attestation.linux._extract_ek_certificate_esapi", return_value=(None, None))
    def test_no_ek_certificate(self, mock_esapi, mock_cli):
        """Neither ESAPI nor CLI finds an EK cert → failure check."""
        work_dir = Path("/tmp")
        mock_ectx = MagicMock()
        check, pem = _extract_ek_certificate(work_dir, mock_ectx)
        assert check.passed is False
        assert pem is None
        assert "No EK certificate" in check.detail


class TestLinuxTpmInfo:
    def test_get_tpm_info_failure(self):
        """get_capability raises → returns None."""
        mock_ectx = MagicMock()
        mock_ectx.get_capability.side_effect = RuntimeError("no TPM")
        result = _get_tpm_info(mock_ectx)
        assert result is None


class TestPkcs11StoreQuery:
    @patch("wif_bunker.keystore.linux._find_pkcs11_lib")
    @patch("pkcs11.lib")
    def test_token_found(self, mock_pkcs11_lib, mock_find_lib):
        """bunker-wif token found → success check."""
        mock_find_lib.return_value = "/usr/lib/pkcs11/libtpm2_pkcs11.so"
        mock_lib = MagicMock()
        mock_pkcs11_lib.return_value = mock_lib

        mock_token = MagicMock()
        mock_lib.get_token.return_value = mock_token

        mock_session = MagicMock()
        mock_session.get_objects.return_value = [MagicMock(), MagicMock()]
        mock_token.open.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_token.open.return_value.__exit__ = MagicMock(return_value=False)

        check, info = _extract_workload_key_from_pkcs11()
        assert check.passed is True
        assert info["token_label"] == "bunker-wif"
        assert info["object_count"] == 2

    @patch("wif_bunker.keystore.linux._find_pkcs11_lib")
    @patch("pkcs11.lib")
    def test_no_token(self, mock_pkcs11_lib, mock_find_lib):
        """No bunker-wif token → failure check."""
        import pkcs11 as pkcs11_mod

        mock_find_lib.return_value = "/usr/lib/pkcs11/libtpm2_pkcs11.so"
        mock_lib = MagicMock()
        mock_pkcs11_lib.return_value = mock_lib

        mock_lib.get_token.side_effect = pkcs11_mod.NoSuchToken()

        check, info = _extract_workload_key_from_pkcs11()
        assert check.passed is False
        assert info is None

    @patch("wif_bunker.keystore.linux._find_pkcs11_lib", side_effect=RuntimeError("no .so"))
    def test_no_pkcs11_lib(self, mock_find_lib):
        """PKCS#11 library not found → failure check."""
        check, info = _extract_workload_key_from_pkcs11()
        assert check.passed is False
        assert info is None
