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


class TestLinuxAttestOrchestrationAndCliFallback:
    def test_get_esapi_passes_env_tcti(self, monkeypatch):
        from wif_bunker.attestation.linux import _get_esapi

        mock_esapi = MagicMock(return_value="ctx")
        monkeypatch.setattr(sys.modules["tpm2_pytss"], "ESAPI", mock_esapi)
        monkeypatch.setenv("TPM2TOOLS_TCTI", "tabrmd:bus_type=session")
        assert _get_esapi() == "ctx"
        mock_esapi.assert_called_once_with(tcti="tabrmd:bus_type=session")

    def test_cli_fallback_success_pem_and_der(self, tmp_path):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID

        from wif_bunker.attestation.linux import _extract_ek_certificate_cli_fallback

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intel EK")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5))
            .sign(key, hashes.SHA256())
        )

        for fmt_bytes in (cert.public_bytes(Encoding.PEM), cert.public_bytes(Encoding.DER)):
            ek_out = tmp_path / "ek_cert_fetched.pem"
            ek_out.write_bytes(fmt_bytes)
            ok_proc = MagicMock(returncode=0, stdout="", stderr="")
            with (
                patch("shutil.which", return_value="/usr/bin/tool"),
                patch("subprocess.run", return_value=ok_proc),
            ):
                check, pem = _extract_ek_certificate_cli_fallback(tmp_path, MagicMock())
            assert check is not None and check.passed is True
            assert "BEGIN CERTIFICATE" in pem

    def test_cli_fallback_missing_tools_or_errors(self, tmp_path):
        from wif_bunker.attestation.linux import _extract_ek_certificate_cli_fallback

        with patch("shutil.which", return_value=None):
            assert _extract_ek_certificate_cli_fallback(tmp_path, MagicMock()) == (None, None)

        fail_proc = MagicMock(returncode=1, stdout="", stderr="err")
        with patch("shutil.which", return_value="/usr/bin/tool"), patch("subprocess.run", return_value=fail_proc):
            assert _extract_ek_certificate_cli_fallback(tmp_path, MagicMock()) == (None, None)

    def test_attest_linux_all_verdict_paths(self):
        from wif_bunker.attestation.base import AttestationCheck
        from wif_bunker.attestation.linux import _attest_linux
        from wif_bunker.config import WorkloadConfig

        cfg = WorkloadConfig()
        cfg.linux_tpm_handle = 0x81000001
        mock_ctx = MagicMock()
        mock_ctx.__enter__.return_value = mock_ctx
        mock_ctx.__exit__.return_value = False

        # 1. Full hardware success (EK + chain + AK + cred + certify)
        with (
            patch("wif_bunker.attestation.linux._get_esapi", return_value=mock_ctx),
            patch("wif_bunker.attestation.linux._get_tpm_info", return_value={"manufacturer": "Intel"}),
            patch(
                "wif_bunker.attestation.linux._extract_ek_certificate",
                return_value=(AttestationCheck("EK certificate extracted", True, "ok"), "PEM"),
            ),
            patch("wif_bunker.attestation.linux.parse_ek_details", return_value={"issuer": "Intel"}),
            patch(
                "wif_bunker.attestation.linux._verify_ek_chain",
                return_value=AttestationCheck("EK certificate chain verified", True, "ok"),
            ),
            patch(
                "wif_bunker.attestation.linux._create_ek_and_ak",
                return_value=(AttestationCheck("Attestation Key created", True, "ok"), True, "ek", "ak", b"AKPEM"),
            ),
            patch(
                "wif_bunker.attestation.linux._credential_activation",
                return_value=AttestationCheck("Credential activation", True, "ok"),
            ),
            patch(
                "wif_bunker.attestation.linux._certify_key",
                return_value=(AttestationCheck("Key attestation (tpm2_certify)", True, "ok"), True, b"att", b"sig"),
            ),
        ):
            rep = _attest_linux(cfg)
        assert rep.checks_passed == 5
        assert "Cryptographically proven" in rep.summary

        # 2. swtpm (no EK cert, but AK + cred + certify pass)
        with (
            patch("wif_bunker.attestation.linux._get_esapi", return_value=mock_ctx),
            patch("wif_bunker.attestation.linux._get_tpm_info", return_value=None),
            patch(
                "wif_bunker.attestation.linux._extract_ek_certificate",
                return_value=(AttestationCheck("EK certificate extracted", False, "no ek"), None),
            ),
            patch(
                "wif_bunker.attestation.linux._create_ek_and_ak",
                return_value=(AttestationCheck("Attestation Key created", True, "ok"), True, "ek", "ak", None),
            ),
            patch(
                "wif_bunker.attestation.linux._credential_activation",
                return_value=AttestationCheck("Credential activation", True, "ok"),
            ),
            patch(
                "wif_bunker.attestation.linux._certify_key",
                return_value=(AttestationCheck("Key attestation (tpm2_certify)", True, "ok"), True, b"att", b"sig"),
            ),
        ):
            rep_sw = _attest_linux(cfg)
        assert "no EK certificate was found" in rep_sw.summary

        # 3. AK creation fails + no EK
        with (
            patch("wif_bunker.attestation.linux._get_esapi", return_value=mock_ctx),
            patch("wif_bunker.attestation.linux._get_tpm_info", return_value=None),
            patch(
                "wif_bunker.attestation.linux._extract_ek_certificate",
                return_value=(AttestationCheck("EK certificate extracted", False, "no ek"), None),
            ),
            patch(
                "wif_bunker.attestation.linux._create_ek_and_ak",
                return_value=(AttestationCheck("Attestation Key created", False, "fail"), False, None, None, None),
            ),
        ):
            rep_fail = _attest_linux(cfg)
        assert "No EK certificate found and attestation failed" in rep_fail.summary

        # 4. Verified TPM, certify failed
        with (
            patch("wif_bunker.attestation.linux._get_esapi", return_value=mock_ctx),
            patch("wif_bunker.attestation.linux._get_tpm_info", return_value=None),
            patch(
                "wif_bunker.attestation.linux._extract_ek_certificate",
                return_value=(AttestationCheck("EK certificate extracted", True, "ok"), "PEM"),
            ),
            patch("wif_bunker.attestation.linux.parse_ek_details", return_value={}),
            patch(
                "wif_bunker.attestation.linux._verify_ek_chain",
                return_value=AttestationCheck("EK certificate chain verified", True, "ok"),
            ),
            patch(
                "wif_bunker.attestation.linux._create_ek_and_ak",
                return_value=(AttestationCheck("Attestation Key created", True, "ok"), True, "ek", "ak", None),
            ),
            patch(
                "wif_bunker.attestation.linux._credential_activation",
                return_value=AttestationCheck("Credential activation", True, "ok"),
            ),
            patch(
                "wif_bunker.attestation.linux._certify_key",
                return_value=(AttestationCheck("Key attestation (tpm2_certify)", False, "fail"), False, None, None),
            ),
        ):
            rep_nocert = _attest_linux(cfg)
        assert "could not be certified" in rep_nocert.summary

        # 5. EK cert present, chain failed, key proven
        with (
            patch("wif_bunker.attestation.linux._get_esapi", return_value=mock_ctx),
            patch("wif_bunker.attestation.linux._get_tpm_info", return_value=None),
            patch(
                "wif_bunker.attestation.linux._extract_ek_certificate",
                return_value=(AttestationCheck("EK certificate extracted", True, "ok"), "PEM"),
            ),
            patch("wif_bunker.attestation.linux.parse_ek_details", return_value={}),
            patch(
                "wif_bunker.attestation.linux._verify_ek_chain",
                return_value=AttestationCheck("EK certificate chain verified", False, "bad"),
            ),
            patch(
                "wif_bunker.attestation.linux._create_ek_and_ak",
                return_value=(AttestationCheck("Attestation Key created", True, "ok"), True, "ek", "ak", None),
            ),
            patch(
                "wif_bunker.attestation.linux._credential_activation",
                return_value=AttestationCheck("Credential activation", True, "ok"),
            ),
            patch(
                "wif_bunker.attestation.linux._certify_key",
                return_value=(AttestationCheck("Key attestation (tpm2_certify)", True, "ok"), True, None, None),
            ),
        ):
            rep_nochain = _attest_linux(cfg)
        assert "chain could not be verified" in rep_nochain.summary

        # 6. ESAPI connection failure
        with patch("wif_bunker.attestation.linux._get_esapi", side_effect=RuntimeError("no device")):
            rep_no_dev = _attest_linux(cfg)
        assert rep_no_dev.supported is False
        assert "TPM not accessible" in rep_no_dev.summary
