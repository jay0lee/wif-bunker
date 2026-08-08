"""Tests for cert.py — covers uncovered lines 62, 65, 210, 228, 244, 267-370, 386-408, 413-443, 477-507."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from wif_bunker.cert import (
    _add_lib_to_path,
    _create_ca_and_sign,
    _find_hardmtls_library,
    _get_hardmtls_lib_name,
    build_adc_config,
    build_certificate_config,
    run_hardmtls_diagnostics,
    verify_cert_retrieval,
)
from wif_bunker.config import CertificateBundle, WorkloadConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_self_signed_cert_pem() -> str:
    """Generate a self-signed certificate PEM for testing the cert-input branch."""
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(cx509.oid.NameOID.COMMON_NAME, "test-self-signed")]))
        .issuer_name(cx509.Name([cx509.NameAttribute(cx509.oid.NameOID.COMMON_NAME, "test-self-signed")]))
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _make_public_key_pem() -> str:
    """Generate a raw PEM public key for testing the PUBLIC KEY branch."""
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )


def _make_config(**overrides) -> WorkloadConfig:
    """Build a WorkloadConfig with optional overrides."""
    config = WorkloadConfig()
    config.project_id = "test-proj-123"
    for k, v in overrides.items():
        setattr(config, k, v)
    return config


def _make_cert_bundle() -> CertificateBundle:
    """Build a minimal CertificateBundle for tests."""
    return CertificateBundle(
        trust_anchor_pem="-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
        workload_cert_pem="-----BEGIN CERTIFICATE-----\nFAKEWORKLOAD\n-----END CERTIFICATE-----",
        issuer_cn="bunker-ca-test",
        serial_number_hex="ABCDEF",
        sha256_fingerprint="abc123fingerprint",
    )


# ---------------------------------------------------------------------------
# _create_ca_and_sign — PUBLIC KEY input (line 62)
# ---------------------------------------------------------------------------


class TestCreateCaAndSignPublicKeyInput:
    def test_accepts_raw_public_key_pem(self, sample_config):
        """Covers line 62: branch where input is a raw PEM public key."""
        pub_pem = _make_public_key_pem()
        bundle, workload_pem = _create_ca_and_sign(pub_pem, sample_config)
        assert isinstance(bundle, CertificateBundle)
        assert "BEGIN CERTIFICATE" in workload_pem


# ---------------------------------------------------------------------------
# _create_ca_and_sign — self-signed cert input (line 65)
# ---------------------------------------------------------------------------


class TestCreateCaAndSignSelfSignedInput:
    def test_accepts_self_signed_cert_pem(self, sample_config):
        """Covers line 65: branch where input is a self-signed certificate."""
        cert_pem = _make_self_signed_cert_pem()
        bundle, workload_pem = _create_ca_and_sign(cert_pem, sample_config)
        assert isinstance(bundle, CertificateBundle)
        assert "BEGIN CERTIFICATE" in workload_pem


# ---------------------------------------------------------------------------
# _get_hardmtls_lib_name — platform branches
# ---------------------------------------------------------------------------


class TestGetHardmtlsLibName:
    def test_win32(self):
        """Covers line 187: Windows returns .dll."""
        with patch("wif_bunker.cert.sys") as mock_sys:
            mock_sys.platform = "win32"
            assert _get_hardmtls_lib_name() == "hardmtls.dll"

    def test_darwin(self):
        """Covers line 189: macOS returns .dylib."""
        with patch("wif_bunker.cert.sys") as mock_sys:
            mock_sys.platform = "darwin"
            assert _get_hardmtls_lib_name() == "libhardmtls.dylib"

    def test_linux(self):
        """Covers line 190: Linux returns .so."""
        with patch("wif_bunker.cert.sys") as mock_sys:
            mock_sys.platform = "linux"
            assert _get_hardmtls_lib_name() == "libhardmtls.so"


# ---------------------------------------------------------------------------
# _find_hardmtls_library — frozen binary (line 210) and not-found (line 228)
# ---------------------------------------------------------------------------


class TestFindHardmtlsLibrary:
    def test_frozen_binary_path(self, tmp_path):
        """Covers line 210: when sys.frozen is True, uses sys.executable's parent."""
        lib_dir = tmp_path / "hardmtls"
        lib_dir.mkdir()
        lib_file = lib_dir / "libhardmtls.dylib"
        lib_file.touch()

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert._add_lib_to_path"),
        ):
            mock_sys.frozen = True
            mock_sys.executable = str(tmp_path / "wif-bunker")
            mock_sys.platform = "darwin"
            result = _find_hardmtls_library()

        assert result == lib_file

    def test_not_found_raises(self, tmp_path):
        """Covers line 228: FileNotFoundError when no search path has the library."""
        with (
            patch("wif_bunker.cert._get_hardmtls_lib_name", return_value="libhardmtls.so"),
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path") as mock_path_cls,
            pytest.raises(FileNotFoundError, match="hardmTLS library"),
        ):
            mock_sys.frozen = False

            # __file__ path
            file_path = MagicMock()
            file_path.parent.parent = MagicMock()
            mock_path_cls.return_value = file_path

            # Make all lib_path.exists() return False
            def fake_truediv(self_path, other):
                m = MagicMock()
                m.__truediv__ = fake_truediv
                m.exists.return_value = False
                m.__str__ = lambda s: f"/fake/{other}"
                return m

            file_path.parent.parent.__truediv__ = fake_truediv
            _find_hardmtls_library()

# ---------------------------------------------------------------------------
# _add_lib_to_path — Windows DLL directory (line 244)
# ---------------------------------------------------------------------------


class TestAddLibToPath:
    def test_adds_to_path_env(self, tmp_path):
        """Covers lines 247-249: adds lib dir to PATH."""
        lib_dir = tmp_path / "libs"
        lib_dir.mkdir()
        original_path = "/usr/bin:/bin"
        with patch.dict("os.environ", {"PATH": original_path}):
            with patch("wif_bunker.cert.sys") as mock_sys:
                mock_sys.platform = "linux"
                _add_lib_to_path(lib_dir)
            import os

            assert str(lib_dir) in os.environ["PATH"]

    def test_win32_add_dll_directory(self, tmp_path):
        """Covers line 244: Windows calls os.add_dll_directory."""
        lib_dir = tmp_path / "libs"
        lib_dir.mkdir()
        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.os") as mock_os,
        ):
            mock_sys.platform = "win32"
            mock_os.environ = {"PATH": "/usr/bin"}
            mock_os.pathsep = ";"
            _add_lib_to_path(lib_dir)
            mock_os.add_dll_directory.assert_called_once_with(str(lib_dir))


# ---------------------------------------------------------------------------
# build_certificate_config — all platform branches (lines 267-370)
# ---------------------------------------------------------------------------


class TestBuildCertificateConfig:
    def test_darwin_keychain_config(self, tmp_path):
        """Covers lines 294-299: macOS keychain cert config."""
        config = _make_config()
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "libhardmtls.dylib"

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file"),
        ):
            mock_sys.platform = "darwin"
            cert_cfg, _cfg_path, _wl_path, _tc_path = build_certificate_config(config, bundle, hardmtls_lib)

        assert "macos_keychain" in cert_cfg["cert_configs"]
        assert cert_cfg["cert_configs"]["macos_keychain"]["issuer"] == bundle.issuer_cn
        assert cert_cfg["version"] == 1
        assert cert_cfg["libs"]["ecp_client"] == str(hardmtls_lib)

    def test_win32_store_config(self, tmp_path):
        """Covers lines 286-293: Windows cert store config (non-YubiKey)."""
        config = _make_config()
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "hardmtls.dll"

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file"),
        ):
            mock_sys.platform = "win32"
            cert_cfg, _, _, _ = build_certificate_config(config, bundle, hardmtls_lib)

        ws = cert_cfg["cert_configs"]["windows_store"]
        assert ws["store"] == "MY"
        assert ws["provider"] == "current_user"
        assert ws["issuer"] == bundle.issuer_cn

    def test_win32_yubikey_store_config(self, tmp_path):
        """Covers lines 267-278: YubiKey on Windows uses windows_store."""
        config = _make_config(use_yubikey=True)
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "hardmtls.dll"

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file"),
        ):
            mock_sys.platform = "win32"
            cert_cfg, _, _, _ = build_certificate_config(config, bundle, hardmtls_lib)

        assert "windows_store" in cert_cfg["cert_configs"]

    def test_yubikey_non_windows_pkcs11(self, tmp_path):
        """Covers lines 279-285: YubiKey on non-Windows uses PKCS#11."""
        config = _make_config(use_yubikey=True)
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "libhardmtls.dylib"

        mock_pkcs11_config = {"pkcs11": {"module": "/fake/ykcs11.dylib", "slot": "0"}}
        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file"),
            patch("wif_bunker.keystore.yubikey.build_ecp_pkcs11_config", return_value=mock_pkcs11_config),
        ):
            mock_sys.platform = "darwin"
            cert_cfg, _, _, _ = build_certificate_config(config, bundle, hardmtls_lib)

        assert "pkcs11" in cert_cfg["cert_configs"]

    def test_linux_pkcs11_with_slot_discovery(self, tmp_path):
        """Covers lines 300-344: Linux PKCS#11 with pkcs11-tool slot discovery."""
        config = _make_config()
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "libhardmtls.so"

        pkcs11_tool_output = (
            "Slot 0 (0x1): SoftHSM slot ID 0x1\n"
            "  token label        : unused\n"
            "Slot 1 (0x2): SoftHSM slot ID 0x2\n"
            "  token label        : bunker-wif token\n"
        )

        mock_result = MagicMock()
        mock_result.stdout = pkcs11_tool_output

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file"),
            patch("wif_bunker.cert.Path.exists", return_value=True),
            patch("wif_bunker.cert.subprocess.run", return_value=mock_result),
        ):
            mock_sys.platform = "linux"
            cert_cfg, _, _, _ = build_certificate_config(config, bundle, hardmtls_lib)

        pkcs11 = cert_cfg["cert_configs"]["pkcs11"]
        assert pkcs11["slot"] == "2"  # slot 0x2 had "bunker-wif"
        assert pkcs11["label"] == config.workload_cn

    def test_linux_pkcs11_slot_discovery_failure_defaults(self, tmp_path):
        """Covers lines 328-333: slot discovery exception defaults to slot '1'."""
        config = _make_config()
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "libhardmtls.so"

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file"),
            patch("wif_bunker.cert.Path.exists", return_value=True),
            patch("wif_bunker.cert.subprocess.run", side_effect=OSError("pkcs11-tool not found")),
        ):
            mock_sys.platform = "linux"
            cert_cfg, _, _, _ = build_certificate_config(config, bundle, hardmtls_lib)

        assert cert_cfg["cert_configs"]["pkcs11"]["slot"] == "1"

    def test_linux_pkcs11_no_module_found(self, tmp_path):
        """Covers line 308: FileNotFoundError when no libtpm2_pkcs11.so found."""
        config = _make_config()
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "libhardmtls.so"

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.Path.exists", return_value=False),
            pytest.raises(FileNotFoundError, match="libtpm2_pkcs11"),
        ):
            mock_sys.platform = "linux"
            build_certificate_config(config, bundle, hardmtls_lib)

    def test_linux_pkcs11_no_bunker_wif_in_slots(self, tmp_path):
        """Covers lines 331-333: no bunker-wif token found defaults to slot '1'."""
        config = _make_config()
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "libhardmtls.so"

        pkcs11_tool_output = "Slot 0 (0x1): SoftHSM slot ID 0x1\n  token label        : some-other-token\n"
        mock_result = MagicMock()
        mock_result.stdout = pkcs11_tool_output

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file"),
            patch("wif_bunker.cert.Path.exists", return_value=True),
            patch("wif_bunker.cert.subprocess.run", return_value=mock_result),
        ):
            mock_sys.platform = "linux"
            cert_cfg, _, _, _ = build_certificate_config(config, bundle, hardmtls_lib)

        assert cert_cfg["cert_configs"]["pkcs11"]["slot"] == "1"

    def test_output_paths(self, tmp_path):
        """Cert config writes workload and trust chain PEM files."""
        config = _make_config()
        bundle = _make_cert_bundle()
        hardmtls_lib = tmp_path / "libhardmtls.dylib"

        written = {}

        def fake_write(path, content):
            written[Path(path).name] = content

        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
            patch("wif_bunker.cert.write_secure_file", side_effect=fake_write),
        ):
            mock_sys.platform = "darwin"
            build_certificate_config(config, bundle, hardmtls_lib)

        assert "workload_cert.pem" in written
        assert "trust_chain.pem" in written
        assert "certificate_config.json" in written


# ---------------------------------------------------------------------------
# build_adc_config (lines 386-408)
# ---------------------------------------------------------------------------


class TestBuildAdcConfig:
    def test_adc_config_without_sa(self, tmp_path):
        """Covers lines 386-408: ADC config without SA impersonation."""
        config = _make_config()

        with (
            patch("wif_bunker.cert.write_secure_file") as mock_write,
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
        ):
            adc_cfg, _adc_path = build_adc_config(
                config=config,
                project_number="123456",
                cert_config_path=tmp_path / "certificate_config.json",
                trust_chain_path=tmp_path / "trust_chain.pem",
                sa_email=None,
                use_sa=False,
            )

        assert adc_cfg["type"] == "external_account"
        assert adc_cfg["subject_token_type"] == "urn:ietf:params:oauth:token-type:mtls"
        assert "service_account_impersonation_url" not in adc_cfg
        assert config.pool_id in adc_cfg["audience"]
        assert config.provider_id in adc_cfg["audience"]
        assert "123456" in adc_cfg["audience"]
        assert adc_cfg["token_url"] == "https://sts.mtls.googleapis.com/v1/token"
        mock_write.assert_called_once()

    def test_adc_config_with_sa(self, tmp_path):
        """Covers lines 402-405: ADC config with SA impersonation."""
        config = _make_config()

        with (
            patch("wif_bunker.cert.write_secure_file"),
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
        ):
            adc_cfg, _ = build_adc_config(
                config=config,
                project_number="123456",
                cert_config_path=tmp_path / "certificate_config.json",
                trust_chain_path=tmp_path / "trust_chain.pem",
                sa_email="sa@proj.iam.gserviceaccount.com",
                use_sa=True,
            )

        assert "service_account_impersonation_url" in adc_cfg
        assert "sa@proj.iam.gserviceaccount.com" in adc_cfg["service_account_impersonation_url"]

    def test_adc_config_trust_chain_path_in_credential_source(self, tmp_path):
        """Verifies trust_chain_path is set correctly in credential_source."""
        config = _make_config()
        tc_path = tmp_path / "trust_chain.pem"

        with (
            patch("wif_bunker.cert.write_secure_file"),
            patch("wif_bunker.cert.Path.cwd", return_value=tmp_path),
        ):
            adc_cfg, _ = build_adc_config(
                config=config,
                project_number="999",
                cert_config_path=tmp_path / "certificate_config.json",
                trust_chain_path=tc_path,
                sa_email=None,
                use_sa=False,
            )

        assert adc_cfg["credential_source"]["certificate"]["trust_chain_path"] == str(tc_path)


# ---------------------------------------------------------------------------
# run_hardmtls_diagnostics (lines 413-443)
# ---------------------------------------------------------------------------


class TestRunHardmtlsDiagnostics:
    def test_reads_config_and_checks_library(self, tmp_path):
        """Covers lines 413-431: reads config, checks lib existence."""
        lib_path = tmp_path / "libhardmtls.so"
        lib_path.write_bytes(b"\x00" * 2048)

        config = {
            "libs": {"ecp_client": str(lib_path)},
            "cert_configs": {},
        }
        config_path = tmp_path / "certificate_config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        log = logging.getLogger("test_diagnostics")
        run_hardmtls_diagnostics(config_path, log)

    def test_config_read_error(self, tmp_path):
        """Covers lines 418-420: returns early when config can't be read."""
        config_path = tmp_path / "nonexistent_config.json"
        log = logging.getLogger("test_diagnostics")
        run_hardmtls_diagnostics(config_path, log)  # should not raise

    def test_lib_not_found(self, tmp_path):
        """Covers line 429: warns when library file doesn't exist."""
        config = {
            "libs": {"ecp_client": str(tmp_path / "missing_lib.so")},
        }
        config_path = tmp_path / "certificate_config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        log = logging.getLogger("test_diagnostics")
        run_hardmtls_diagnostics(config_path, log)  # should not raise

    def test_darwin_find_identity(self, tmp_path):
        """Covers lines 433-443: macOS find-identity check."""
        lib_path = tmp_path / "libhardmtls.dylib"
        lib_path.write_bytes(b"\x00" * 1024)

        config = {"libs": {"ecp_client": str(lib_path)}}
        config_path = tmp_path / "certificate_config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        mock_result = MagicMock()
        mock_result.stdout = "1 valid identity found"

        log = logging.getLogger("test_diagnostics")
        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.subprocess.run", return_value=mock_result),
        ):
            mock_sys.platform = "darwin"
            run_hardmtls_diagnostics(config_path, log)

    def test_darwin_find_identity_error(self, tmp_path):
        """Covers line 443: find-identity subprocess error."""
        lib_path = tmp_path / "libhardmtls.dylib"
        lib_path.write_bytes(b"\x00" * 1024)

        config = {"libs": {"ecp_client": str(lib_path)}}
        config_path = tmp_path / "certificate_config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        log = logging.getLogger("test_diagnostics")
        with (
            patch("wif_bunker.cert.sys") as mock_sys,
            patch("wif_bunker.cert.subprocess.run", side_effect=OSError("security not found")),
        ):
            mock_sys.platform = "darwin"
            run_hardmtls_diagnostics(config_path, log)  # should not raise

    def test_json_parse_error(self, tmp_path):
        """Covers lines 430-431: library check with invalid JSON."""
        config_path = tmp_path / "certificate_config.json"
        config_path.write_text("not valid json{{{", encoding="utf-8")

        log = logging.getLogger("test_diagnostics")
        run_hardmtls_diagnostics(config_path, log)  # should not raise


# ---------------------------------------------------------------------------
# verify_cert_retrieval (lines 477-507)
# ---------------------------------------------------------------------------


class TestVerifyCertRetrieval:
    def _make_real_cert_pem_bytes(self) -> bytes:
        """Generate a real X.509 cert PEM for parsing tests."""
        key = ec.generate_private_key(ec.SECP256R1())
        import datetime

        from cryptography.x509.oid import NameOID

        cert = (
            cx509.CertificateBuilder()
            .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "test-workload")]))
            .issuer_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "test-ca")]))
            .public_key(key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    def test_success_returns_pem(self):
        """Covers lines 477-501: successful cert retrieval and parsing."""
        cert_pem_bytes = self._make_real_cert_pem_bytes()

        with patch("wif_bunker.cert.hardmtls_get_cert_pem", return_value=cert_pem_bytes):
            result = verify_cert_retrieval("/fake/config.json", "/fake/lib.so")

        assert "BEGIN CERTIFICATE" in result

    def test_runtime_error_raised_on_cert_len_zero(self):
        """Covers lines 481-485: RuntimeError when hardmtls returns cert_len=0."""
        with (
            patch("wif_bunker.cert.hardmtls_get_cert_pem", side_effect=RuntimeError("cert_len=0")),
            pytest.raises(RuntimeError, match="cert retrieval failed"),
        ):
            verify_cert_retrieval("/fake/config.json", "/fake/lib.so")

    def test_runtime_error_with_debug_runs_diagnostics(self):
        """Covers lines 483-484: debug=True triggers diagnostics."""
        with (
            patch("wif_bunker.cert.hardmtls_get_cert_pem", side_effect=RuntimeError("cert_len=0")),
            patch("wif_bunker.cert.run_hardmtls_diagnostics") as mock_diag,
            pytest.raises(RuntimeError),
        ):
            verify_cert_retrieval("/fake/config.json", "/fake/lib.so", debug=True)

        mock_diag.assert_called_once()

    def test_parse_error_is_warning_not_fatal(self):
        """Covers lines 497-498: cert parse failure warns but returns PEM."""
        bad_pem = b"-----BEGIN CERTIFICATE-----\nINVALIDDATA\n-----END CERTIFICATE-----\n"

        with patch("wif_bunker.cert.hardmtls_get_cert_pem", return_value=bad_pem):
            result = verify_cert_retrieval("/fake/config.json", "/fake/lib.so")

        assert "BEGIN CERTIFICATE" in result

    def test_unexpected_exception_wraps_in_runtime_error(self):
        """Covers lines 505-507: unexpected exception wrapped in RuntimeError."""
        with (
            patch("wif_bunker.cert.hardmtls_get_cert_pem", side_effect=ValueError("unexpected")),
            pytest.raises(RuntimeError, match="hardmTLS cert retrieval failed"),
        ):
            verify_cert_retrieval("/fake/config.json", "/fake/lib.so")
