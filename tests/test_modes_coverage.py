"""Tests to cover uncovered lines in wif_bunker/modes.py.

Covers:
- _run_cert_only: file output paths (lines 33-53)
- _run_cert_and_mtls_test: full mTLS smoke-test workflow (lines 68-201)
- _default_attest_dir: win32 branch (lines 207-208)
- _run_status: hardmTLS import + ADC stages (lines 315-348)
- _run_supported_algorithms: verbose cross output, win32/linux/unsupported branches (lines 362-399)
- _run_all_versions: comprehensive version printing (lines 407-545)
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wif_bunker.config import WorkloadConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cert_bundle():
    """Create a minimal mock CertificateBundle."""
    bundle = MagicMock()
    bundle.workload_cert_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
    bundle.trust_anchor_pem = "-----BEGIN CERTIFICATE-----\nFAKE_CA\n-----END CERTIFICATE-----\n"
    bundle.issuer_cn = "test-ca"
    bundle.sha256_fingerprint = "AA:BB:CC"
    return bundle


def _generate_self_signed_cert_pem(cn="test-workload", days=90):
    """Generate a real self-signed PEM cert for status tests."""
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# _run_cert_only
# ---------------------------------------------------------------------------


class TestRunCertOnly:
    """Tests for _run_cert_only (lines 33-53)."""

    @patch("wif_bunker.modes.write_secure_file")
    @patch("wif_bunker.modes.generate_os_keystore_cert")
    def test_writes_cert_and_chain_files(self, mock_gen, mock_write, tmp_path, caplog):
        """Covers lines 33-53: file output and log messages."""
        config = WorkloadConfig()
        bundle = _make_cert_bundle()
        mock_gen.return_value = bundle

        from wif_bunker.modes import _run_cert_only

        with caplog.at_level(logging.INFO):
            _run_cert_only(config, str(tmp_path))

        # Should write cert + chain
        assert mock_write.call_count == 2
        cert_path_call = mock_write.call_args_list[0]
        chain_path_call = mock_write.call_args_list[1]
        assert "workload_cert.pem" in str(cert_path_call[0][0])
        assert "trust_chain.pem" in str(chain_path_call[0][0])
        assert "Certificate generated" in caplog.text
        assert config.workload_cn in caplog.text

    @patch("wif_bunker.modes.write_secure_file")
    @patch("wif_bunker.modes.generate_os_keystore_cert")
    def test_creates_output_dir(self, mock_gen, mock_write, tmp_path):
        """Covers line 37: os.makedirs call."""
        config = WorkloadConfig()
        mock_gen.return_value = _make_cert_bundle()

        from wif_bunker.modes import _run_cert_only

        nested = tmp_path / "a" / "b" / "c"
        _run_cert_only(config, str(nested))
        assert nested.exists()


# ---------------------------------------------------------------------------
# _default_attest_dir
# ---------------------------------------------------------------------------


class TestDefaultAttestDir:
    """Tests for _default_attest_dir (lines 207-208)."""

    @patch("sys.platform", "win32")
    def test_windows_path(self, monkeypatch):
        """Covers lines 207-208: Windows LOCALAPPDATA branch."""
        monkeypatch.setenv("LOCALAPPDATA", "/fake/appdata")
        from wif_bunker.modes import _default_attest_dir

        result = _default_attest_dir()
        assert "wif-bunker" in result
        assert "attestation" in result

    @patch("sys.platform", "linux")
    def test_non_windows_path(self):
        """Covers line 209: non-Windows fallback."""
        from wif_bunker.modes import _default_attest_dir

        result = _default_attest_dir()
        assert ".config/wif-bunker/attestation" in result.replace("\\", "/")


# ---------------------------------------------------------------------------
# _run_status: hardmTLS + ADC stages (lines 315-348)
# ---------------------------------------------------------------------------


class TestRunStatusHardmtlsAndADC:
    """Tests for _run_status deep stages: hardmTLS retrieval and ADC."""

    def _setup_status_dir(self, tmp_path, cert_pem=None, cert_config=None, adc_config=None):
        """Helper to set up a valid status directory with all config files."""
        if cert_pem is None:
            cert_pem = _generate_self_signed_cert_pem()
        (tmp_path / "workload_cert.pem").write_bytes(cert_pem)
        (tmp_path / "adc.json").write_text(adc_config or '{"workforce_pool_user_project": "test-proj"}')
        cc = cert_config or json.dumps({"libs": {"ecp_client": "/fake/lib.so"}})
        (tmp_path / "certificate_config.json").write_text(cc)
        (tmp_path / "trust_chain.pem").write_text("dummy")

    @patch("wif_bunker.modes.json.loads")
    def test_hardmtls_lib_not_found_returns(self, mock_json, monkeypatch, tmp_path, caplog):
        """Covers lines 310-313: hardmTLS lib path doesn't exist."""
        self._setup_status_dir(tmp_path)
        monkeypatch.chdir(tmp_path)
        mock_json.return_value = {"libs": {"ecp_client": "/nonexistent/lib.so"}}

        from wif_bunker.modes import _run_status

        with caplog.at_level(logging.ERROR):
            _run_status()

        assert "library not found" in caplog.text

    @patch("wif_bunker.modes.AuthorizedSession")
    @patch("wif_bunker.modes.google.auth.default")
    def test_adc_stage_success(self, mock_auth_default, mock_session_cls, monkeypatch, tmp_path, caplog):
        """Covers lines 324-345: ADC verification success path."""
        self._setup_status_dir(tmp_path)
        monkeypatch.chdir(tmp_path)

        hardmtls_lib_path = str(tmp_path / "fake_lib.so")
        Path(hardmtls_lib_path).touch()
        cert_config = json.dumps({"libs": {"ecp_client": hardmtls_lib_path}})
        (tmp_path / "certificate_config.json").write_text(cert_config)

        mock_get_cert = MagicMock(return_value=b"FAKE_CERT_PEM_DATA")
        with patch.dict("sys.modules", {"wif_bunker.cert": MagicMock(hardmtls_get_cert_pem=mock_get_cert)}):
            mock_creds = MagicMock()
            mock_auth_default.return_value = (mock_creds, "test-proj")
            mock_session = MagicMock()
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_session.get.return_value = mock_resp
            mock_session_cls.return_value = mock_session

            from wif_bunker.modes import _run_status

            with caplog.at_level(logging.INFO):
                _run_status()

            assert "API call successful" in caplog.text

    @patch("wif_bunker.modes.AuthorizedSession")
    @patch("wif_bunker.modes.google.auth.default")
    def test_adc_stage_failure(self, mock_auth_default, mock_session_cls, monkeypatch, tmp_path, caplog):
        """Covers lines 346-348: ADC verification failure path."""
        self._setup_status_dir(tmp_path)
        monkeypatch.chdir(tmp_path)

        hardmtls_lib_path = str(tmp_path / "fake_lib.so")
        Path(hardmtls_lib_path).touch()
        cert_config = json.dumps({"libs": {"ecp_client": hardmtls_lib_path}})
        (tmp_path / "certificate_config.json").write_text(cert_config)

        mock_get_cert = MagicMock(return_value=b"FAKE_CERT_PEM_DATA")
        with patch.dict("sys.modules", {"wif_bunker.cert": MagicMock(hardmtls_get_cert_pem=mock_get_cert)}):
            mock_auth_default.side_effect = Exception("ADC exploded")

            from wif_bunker.modes import _run_status

            with caplog.at_level(logging.ERROR):
                _run_status()

            assert "ADC exploded" in caplog.text

    def test_hardmtls_import_exception(self, monkeypatch, tmp_path, caplog):
        """Covers lines 319-321: hardmTLS general exception."""
        self._setup_status_dir(tmp_path)
        monkeypatch.chdir(tmp_path)

        hardmtls_lib_path = str(tmp_path / "fake_lib.so")
        Path(hardmtls_lib_path).touch()
        cert_config = json.dumps({"libs": {"ecp_client": hardmtls_lib_path}})
        (tmp_path / "certificate_config.json").write_text(cert_config)

        with (
            patch("wif_bunker.modes.json.loads") as mock_json,
            patch.dict(
                "sys.modules",
                {"wif_bunker.cert": MagicMock(hardmtls_get_cert_pem=MagicMock(side_effect=RuntimeError("boom")))},
            ),
        ):
            mock_json.return_value = {"libs": {"ecp_client": hardmtls_lib_path}}
            from wif_bunker.modes import _run_status

            with caplog.at_level(logging.ERROR):
                _run_status()

            assert "boom" in caplog.text


# ---------------------------------------------------------------------------
# _run_supported_algorithms: verbose cross output, platform branches
# ---------------------------------------------------------------------------


class TestRunSupportedAlgorithmsExtended:
    """Tests for _run_supported_algorithms: uncovered branches (lines 362-399)."""

    @patch("sys.platform", "darwin")
    @patch("wif_bunker.keystore.macos.get_supported_algorithms_macos", return_value=["es256"])
    def test_verbose_shows_cross_for_unsupported(self, mock_probe, capsys):
        """Covers line 399: verbose cross mark for unsupported algo."""
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms(verbose=True)
        captured = capsys.readouterr()
        assert "es384" in captured.out

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.windows.get_supported_algorithms_windows", return_value=["es256", "rsa2048"])
    def test_windows_platform_dispatch(self, mock_probe, capsys):
        """Covers lines 375-382: Windows CNG dispatch."""
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms(soft_key=True)
        captured = capsys.readouterr()
        assert "es256" in captured.out
        assert "rsa2048" in captured.out

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.windows.get_supported_algorithms_windows", return_value=["es256"])
    def test_windows_tpm_verbose(self, mock_probe, capsys):
        """Covers line 376: Windows CNG (Platform TPM) keystore name."""
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms(soft_key=False, verbose=True)
        captured = capsys.readouterr()
        assert "Windows CNG (Platform TPM)" in captured.out

    @patch("sys.platform", "linux")
    @patch("wif_bunker.keystore.linux.get_supported_algorithms_linux", return_value=["es256", "rsa2048"])
    def test_linux_platform_dispatch(self, mock_probe, capsys):
        """Covers lines 383-388: Linux TPM dispatch."""
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms(verbose=True)
        captured = capsys.readouterr()
        assert "Linux TPM" in captured.out

    @patch("sys.platform", "freebsd")
    def test_unsupported_platform_raises(self):
        """Covers line 390: unsupported platform RuntimeError."""
        from wif_bunker.modes import _run_supported_algorithms

        with pytest.raises(RuntimeError, match="Unsupported platform"):
            _run_supported_algorithms()

    @patch("wif_bunker.keystore.yubikey.get_supported_algorithms_yubikey", return_value=["es256", "es384"])
    def test_yubikey_dispatch(self, mock_probe, capsys):
        """Covers lines 362-368: YubiKey dispatch."""
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms(use_yubikey=True, yubikey_serial=12345)
        captured = capsys.readouterr()
        assert "es256" in captured.out

    @patch("wif_bunker.keystore.yubikey.get_supported_algorithms_yubikey", return_value=["es256", "es384"])
    def test_yubikey_verbose(self, mock_probe, capsys):
        """Covers line 362-368 verbose mode with YubiKey."""
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms(use_yubikey=True, verbose=True)
        captured = capsys.readouterr()
        assert "YubiKey" in captured.out


# ---------------------------------------------------------------------------
# _run_all_versions
# ---------------------------------------------------------------------------


def _run_all_versions_with_patches(monkeypatch, tmp_path, hardmtls_effect=None, which_fn=None, extra_patches=None):
    """Helper to run _run_all_versions with common mocks."""
    if hardmtls_effect is None:
        hardmtls_effect = FileNotFoundError
    if which_fn is None:
        which_fn = lambda name: None  # noqa: E731

    from contextlib import ExitStack

    patches = [
        patch("shutil.which", side_effect=which_fn if callable(which_fn) else (lambda n: which_fn)),
        patch("wif_bunker.cert._find_hardmtls_library", side_effect=hardmtls_effect),
    ]
    if extra_patches:
        patches.extend(extra_patches)

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        from wif_bunker.modes import _run_all_versions

        _run_all_versions()


class TestRunAllVersions:
    """Tests for _run_all_versions (lines 407-545)."""

    @patch("wif_bunker.modes._CONFIG_FILES", ("adc.json",))
    @patch("sys.platform", "darwin")
    def test_all_versions_darwin(self, monkeypatch, tmp_path, capsys):
        """Covers lines 407-545: full _run_all_versions on macOS."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        for key in ["GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_API_USE_CLIENT_CERTIFICATE", "OPENSSL_DIR"]:
            monkeypatch.delenv(key, raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError("not found")),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "WIF Bunker" in captured.out
        assert "Python" in captured.out
        assert "OpenSSL" in captured.out
        assert "Key Dependencies" in captured.out
        assert "hardmTLS" in captured.out
        assert "(not found)" in captured.out
        assert "System" in captured.out
        assert "Config Files" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ("adc.json",))
    @patch("sys.platform", "darwin")
    def test_all_versions_with_openssl_cli(self, monkeypatch, tmp_path, capsys):
        """Covers lines 447-458: openssl CLI found on PATH."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        monkeypatch.delenv("OPENSSL_DIR", raising=False)

        mock_result = MagicMock()
        mock_result.stdout = "OpenSSL 3.0.0 7 sep 2021\n"

        def fake_which(name):
            return "/usr/bin/openssl" if name == "openssl" else None

        with (
            patch("shutil.which", side_effect=fake_which),
            patch("subprocess.run", return_value=mock_result),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "OpenSSL 3.0.0" in captured.out
        assert "/usr/bin/openssl" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ("adc.json",))
    @patch("sys.platform", "darwin")
    def test_all_versions_openssl_cli_fails(self, monkeypatch, tmp_path, capsys):
        """Covers lines 457-458: openssl version query fails."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        monkeypatch.delenv("OPENSSL_DIR", raising=False)

        def fake_which(name):
            return "/usr/bin/openssl" if name == "openssl" else None

        with (
            patch("shutil.which", side_effect=fake_which),
            patch("subprocess.run", side_effect=OSError("no openssl")),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "version query failed" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ("adc.json",))
    @patch("sys.platform", "darwin")
    def test_all_versions_openssl_dir_env(self, monkeypatch, tmp_path, capsys):
        """Covers lines 461-463: OPENSSL_DIR env var set."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        monkeypatch.setenv("OPENSSL_DIR", "/custom/openssl")

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "OPENSSL_DIR" in captured.out
        assert "/custom/openssl" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ("adc.json",))
    @patch("sys.platform", "darwin")
    def test_all_versions_frozen_exe(self, monkeypatch, tmp_path, capsys):
        """Covers lines 438-440: sys.frozen = True (PyInstaller)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        monkeypatch.delenv("OPENSSL_DIR", raising=False)

        # Manually manage sys.frozen since monkeypatch teardown fails
        # when delattr is called on an attribute that didn't originally exist.
        had_frozen = hasattr(sys, "frozen")
        old_frozen = getattr(sys, "frozen", None)
        sys.frozen = True
        try:
            with (
                patch("shutil.which", return_value=None),
                patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
            ):
                from wif_bunker.modes import _run_all_versions

                _run_all_versions()

            captured = capsys.readouterr()
            assert "Frozen" in captured.out
            assert "PyInstaller" in captured.out
        finally:
            if had_frozen:
                sys.frozen = old_frozen
            elif hasattr(sys, "frozen"):
                del sys.frozen

    @patch("wif_bunker.modes._CONFIG_FILES", ("adc.json",))
    @patch("sys.platform", "linux")
    def test_all_versions_linux_deps(self, monkeypatch, tmp_path, capsys):
        """Covers lines 475-477: Linux-specific dependency output."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "adc.json").write_text("{}")
        monkeypatch.delenv("OPENSSL_DIR", raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "tpm2-pytss" in captured.out
        assert "python-pkcs11" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ("missing.json",))
    @patch("sys.platform", "darwin")
    def test_all_versions_missing_config(self, monkeypatch, tmp_path, capsys):
        """Covers lines 538-545: config files section with missing files."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OPENSSL_DIR", raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "missing.json" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ())
    @patch("sys.platform", "darwin")
    def test_all_versions_env_vars_found(self, monkeypatch, tmp_path, capsys):
        """Covers lines 517-521: environment variable found."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/creds.json")
        monkeypatch.delenv("OPENSSL_DIR", raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "GOOGLE_APPLICATION_CREDENTIALS=/path/to/creds.json" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ())
    @patch("sys.platform", "darwin")
    def test_all_versions_no_env_vars(self, monkeypatch, tmp_path, capsys):
        """Covers lines 522-523: no relevant env vars set."""
        monkeypatch.chdir(tmp_path)
        env_keys = [
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_API_USE_CLIENT_CERTIFICATE",
            "GOOGLE_API_CERTIFICATE_CONFIG",
            "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
            "GOOGLE_CLOUD_PROJECT",
            "CLOUDSDK_CORE_PROJECT",
            "OPENSSL_DIR",
            "OPENSSL_CONF",
            "OPENSSL_MODULES",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "ENABLE_ENTERPRISE_CERTIFICATE_LOGS",
            "RUST_LOG",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
            "TPM2TOOLS_TCTI",
            "TPM2_PKCS11_TCTI",
            "TPM2_PKCS11_STORE",
            "DBUS_SESSION_BUS_ADDRESS",
        ]
        for k in env_keys:
            monkeypatch.delenv(k, raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "(none of the relevant variables are set)" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ())
    @patch("sys.platform", "darwin")
    def test_all_versions_hardmtls_found(self, monkeypatch, tmp_path, capsys):
        """Covers lines 481-485: hardmTLS library found."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OPENSSL_DIR", raising=False)
        for k in [
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_API_USE_CLIENT_CERTIFICATE",
            "GOOGLE_API_CERTIFICATE_CONFIG",
        ]:
            monkeypatch.delenv(k, raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", return_value="/usr/lib/hardmtls.so"),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "/usr/lib/hardmtls.so" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ())
    @patch("sys.platform", "darwin")
    def test_all_versions_hardmtls_error(self, monkeypatch, tmp_path, capsys):
        """Covers lines 488-489: hardmTLS library error."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OPENSSL_DIR", raising=False)
        for k in [
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_API_USE_CLIENT_CERTIFICATE",
            "GOOGLE_API_CERTIFICATE_CONFIG",
        ]:
            monkeypatch.delenv(k, raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=RuntimeError("ctypes error")),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "(error: ctypes error)" in captured.out

    @patch("wif_bunker.modes._CONFIG_FILES", ())
    @patch("sys.platform", "win32")
    def test_all_versions_windows_platform(self, monkeypatch, tmp_path, capsys):
        """Covers lines 533-535: Windows version output."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OPENSSL_DIR", raising=False)
        for k in [
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_API_USE_CLIENT_CERTIFICATE",
            "GOOGLE_API_CERTIFICATE_CONFIG",
        ]:
            monkeypatch.delenv(k, raising=False)

        with (
            patch("shutil.which", return_value=None),
            patch("wif_bunker.cert._find_hardmtls_library", side_effect=FileNotFoundError),
            patch("platform.win32_ver", return_value=("10", "10.0.19041", "", "")),
        ):
            from wif_bunker.modes import _run_all_versions

            _run_all_versions()

        captured = capsys.readouterr()
        assert "Windows version" in captured.out


# ---------------------------------------------------------------------------
# _run_cert_and_mtls_test
# ---------------------------------------------------------------------------


class TestRunCertAndMtlsTest:
    """Tests for _run_cert_and_mtls_test (lines 68-201)."""

    @patch("wif_bunker.modes.write_secure_file")
    @patch("wif_bunker.modes.generate_os_keystore_cert")
    def test_hardmtls_lib_not_found_exits(self, mock_gen, mock_write, tmp_path):
        """Covers lines 96-100: hardmTLS library not found raises SystemExit."""
        config = WorkloadConfig()
        mock_gen.return_value = _make_cert_bundle()

        mock_cert_module = MagicMock()
        mock_cert_module._find_hardmtls_library.side_effect = FileNotFoundError("not found")
        with patch.dict("sys.modules", {"wif_bunker.cert": mock_cert_module}):
            from wif_bunker.modes import _run_cert_and_mtls_test

            with pytest.raises(SystemExit):
                _run_cert_and_mtls_test(config, str(tmp_path))

    @pytest.mark.skipif(sys.platform == "win32", reason="reload triggers real OS check")
    @patch("wif_bunker.modes.write_secure_file")
    @patch("wif_bunker.keystore.generate_os_keystore_cert")
    def test_full_success_path(self, mock_gen, mock_write, tmp_path, caplog):
        """Covers lines 68-201: full happy-path mTLS test."""
        config = WorkloadConfig()
        bundle = _make_cert_bundle()
        mock_gen.return_value = bundle

        mock_cert = MagicMock()
        mock_cert._find_hardmtls_library.return_value = "/fake/hardmtls.so"
        mock_cert.build_certificate_config.return_value = (
            {},
            tmp_path / "cert_config.json",
            tmp_path / "workload_cert.pem",
            tmp_path / "trust_chain.pem",
        )
        mock_cert.verify_cert_retrieval.return_value = None

        mock_session = MagicMock()
        certauth_resp = MagicMock()
        certauth_resp.status_code = 200
        certauth_resp.json.return_value = {
            "SSL_CLIENT_S_DN": "CN=test",
            "SSL_CLIENT_I_DN": "CN=ca",
            "SSL_CLIENT_SERIAL": "1234",
            "SSL_CLIENT_VERIFY": "SUCCESS",
        }
        sts_resp = MagicMock()
        sts_resp.status_code = 200

        mock_requests = MagicMock()
        mock_requests.Session.return_value = mock_session
        mock_session.get.side_effect = [certauth_resp, sts_resp]
        mock_requests.exceptions = __import__("requests").exceptions

        mock_offload = MagicMock()

        with (
            patch.dict("sys.modules", {"wif_bunker.cert": mock_cert, "requests": mock_requests}),
            patch("google.auth.transport.requests._MutualTlsOffloadAdapter", mock_offload),
        ):
            from importlib import reload

            import wif_bunker.modes

            reload(wif_bunker.modes)
            with caplog.at_level(logging.INFO):
                wif_bunker.modes._run_cert_and_mtls_test(config, str(tmp_path))

        assert "ALL PASSED" in caplog.text
