import importlib.util
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from wif_bunker.config import CertificateBundle, WorkloadConfig


def _make_fake_workload_pem():
    """Create a minimal self-signed PEM cert for test mocking."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.PEM).decode("utf-8")


@pytest.fixture
def config():
    cfg = MagicMock(spec=WorkloadConfig)
    cfg.workload_cn = "test-bunker"
    cfg.key_algorithm = "es256"
    cfg.key_algo_config = {
        "macos_sc_auth": "secp256r1",
        "linux_tpm2": "ecc256",
        "windows_certreq": "ECDSA_P256",
        "windows_key_length": "256",
        "ncrypt_algo": "ECDSA_P256",
        "ncrypt_key_length": None,
        "ncrypt_cng_class": "ECDsaCng",
    }
    cfg.linux_tpm_pin = "1234"
    cfg.soft_key = False
    return cfg


class TestMacOSKeystoreFlow:
    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    @patch("wif_bunker.keystore.macos._create_ca_and_sign")
    @patch("wif_bunker.keystore.macos.require_commands")
    @patch("wif_bunker.keystore.macos.subprocess.run")
    def test_cleanup_deletes_stale_identities(self, mock_run, mock_require, mock_ca, config):
        from wif_bunker.keystore.macos import _generate_cert_macos

        # Setup mock for subprocess.run
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "sc_auth" and cmd[1] == "identities":
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="stale-hash\tbunker-stale\nnew-hash\ttest-bunker\n"
                )
            elif cmd[0] == "security" and cmd[1] == "find-certificate":
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")
            elif cmd[0] == "sc_auth" and cmd[1] == "create-ctk-csr":
                # Create a fake CSR file to satisfy the existence check
                from pathlib import Path

                if "-f" in cmd:
                    idx = cmd.index("-f")
                    basename = cmd[idx + 1]
                    Path(f"{basename}.csr").write_text("fake csr")
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")

        mock_run.side_effect = side_effect
        mock_ca.return_value = (
            CertificateBundle(
                trust_anchor_pem="ca",
                workload_cert_pem="leaf",
                issuer_cn="issuer",
                serial_number_hex="01",
                sha256_fingerprint="sha",
            ),
            "fake-pem",
        )

        _generate_cert_macos(config)

        # Verify delete-ctk-identity was called for the stale identity
        mock_run.assert_any_call(["sc_auth", "delete-ctk-identity", "-h", "stale-hash"], capture_output=True)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    @patch("wif_bunker.keystore.macos.platform.mac_ver")
    @patch("wif_bunker.keystore.macos.require_commands")
    def test_version_check_rejects_old_macos(self, mock_require, mock_mac_ver, config):
        from wif_bunker.keystore.macos import _generate_cert_macos

        mock_mac_ver.return_value = ("14.0",)

        with pytest.raises(RuntimeError, match="macOS 15\\+"):
            _generate_cert_macos(config)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    @patch("wif_bunker.keystore.macos._create_ca_and_sign")
    @patch("wif_bunker.keystore.macos.platform.mac_ver")
    @patch("wif_bunker.keystore.macos.require_commands")
    @patch("wif_bunker.keystore.macos.subprocess.run")
    def test_version_check_accepts_macos15(self, mock_run, mock_require, mock_mac_ver, mock_ca, config):
        from wif_bunker.keystore.macos import _generate_cert_macos

        mock_mac_ver.return_value = ("15.0",)

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "sc_auth" and cmd[1] == "identities":
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="new-hash\ttest-bunker\n")
            elif cmd[0] == "security" and cmd[1] == "find-certificate":
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")
            elif cmd[0] == "sc_auth" and cmd[1] == "create-ctk-csr":
                from pathlib import Path

                if "-f" in cmd:
                    idx = cmd.index("-f")
                    basename = cmd[idx + 1]
                    Path(f"{basename}.csr").write_text("fake csr")
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")

        mock_run.side_effect = side_effect
        mock_ca.return_value = (
            CertificateBundle(
                trust_anchor_pem="ca",
                workload_cert_pem="leaf",
                issuer_cn="issuer",
                serial_number_hex="01",
                sha256_fingerprint="sha",
            ),
            "fake-pem",
        )

        # Should not raise
        _generate_cert_macos(config)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    @patch("wif_bunker.keystore.macos.require_commands")
    @patch("wif_bunker.keystore.macos.subprocess.run")
    def test_se_auth_failed_gives_clear_error(self, mock_run, mock_require, config):
        from wif_bunker.keystore.macos import _generate_cert_macos

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "sc_auth" and cmd[1] == "create-ctk-identity":
                raise subprocess.CalledProcessError(returncode=1, cmd=cmd, stderr="-25293 errSecAuthFailed")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")

        mock_run.side_effect = side_effect

        with pytest.raises(RuntimeError, match="Secure Enclave"):
            _generate_cert_macos(config)


@pytest.mark.skipif(not importlib.util.find_spec("pkcs11"), reason="python-pkcs11 not installed")
class TestLinuxKeystoreFlow:
    @patch("socket.socket")
    def test_secret_tool_lookup_fallback(self, mock_socket):
        # We test that _check_tpm_linux falls back to the socket if /dev/tpmrm0 is missing
        import os

        from wif_bunker.keystore.linux import _check_tpm_linux

        # Simulate no /dev/tpmrm0
        with (
            patch("wif_bunker.keystore.linux.Path.exists", return_value=False),
            patch.dict(os.environ, clear=True),
        ):
            # Socket connects successfully (swtpm fallback)
            mock_sock_instance = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock_instance

            # Should not raise an exception
            _check_tpm_linux()

            # Verify socket fallback was attempted
            mock_sock_instance.connect.assert_called_with(("127.0.0.1", 2321))

    @patch("wif_bunker.keystore.linux.Path.home")
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    @patch("wif_bunker.keystore.linux._find_pkcs11_lib", return_value="/usr/lib/pkcs11/libtpm2_pkcs11.so")
    @patch("wif_bunker.keystore.linux._create_ca_and_sign")
    @patch("pkcs11.lib")
    def test_pkcs11_key_generation_and_cert_import(
        self, mock_pkcs11_lib, mock_ca, mock_find_lib, mock_check, mock_home, config, tmp_path
    ):
        """Verify full PKCS#11 flow: key gen → pub key extract → cert import."""
        mock_home.return_value = tmp_path
        import os

        from cryptography.hazmat.primitives import serialization
        from pkcs11 import Attribute, KeyType

        from wif_bunker.keystore.linux import _generate_cert_linux

        # Mock the PKCS#11 library
        mock_lib = MagicMock()
        mock_pkcs11_lib.return_value = mock_lib

        # Mock token: exists on first call (cleanup finds it, but no objects)
        mock_token = MagicMock()
        mock_lib.get_token.return_value = mock_token

        # Cleanup session: no objects to destroy
        mock_cleanup_session = MagicMock()
        mock_cleanup_session.get_objects.return_value = []

        # Generate session with key pair
        mock_gen_session = MagicMock()
        mock_pub = MagicMock()
        mock_priv = MagicMock()
        mock_gen_session.generate_keypair.return_value = (mock_pub, mock_priv)

        # EC public key attributes (P-256 uncompressed point from a real key)
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        real_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
        real_point = real_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        # Wrap in DER OCTET STRING like libtpm2_pkcs11 does
        fake_point = bytes([0x04, len(real_point)]) + real_point

        mock_pub.key_type = KeyType.EC
        mock_pub.__getitem__ = lambda self, key: {
            Attribute.EC_POINT: fake_point,
            Attribute.EC_PARAMS: b"",
            Attribute.ID: b"\x01\x02\x03",
        }.get(key, b"")

        # Two token.open calls: cleanup (rw=True), then generate (user_pin, rw=True)
        call_count = {"n": 0}

        def open_side_effect(**kwargs):
            ctx = MagicMock()
            call_count["n"] += 1
            if call_count["n"] == 1:
                ctx.__enter__ = MagicMock(return_value=mock_cleanup_session)
            else:
                ctx.__enter__ = MagicMock(return_value=mock_gen_session)
            ctx.__exit__ = MagicMock(return_value=False)
            return ctx

        mock_token.open.side_effect = open_side_effect

        mock_ca.return_value = (
            CertificateBundle(
                trust_anchor_pem="ca",
                workload_cert_pem="leaf",
                issuer_cn="issuer",
                serial_number_hex="01",
                sha256_fingerprint="sha",
            ),
            _make_fake_workload_pem(),
        )

        with patch.dict(os.environ, clear=True):
            result = _generate_cert_linux(config)

        assert result.trust_anchor_pem == "ca"
        mock_gen_session.generate_keypair.assert_called_once()
        mock_gen_session.create_object.assert_called_once()

    @patch("wif_bunker.keystore.linux.Path.home")
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    @patch("wif_bunker.keystore.linux._find_pkcs11_lib", return_value="/usr/lib/pkcs11/libtpm2_pkcs11.so")
    @patch("pkcs11.lib")
    def test_pkcs11_device_error_raises_runtime_error(
        self, mock_pkcs11_lib, mock_find_lib, mock_check, mock_home, config, tmp_path
    ):
        """PKCS#11 device errors are converted to actionable RuntimeErrors."""
        mock_home.return_value = tmp_path
        import os

        import pkcs11 as pkcs11_mod

        from wif_bunker.keystore.linux import _generate_cert_linux

        mock_lib = MagicMock()
        mock_pkcs11_lib.return_value = mock_lib

        # Token exists but session open fails with device error
        mock_token = MagicMock()
        mock_lib.get_token.return_value = mock_token

        # Cleanup session opens fine, generate session fails
        call_count = {"n": 0}

        def open_side_effect(**kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # Cleanup session - fine
                ctx = MagicMock()
                mock_session = MagicMock()
                mock_session.get_objects.return_value = []
                ctx.__enter__ = MagicMock(return_value=mock_session)
                ctx.__exit__ = MagicMock(return_value=False)
                return ctx
            # Generate session - device error
            raise pkcs11_mod.PKCS11Error("CKR_DEVICE_ERROR")

        mock_token.open.side_effect = open_side_effect

        with patch.dict(os.environ, clear=True), pytest.raises(RuntimeError, match="TPM device error"):
            _generate_cert_linux(config)


class TestWindowsKeystoreErrorPaths:
    @patch("wif_bunker.keystore.windows.ncrypt")
    @patch("wif_bunker.keystore.windows.require_commands")
    @patch("wif_bunker.keystore.windows.subprocess.run")
    def test_ncrypt_failure_raises(self, mock_run, mock_require, mock_ncrypt, config):
        from wif_bunker.keystore.windows import _generate_cert_windows

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        mock_ncrypt.delete_key.return_value = False
        mock_ncrypt.create_tpm_key.side_effect = RuntimeError("NCryptCreatePersistedKey failed: 0x80090020")

        with pytest.raises(RuntimeError, match="NCryptCreatePersistedKey"):
            _generate_cert_windows(config)


class TestMainModule:
    def test_main_module_calls_main(self):
        with patch("wif_bunker.cli.main") as mock_main:
            # We execute the __main__.py file
            import runpy

            runpy.run_module("wif_bunker.__main__", run_name="__main__")
            mock_main.assert_called_once()
