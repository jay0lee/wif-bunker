import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from wif_bunker.config import CertificateBundle, WorkloadConfig


@pytest.fixture
def config():
    cfg = MagicMock(spec=WorkloadConfig)
    cfg.workload_cn = "test-bunker"
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
    @patch("wif_bunker.keystore.macos._require_command")
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
    @patch("wif_bunker.keystore.macos._require_command")
    def test_version_check_rejects_old_macos(self, mock_require, mock_mac_ver, config):
        from wif_bunker.keystore.macos import _generate_cert_macos

        mock_mac_ver.return_value = ("14.0",)

        with pytest.raises(RuntimeError, match="macOS 15\\+"):
            _generate_cert_macos(config)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    @patch("wif_bunker.keystore.macos._create_ca_and_sign")
    @patch("wif_bunker.keystore.macos.platform.mac_ver")
    @patch("wif_bunker.keystore.macos._require_command")
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
    @patch("wif_bunker.keystore.macos._require_command")
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


class TestLinuxKeystoreFlow:
    @patch("socket.socket")
    @patch("wif_bunker.keystore.linux.subprocess.run")
    def test_secret_tool_lookup_fallback(self, mock_run, mock_socket):
        # We test that _check_tpm_linux falls back to the socket if systemctl fails
        import os

        from wif_bunker.keystore.linux import _check_tpm_linux

        # Simulate no /dev/tpmrm0
        with (
            patch("wif_bunker.keystore.linux.Path.exists", return_value=False),
            patch.dict(os.environ, clear=True),
        ):
            # Systemctl fails with FileNotFoundError (e.g. simulating command not found)
            mock_run.side_effect = FileNotFoundError()

            # Socket connects successfully
            mock_sock_instance = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock_instance

            # Should not raise an exception
            _check_tpm_linux()

            # Verify systemctl was attempted
            mock_run.assert_called_with(
                ["systemctl", "is-active", "--quiet", "tpm2-abrmd"], capture_output=True, timeout=5
            )
            # Verify socket fallback was attempted
            mock_sock_instance.connect.assert_called_with(("127.0.0.1", 2321))

    @patch("wif_bunker.keystore.linux.Path.home")
    @patch("wif_bunker.keystore.linux._require_command")
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    @patch("wif_bunker.keystore.linux.subprocess.run")
    @patch("wif_bunker.keystore.linux.write_secure_file")
    @patch("wif_bunker.keystore.linux._create_ca_and_sign")
    def test_tpm2_ptool_addkey_extracts_id(
        self, mock_ca, mock_write, mock_run, mock_check, mock_require, mock_home, config, tmp_path
    ):
        mock_home.return_value = tmp_path
        import os
        from pathlib import Path

        from wif_bunker.keystore.linux import _generate_cert_linux

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "tpm2_ptool" and cmd[1] == "addkey":
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="some output\nCKA_ID '0xABCD'\n")
            if cmd[0] == "certtool":
                Path("bunker-workload-selfsigned.pem").write_text("fake pem")
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

        with patch.dict(os.environ, clear=True):
            _generate_cert_linux(config)

        # Verify addcert was called with the extracted key-id
        addcert_call = [
            c for c in mock_run.call_args_list if c.args[0][0] == "tpm2_ptool" and c.args[0][1] == "addcert"
        ]
        assert len(addcert_call) > 0
        assert "--key-id=0xABCD" in addcert_call[0].args[0]

    @patch("wif_bunker.keystore.linux.Path.home")
    @patch("wif_bunker.keystore.linux._require_command")
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    @patch("wif_bunker.keystore.linux.subprocess.run")
    @patch("wif_bunker.keystore.linux.write_secure_file")
    @patch("wif_bunker.keystore.linux._create_ca_and_sign")
    def test_tpm2_ptool_addkey_no_id_raises(
        self, mock_ca, mock_write, mock_run, mock_check, mock_require, mock_home, config, tmp_path
    ):
        mock_home.return_value = tmp_path
        import os
        from pathlib import Path

        from wif_bunker.keystore.linux import _generate_cert_linux

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "tpm2_ptool" and cmd[1] == "addkey":
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="no id here\n")
            if cmd[0] == "certtool":
                Path("bunker-workload-selfsigned.pem").write_text("fake pem")
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

        with patch.dict(os.environ, clear=True), pytest.raises(RuntimeError, match="Could not extract CKA_ID"):
            _generate_cert_linux(config)


class TestWindowsKeystoreErrorPaths:
    @patch("wif_bunker.keystore.windows.ncrypt")
    @patch("wif_bunker.keystore.windows._require_command")
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
