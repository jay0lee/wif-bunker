"""Tests for the --supported-algorithms feature across all keystores."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

# ── Linux: get_supported_algorithms_linux ──


class TestLinuxSupportedAlgorithms:
    """Tests for get_supported_algorithms_linux using mocked tpm2_testparms."""

    @patch("wif_bunker.keystore.linux.shutil.which", return_value="/usr/bin/tpm2_testparms")
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    @patch("wif_bunker.keystore.linux.subprocess.run")
    def test_all_algorithms_supported(self, mock_run, mock_check_tpm, mock_which):
        """All tpm2_testparms calls succeed → all Linux algos returned."""
        from wif_bunker.keystore.linux import get_supported_algorithms_linux

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        result = get_supported_algorithms_linux()
        assert "es256" in result
        assert "es384" in result
        assert "rsa2048" in result
        assert "rsa3072" in result
        assert "rsa4096" in result

    @patch("wif_bunker.keystore.linux.shutil.which", return_value="/usr/bin/tpm2_testparms")
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    @patch("wif_bunker.keystore.linux.subprocess.run")
    def test_intel_ptt_no_p384(self, mock_run, mock_check_tpm, mock_which):
        """Intel PTT: ecc384 probe fails, others pass → es384 excluded."""
        from wif_bunker.keystore.linux import get_supported_algorithms_linux

        def side_effect(cmd, **kwargs):
            # ecc384:ecdsa → fail (curve not supported)
            if "ecc384:ecdsa" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="curve not supported")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect

        result = get_supported_algorithms_linux()
        assert "es256" in result
        assert "es384" not in result
        assert "rsa2048" in result
        assert "rsa4096" in result

    @patch("wif_bunker.keystore.linux.shutil.which", return_value=None)
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    def test_no_tpm2_testparms_raises(self, mock_check_tpm, mock_which):
        """Missing tpm2_testparms binary raises RuntimeError."""
        from wif_bunker.keystore.linux import get_supported_algorithms_linux

        with pytest.raises(RuntimeError, match="tpm2_testparms not found"):
            get_supported_algorithms_linux()

    @patch("wif_bunker.keystore.linux.shutil.which", return_value="/usr/bin/tpm2_testparms")
    @patch("wif_bunker.keystore.linux._check_tpm_linux")
    @patch("wif_bunker.keystore.linux.subprocess.run")
    def test_swtpm_no_rsa4096(self, mock_run, mock_check_tpm, mock_which):
        """swtpm: rsa4096 probe fails → rsa4096 excluded."""
        from wif_bunker.keystore.linux import get_supported_algorithms_linux

        def side_effect(cmd, **kwargs):
            if "rsa4096" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect

        result = get_supported_algorithms_linux()
        assert "rsa4096" not in result
        assert "es256" in result
        assert "rsa2048" in result


# ── macOS: get_supported_algorithms_macos ──


class TestMacOSSupportedAlgorithms:
    """Tests for the macOS static algorithm list."""

    def test_returns_es256_and_es384(self):
        from wif_bunker.keystore.macos import get_supported_algorithms_macos

        result = get_supported_algorithms_macos()
        assert result == ["es256", "es384"]

    def test_no_rsa(self):
        from wif_bunker.keystore.macos import get_supported_algorithms_macos

        result = get_supported_algorithms_macos()
        assert not any(a.startswith("rsa") for a in result)


# ── Windows: ncrypt.test_algorithm ──


class TestNCryptTestAlgorithm:
    """Tests for ncrypt.test_algorithm using mocked ctypes."""

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_supported_algorithm_returns_true(self, mock_load):
        from wif_bunker.keystore.ncrypt import test_algorithm

        ctypes_mock = MagicMock()
        wintypes_mock = MagicMock()
        ncrypt_mock = MagicMock()

        # All NCrypt calls succeed (return 0)
        ncrypt_mock.NCryptOpenStorageProvider.return_value = 0
        ncrypt_mock.NCryptCreatePersistedKey.return_value = 0
        ncrypt_mock.NCryptFinalizeKey.return_value = 0
        ncrypt_mock.NCryptDeleteKey.return_value = 0

        mock_load.return_value = (ctypes_mock, wintypes_mock, ncrypt_mock)

        assert test_algorithm("ECDSA_P256") is True

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_unsupported_algorithm_returns_false(self, mock_load):
        from wif_bunker.keystore.ncrypt import test_algorithm

        ctypes_mock = MagicMock()
        wintypes_mock = MagicMock()
        ncrypt_mock = MagicMock()

        ncrypt_mock.NCryptOpenStorageProvider.return_value = 0
        ncrypt_mock.NCryptCreatePersistedKey.return_value = 0x80090029  # NTE_NOT_SUPPORTED
        # Ensure key_handle.value is falsy so cleanup doesn't try to free
        handle_mock = MagicMock()
        handle_mock.value = 0
        wintypes_mock.HANDLE.return_value = handle_mock

        mock_load.return_value = (ctypes_mock, wintypes_mock, ncrypt_mock)

        assert test_algorithm("ECDSA_P384") is False

    @patch("wif_bunker.keystore.ncrypt._load_ctypes")
    def test_finalize_failure_returns_false(self, mock_load):
        """TPM rejects at finalize (e.g. unsupported key length)."""
        from wif_bunker.keystore.ncrypt import test_algorithm

        ctypes_mock = MagicMock()
        wintypes_mock = MagicMock()
        ncrypt_mock = MagicMock()

        ncrypt_mock.NCryptOpenStorageProvider.return_value = 0
        ncrypt_mock.NCryptCreatePersistedKey.return_value = 0
        ncrypt_mock.NCryptSetProperty.return_value = 0
        ncrypt_mock.NCryptFinalizeKey.return_value = 0x80090020  # NTE_FAIL

        mock_load.return_value = (ctypes_mock, wintypes_mock, ncrypt_mock)

        assert test_algorithm("RSA", key_length=4096) is False


# ── Windows: get_supported_algorithms_windows ──


class TestWindowsSupportedAlgorithms:
    """Tests for get_supported_algorithms_windows with mocked probing."""

    @patch("wif_bunker.keystore.windows.ncrypt.test_algorithm", return_value=True)
    def test_all_supported_soft_key(self, mock_test):
        from wif_bunker.keystore.windows import get_supported_algorithms_windows

        result = get_supported_algorithms_windows(soft_key=True)
        assert "es256" in result
        assert "es384" in result
        assert "rsa2048" in result
        assert "rsa4096" in result

    @patch("wif_bunker.keystore.windows.ncrypt.test_algorithm")
    def test_tpm_excludes_unsupported(self, mock_test):
        from wif_bunker.keystore.windows import get_supported_algorithms_windows

        def side_effect(algo, key_length=None, soft_key=False):
            # Simulate TPM rejecting RSA4096
            return not (algo == "RSA" and key_length == 4096)

        mock_test.side_effect = side_effect

        result = get_supported_algorithms_windows(soft_key=False)
        assert "rsa4096" not in result
        assert "es256" in result


# ── YubiKey: get_supported_algorithms_yubikey ──


class TestYubiKeySupportedAlgorithms:
    """Tests for firmware-based algorithm detection."""

    @patch("ykman.device.list_all_devices")
    def test_fw_57_includes_rsa4096(self, mock_devices):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey

        info = MagicMock()
        info.serial = 12345678
        info.version = (5, 7, 1)
        mock_devices.return_value = [(MagicMock(), info)]

        result = get_supported_algorithms_yubikey()
        assert "es256" in result
        assert "es384" in result
        assert "rsa2048" in result
        assert "rsa4096" in result

    @patch("ykman.device.list_all_devices")
    def test_fw_56_excludes_rsa4096(self, mock_devices):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey

        info = MagicMock()
        info.serial = 12345678
        info.version = (5, 6, 0)
        mock_devices.return_value = [(MagicMock(), info)]

        result = get_supported_algorithms_yubikey()
        assert "rsa4096" not in result
        assert "es256" in result
        assert "rsa2048" in result

    @patch("ykman.device.list_all_devices")
    def test_no_yubikey_raises(self, mock_devices):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey

        mock_devices.return_value = []

        with pytest.raises(RuntimeError, match="No YubiKeys found"):
            get_supported_algorithms_yubikey()

    @patch("ykman.device.list_all_devices")
    def test_old_firmware_raises(self, mock_devices):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey

        info = MagicMock()
        info.serial = 12345678
        info.version = (4, 2, 0)
        mock_devices.return_value = [(MagicMock(), info)]

        with pytest.raises(RuntimeError, match="too old"):
            get_supported_algorithms_yubikey()

    @patch("ykman.device.list_all_devices")
    def test_serial_selection(self, mock_devices):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey

        info1 = MagicMock()
        info1.serial = 111
        info1.version = (5, 7, 0)
        info2 = MagicMock()
        info2.serial = 222
        info2.version = (5, 4, 0)
        mock_devices.return_value = [(MagicMock(), info1), (MagicMock(), info2)]

        # Select the fw 5.4 key → no rsa4096
        result = get_supported_algorithms_yubikey(serial=222)
        assert "rsa4096" not in result

        # Select the fw 5.7 key → has rsa4096
        result = get_supported_algorithms_yubikey(serial=111)
        assert "rsa4096" in result


# ── CLI dispatch: --supported-algorithms ──


class TestSupportedAlgorithmsCLI:
    """Tests for the --supported-algorithms CLI flag dispatch."""

    @patch("wif_bunker.cli._run_supported_algorithms")
    @patch("sys.argv", ["wif-bunker", "--supported-algorithms"])
    def test_flag_dispatches_to_handler(self, mock_run):
        from wif_bunker.cli import _main_impl

        _main_impl()
        mock_run.assert_called_once()

    @patch("wif_bunker.cli._run_supported_algorithms")
    @patch("sys.argv", ["wif-bunker", "--supported-algorithms", "--debug"])
    def test_verbose_mode(self, mock_run):
        from wif_bunker.cli import _main_impl

        _main_impl()
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs["verbose"] is True

    @patch("sys.argv", ["wif-bunker", "--supported-algorithms", "--cert-only"])
    def test_mutually_exclusive_with_cert_only(self):
        from wif_bunker.cli import _main_impl

        with pytest.raises(SystemExit) as exc_info:
            _main_impl()
        assert exc_info.value.code == 2


# ── _run_supported_algorithms mode function ──


class TestRunSupportedAlgorithmsMode:
    """Tests for the _run_supported_algorithms mode function."""

    @patch("sys.platform", "darwin")
    @patch("wif_bunker.keystore.macos.get_supported_algorithms_macos", return_value=["es256", "es384"])
    def test_macos_output(self, mock_probe, capsys):
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms()
        captured = capsys.readouterr()
        assert "es256\n" in captured.out
        assert "es384\n" in captured.out

    @patch("sys.platform", "darwin")
    @patch("wif_bunker.keystore.macos.get_supported_algorithms_macos", return_value=["es256", "es384"])
    def test_verbose_output_shows_keystore(self, mock_probe, capsys):
        from wif_bunker.modes import _run_supported_algorithms

        _run_supported_algorithms(verbose=True)
        captured = capsys.readouterr()
        assert "Keystore: macOS Secure Enclave" in captured.out
        assert "es256" in captured.out
