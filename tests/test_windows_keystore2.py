import subprocess
from unittest.mock import MagicMock, patch

import pytest

from wif_bunker.config import WorkloadConfig
from wif_bunker.keystore.windows import _generate_cert_windows, get_supported_algorithms_windows


@pytest.fixture
def config():
    cfg = MagicMock(spec=WorkloadConfig)
    cfg.workload_cn = "test-bunker"
    cfg.key_algo_config = {
        "ncrypt_algo": "ECDSA_P256",
        "ncrypt_key_length": None,
    }
    cfg.soft_key = False
    return cfg


def test_get_supported_algorithms_windows():
    with patch("wif_bunker.keystore.ncrypt.test_algorithm", return_value=True):
        algos = get_supported_algorithms_windows()
        assert "es256" in algos
        # tests line 47 continue
        assert "macos_algo" not in algos


def test_generate_cert_windows_success(config):
    config.soft_key = True  # to cover line 103
    with patch("wif_bunker.keystore.windows.require_commands"), patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="1\n", stderr="")
        with patch("wif_bunker.keystore.windows.ncrypt") as mock_ncrypt:
            mock_ncrypt.MS_SOFTWARE_KSP = "soft"
            mock_ncrypt.create_tpm_key.return_value = "handle"
            mock_ncrypt.export_public_key_pem.return_value = "pem"
            with patch("wif_bunker.keystore.windows._create_ca_and_sign") as mock_ca:
                mock_ca.return_value = ("bundle", _make_fake_workload_pem())
                bundle = _generate_cert_windows(config)
                assert bundle == "bundle"


def test_generate_cert_windows_verify_fails(config):
    with patch("wif_bunker.keystore.windows.require_commands"), patch("subprocess.run") as mock_run:
        # First run is cleanup, second is verify which fails
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="0\n", stderr=""),
        ]
        with patch("wif_bunker.keystore.windows.ncrypt") as mock_ncrypt:
            mock_ncrypt.create_tpm_key.return_value = "handle"
            mock_ncrypt.export_public_key_pem.return_value = "pem"
            with patch("wif_bunker.keystore.windows._create_ca_and_sign") as mock_ca:
                mock_ca.return_value = ("bundle", _make_fake_workload_pem())
                with pytest.raises(RuntimeError, match="Workload cert was not found"):
                    _generate_cert_windows(config)


def test_generate_cert_windows_called_process_error(config):
    with patch("wif_bunker.keystore.windows.require_commands"), patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd=[], stderr="error", output="out")
        with patch("wif_bunker.keystore.windows.ncrypt"):
            with pytest.raises(RuntimeError, match="Windows certificate generation failed"):
                _generate_cert_windows(config)


def test_generate_cert_windows_exception(config):
    with patch("wif_bunker.keystore.windows.require_commands"):
        with patch("subprocess.run", side_effect=Exception("generic error")):
            with patch("wif_bunker.keystore.windows.ncrypt"):
                with pytest.raises(RuntimeError, match="Windows certificate generation failed: generic error"):
                    _generate_cert_windows(config)


def _make_fake_workload_pem():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
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
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_get_supported_algorithms_windows_skip():
    from wif_bunker.config import _KEY_ALGORITHMS

    with patch.dict(_KEY_ALGORITHMS, {"fake": {"platforms": ["linux"]}}):
        with patch("wif_bunker.keystore.ncrypt.test_algorithm", return_value=True):
            algos = get_supported_algorithms_windows()
            assert "fake" not in algos
