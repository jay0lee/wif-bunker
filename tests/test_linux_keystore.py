import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pkcs11 import Attribute, KeyType, ObjectClass, PKCS11Error
from pkcs11.exceptions import NoSuchToken

from wif_bunker.keystore.linux import (
    _check_tpm_linux,
    _cleanup_existing_token,
    _ensure_token_via_tpm2_ptool,
    _extract_public_key_pem,
    _find_key_objects,
    _find_pkcs11_lib,
    _generate_cert_linux,
    _handle_pkcs11_error,
    _init_token,
    _query_p11kit,
    _run_pkcs11_tool_keygen,
    get_supported_algorithms_linux,
)


@pytest.fixture
def mock_pkcs11_lib():
    with patch("wif_bunker.keystore.linux.pkcs11.lib") as m:
        yield m


def test_find_pkcs11_lib_env_var(tmp_path):
    lib_path = tmp_path / "libtpm2_pkcs11.so"
    lib_path.touch()
    with patch.dict(os.environ, {"TPM2_PKCS11_MODULE": str(lib_path)}):
        assert _find_pkcs11_lib() == str(lib_path)


def test_find_pkcs11_lib_p11kit(tmp_path):
    lib_path = tmp_path / "libtpm2_pkcs11.so"
    lib_path.touch()
    with patch("wif_bunker.keystore.linux._query_p11kit", return_value=str(lib_path)):
        with patch.dict(os.environ, clear=True):
            assert _find_pkcs11_lib() == str(lib_path)


def test_find_pkcs11_lib_well_known(tmp_path):
    with patch("wif_bunker.keystore.linux._query_p11kit", return_value=None), patch.dict(os.environ, clear=True):
        with patch("wif_bunker.keystore.linux._PKCS11_LIB_PATHS", [str(tmp_path / "lib")]):
            lib = tmp_path / "lib"
            lib.touch()
            assert _find_pkcs11_lib() == str(lib)


def test_find_pkcs11_lib_not_found():
    with patch("wif_bunker.keystore.linux._query_p11kit", return_value=None), patch.dict(os.environ, clear=True):
        with patch("wif_bunker.keystore.linux._PKCS11_LIB_PATHS", []):
            with pytest.raises(RuntimeError, match="Could not find libtpm2_pkcs11.so"):
                _find_pkcs11_lib()


def test_query_p11kit():
    with patch("shutil.which", return_value="/usr/bin/p11-kit"), patch("subprocess.run") as m_run:
        m_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="module: /fake/path/libtpm2_pkcs11.so"
        )
        with patch("pathlib.Path.exists", return_value=True):
            assert _query_p11kit() == "/fake/path/libtpm2_pkcs11.so"

        m_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="")
        assert _query_p11kit() is None

        m_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=5)
        assert _query_p11kit() is None

        m_run.side_effect = OSError()
        assert _query_p11kit() is None

    with patch("shutil.which", return_value=None):
        assert _query_p11kit() is None


def test_check_tpm_linux_dev_access_ok():
    with patch("wif_bunker.keystore.linux.Path.exists", return_value=True), patch("os.access", return_value=True):
        _check_tpm_linux()  # should not raise


@pytest.mark.skipif(sys.platform == "win32", reason="pwd/grp modules are Unix-only")
def test_check_tpm_linux_dev_access_denied():
    with patch("wif_bunker.keystore.linux.Path.exists", return_value=True), patch("os.access", return_value=False):
        with patch("pwd.getpwuid") as m_pwd, patch("grp.getgrgid") as m_grp, patch("grp.getgrall") as m_grall:
            m_pwd.return_value.pw_name = "testuser"
            m_grp.return_value.gr_name = "tss"
            mock_group = MagicMock()
            mock_group.gr_name = "other"
            mock_group.gr_mem = ["testuser"]
            m_grall.return_value = [mock_group]
            with patch("os.getuid", return_value=1000), patch("pathlib.Path.stat") as m_stat:
                m_stat.return_value.st_gid = 123
                with pytest.raises(RuntimeError, match="not accessible by user"):
                    _check_tpm_linux()


@pytest.mark.skipif(sys.platform == "win32", reason="pwd/grp modules are Unix-only")
def test_check_tpm_linux_dev_access_denied_except():
    with patch("wif_bunker.keystore.linux.Path.exists", return_value=True), patch("os.access", return_value=False):
        with patch("pwd.getpwuid") as m_pwd, patch("grp.getgrgid") as m_grp:
            m_pwd.return_value.pw_name = "testuser"
            m_grp.side_effect = KeyError()
            with patch("os.getuid", return_value=1000), patch("pathlib.Path.stat"):
                with pytest.raises(RuntimeError, match="not accessible by user"):
                    _check_tpm_linux()


def test_check_tpm_linux_no_dev_tcti():
    with patch("wif_bunker.keystore.linux.Path.exists", return_value=False):
        with patch.dict(os.environ, {"TPM2TOOLS_TCTI": "swtpm:..."}):
            _check_tpm_linux()  # should not raise


def test_check_tpm_linux_no_dev_no_tcti_socket_err():
    with patch("wif_bunker.keystore.linux.Path.exists", return_value=False), patch.dict(os.environ, clear=True):
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.__enter__.return_value.connect.side_effect = ConnectionRefusedError()
            with pytest.raises(RuntimeError, match="No TPM device found"):
                _check_tpm_linux()


def test_get_supported_algorithms_linux_slots_found(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_pkcs11_lib.return_value = mock_lib

    mock_slot = MagicMock()
    mock_lib.get_slots.return_value = [mock_slot]
    from pkcs11 import Mechanism

    mock_slot.get_mechanisms.return_value = [Mechanism.ECDSA, Mechanism.RSA_PKCS]

    mock_mech_info = MagicMock()
    mock_mech_info.min_key_length = 256
    mock_mech_info.max_key_length = 256
    mock_slot.get_mechanism_info.return_value = mock_mech_info

    with patch("wif_bunker.keystore.linux._check_tpm_linux"), patch("wif_bunker.keystore.linux._find_pkcs11_lib"):
        supported = get_supported_algorithms_linux()
        assert "es256" in supported


def test_get_supported_algorithms_linux_no_slots(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_pkcs11_lib.return_value = mock_lib
    mock_lib.get_slots.return_value = []

    with patch("wif_bunker.keystore.linux._check_tpm_linux"), patch("wif_bunker.keystore.linux._find_pkcs11_lib"):
        with pytest.raises(RuntimeError, match="No PKCS#11 slots available"):
            get_supported_algorithms_linux()


def test_get_supported_algorithms_linux_error(mock_pkcs11_lib):
    mock_pkcs11_lib.side_effect = PKCS11Error("error")
    with patch("wif_bunker.keystore.linux._check_tpm_linux"), patch("wif_bunker.keystore.linux._find_pkcs11_lib"):
        with pytest.raises(RuntimeError, match="Could not query PKCS#11"):
            get_supported_algorithms_linux()


def test_get_supported_algorithms_linux_mech_range(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_pkcs11_lib.return_value = mock_lib
    mock_slot = MagicMock()
    mock_lib.get_slots.return_value = [mock_slot]
    from pkcs11 import Mechanism

    mock_slot.get_mechanisms.return_value = [Mechanism.ECDSA]

    mock_mech_info = MagicMock()
    mock_mech_info.min_key_length = 384  # 256 is out of bounds
    mock_mech_info.max_key_length = 512
    mock_slot.get_mechanism_info.return_value = mock_mech_info

    with patch("wif_bunker.keystore.linux._check_tpm_linux"), patch("wif_bunker.keystore.linux._find_pkcs11_lib"):
        supported = get_supported_algorithms_linux()
        assert "es256" not in supported


def test_get_supported_algorithms_linux_mech_query_err(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_pkcs11_lib.return_value = mock_lib
    mock_slot = MagicMock()
    mock_lib.get_slots.return_value = [mock_slot]
    from pkcs11 import Mechanism

    mock_slot.get_mechanisms.return_value = [Mechanism.ECDSA]

    mock_slot.get_mechanism_info.side_effect = PKCS11Error()

    with patch("wif_bunker.keystore.linux._check_tpm_linux"), patch("wif_bunker.keystore.linux._find_pkcs11_lib"):
        supported = get_supported_algorithms_linux()
        # If query fails, assumes supported
        assert "es256" in supported


def test_cleanup_existing_token_success(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_token = MagicMock()
    mock_session = MagicMock()
    mock_obj = MagicMock()

    mock_lib.get_token.return_value = mock_token
    mock_token.open.return_value.__enter__.return_value = mock_session
    mock_session.get_objects.return_value = [mock_obj]

    _cleanup_existing_token(mock_lib, "pin")
    mock_obj.destroy.assert_called_once()


def test_cleanup_existing_token_no_token(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_lib.get_token.side_effect = NoSuchToken()
    _cleanup_existing_token(mock_lib, "pin")  # should not raise


def test_cleanup_existing_token_error_destroy(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_token = MagicMock()
    mock_session = MagicMock()
    mock_obj = MagicMock()

    mock_lib.get_token.return_value = mock_token
    mock_token.open.return_value.__enter__.return_value = mock_session
    mock_session.get_objects.return_value = [mock_obj]
    mock_obj.destroy.side_effect = PKCS11Error("destroy error")

    _cleanup_existing_token(mock_lib, "pin")  # should ignore


def test_cleanup_existing_token_error_open(mock_pkcs11_lib):
    mock_lib = MagicMock()
    mock_token = MagicMock()

    mock_lib.get_token.return_value = mock_token
    mock_token.open.side_effect = PKCS11Error("open error")

    _cleanup_existing_token(mock_lib, "pin")  # should ignore


def test_ensure_token_via_tpm2_ptool():
    with patch("shutil.which", return_value="/bin/tpm2_ptool"), patch("subprocess.run") as m_run:
        m_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="bunker-wif", stderr=""),  # list-token-slots
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),  # rmtoken
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),  # addtoken
        ]
        _ensure_token_via_tpm2_ptool("pin", "/store", "/lib")
        assert m_run.call_count == 3


def test_ensure_token_via_tpm2_ptool_addtoken_fail():
    with patch("shutil.which", return_value="/bin/tpm2_ptool"), patch("subprocess.run") as m_run:
        m_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),  # list-token-slots
            subprocess.CalledProcessError(returncode=1, cmd=[], stderr="error"),  # addtoken
        ]
        with pytest.raises(RuntimeError, match="Failed to create PKCS#11 token"):
            _ensure_token_via_tpm2_ptool("pin", "/store", "/lib")


def test_ensure_token_via_tpm2_ptool_no_tool():
    with patch("shutil.which", return_value=None):
        _ensure_token_via_tpm2_ptool("pin", "/store", "/lib")  # should just return


def test_init_token():
    mock_lib = MagicMock()
    _init_token(mock_lib, "pin", "/lib")
    mock_lib.get_token.assert_called_with(token_label="bunker-wif")


def test_init_token_fail():
    mock_lib = MagicMock()
    mock_lib.get_token.side_effect = NoSuchToken()
    with pytest.raises(RuntimeError, match="PKCS#11 token 'bunker-wif' not found"):
        _init_token(mock_lib, "pin", "/lib")


def test_extract_public_key_pem_ec():
    mock_pub = MagicMock()
    mock_pub.key_type = KeyType.EC
    real_key = ec.generate_private_key(ec.SECP384R1())
    real_point = real_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    mock_pub.__getitem__.side_effect = lambda k: (
        bytes([0x04, len(real_point)]) + real_point if k == Attribute.EC_POINT else None
    )
    pem = _extract_public_key_pem(mock_pub)
    assert "BEGIN PUBLIC KEY" in pem


def test_extract_public_key_pem_ec_raw():
    mock_pub = MagicMock()
    mock_pub.key_type = KeyType.EC
    real_key = ec.generate_private_key(ec.SECP256R1())
    real_point = real_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    # direct point
    mock_pub.__getitem__.side_effect = lambda k: real_point if k == Attribute.EC_POINT else None
    pem = _extract_public_key_pem(mock_pub)
    assert "BEGIN PUBLIC KEY" in pem


def test_extract_public_key_pem_ec_invalid():
    mock_pub = MagicMock()
    mock_pub.key_type = KeyType.EC
    mock_pub.__getitem__.side_effect = lambda k: b"\x04\x11fake" if k == Attribute.EC_POINT else None
    with pytest.raises(RuntimeError, match="Unexpected EC point length"):
        _extract_public_key_pem(mock_pub)


def test_extract_public_key_pem_rsa():
    mock_pub = MagicMock()
    mock_pub.key_type = KeyType.RSA
    mock_pub.__getitem__.side_effect = lambda k: b"\x01\x00\x01" if k == Attribute.PUBLIC_EXPONENT else b"\x02" * 256
    pem = _extract_public_key_pem(mock_pub)
    assert "BEGIN PUBLIC KEY" in pem


def test_extract_public_key_pem_invalid():
    mock_pub = MagicMock()
    mock_pub.key_type = KeyType.DSA
    with pytest.raises(RuntimeError, match="Unsupported PKCS#11 key type"):
        _extract_public_key_pem(mock_pub)


def test_run_pkcs11_tool_keygen():
    with patch("subprocess.run") as m_run:
        m_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="done", stderr="")
        _run_pkcs11_tool_keygen("/lib", "label", "pin", "EC:prime256v1", "cn")
        m_run.assert_called_once()


def test_run_pkcs11_tool_keygen_fail():
    with patch("subprocess.run") as m_run:
        m_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd=[], stderr="error", output="")
        with pytest.raises(RuntimeError, match="pkcs11-tool --keypairgen failed"):
            _run_pkcs11_tool_keygen("/lib", "label", "pin", "EC:prime256v1", "cn")


def test_find_key_objects():
    mock_session = MagicMock()
    mock_pub = MagicMock()
    mock_pub.__getitem__.side_effect = lambda k: ObjectClass.PUBLIC_KEY
    mock_priv = MagicMock()
    mock_priv.__getitem__.side_effect = lambda k: ObjectClass.PRIVATE_KEY
    mock_session.get_objects.return_value = [mock_pub, mock_priv]
    pub, priv = _find_key_objects(mock_session, "label")
    assert pub == mock_pub
    assert priv == mock_priv


def test_find_key_objects_not_found():
    mock_session = MagicMock()
    mock_session.get_objects.return_value = []
    with pytest.raises(RuntimeError, match="Key pair not found"):
        _find_key_objects(mock_session, "label")


def test_handle_pkcs11_error():
    with pytest.raises(RuntimeError, match="TPM PKCS#11 token not recognized"):
        _handle_pkcs11_error(PKCS11Error("CKR_TOKEN_NOT_RECOGNIZED"))
    with pytest.raises(RuntimeError, match="TPM device error"):
        _handle_pkcs11_error(PKCS11Error("CKR_DEVICE_ERROR"))
    with pytest.raises(RuntimeError, match="PKCS#11 PIN incorrect"):
        _handle_pkcs11_error(PKCS11Error("CKR_PIN_INCORRECT"))
    with pytest.raises(RuntimeError, match="PKCS#11 operation failed"):
        _handle_pkcs11_error(PKCS11Error("OTHER_ERROR"))


@pytest.fixture
def linux_config():
    cfg = MagicMock()
    cfg.linux_tpm_pin = "pin"
    cfg.key_algo_config = {"linux_tpm2": "ecc256"}
    cfg.workload_cn = "cn"
    return cfg


def test_generate_cert_linux_unsupported_algo(linux_config):
    linux_config.key_algo_config = {"linux_tpm2": "unsupported"}
    with patch("wif_bunker.keystore.linux._check_tpm_linux"):
        with patch("wif_bunker.keystore.linux._find_pkcs11_lib", return_value="/lib"):
            with pytest.raises(RuntimeError, match="Unsupported algorithm for Linux TPM"):
                _generate_cert_linux(linux_config)


def test_generate_cert_linux_ecc384(linux_config, mock_pkcs11_lib):
    linux_config.key_algo_config = {"linux_tpm2": "ecc384"}

    mock_lib = MagicMock()
    mock_pkcs11_lib.return_value = mock_lib
    mock_token = MagicMock()
    mock_lib.get_token.return_value = mock_token
    mock_session = MagicMock()
    mock_token.open.return_value.__enter__.return_value = mock_session

    with patch("wif_bunker.keystore.linux._check_tpm_linux"):
        with patch("wif_bunker.keystore.linux._find_pkcs11_lib", return_value="/lib"):
            with patch("wif_bunker.keystore.linux._ensure_token_via_tpm2_ptool"):
                with patch("wif_bunker.keystore.linux._run_pkcs11_tool_keygen") as m_keygen:
                    with patch("wif_bunker.keystore.linux._find_key_objects") as m_find:
                        mock_pub = MagicMock()
                        mock_pub.__getitem__.side_effect = lambda k: b"id" if k == Attribute.ID else None
                        m_find.return_value = (mock_pub, MagicMock())
                        with patch("wif_bunker.keystore.linux._extract_public_key_pem", return_value="pem"):
                            with patch("wif_bunker.keystore.linux._create_ca_and_sign") as m_sign:
                                m_sign.return_value = ("bundle", _make_fake_workload_pem())
                                bundle = _generate_cert_linux(linux_config)
                                assert bundle == "bundle"
                                m_keygen.assert_called_with(
                                    module_path="/lib",
                                    token_label="bunker-wif",
                                    pin="pin",
                                    key_type="EC:secp384r1",
                                    label="cn",
                                )


def test_generate_cert_linux_rsa2048(linux_config, mock_pkcs11_lib):
    linux_config.key_algo_config = {"linux_tpm2": "rsa2048"}

    mock_lib = MagicMock()
    mock_pkcs11_lib.return_value = mock_lib
    mock_token = MagicMock()
    mock_lib.get_token.return_value = mock_token
    mock_session = MagicMock()
    mock_token.open.return_value.__enter__.return_value = mock_session

    with patch("wif_bunker.keystore.linux._check_tpm_linux"):
        with patch("wif_bunker.keystore.linux._find_pkcs11_lib", return_value="/lib"):
            with patch("wif_bunker.keystore.linux._ensure_token_via_tpm2_ptool"):
                with patch("wif_bunker.keystore.linux._run_pkcs11_tool_keygen") as m_keygen:
                    with patch("wif_bunker.keystore.linux._find_key_objects") as m_find:
                        mock_pub = MagicMock()
                        mock_pub.__getitem__.side_effect = lambda k: b"id" if k == Attribute.ID else None
                        m_find.return_value = (mock_pub, MagicMock())
                        with patch("wif_bunker.keystore.linux._extract_public_key_pem", return_value="pem"):
                            with patch("wif_bunker.keystore.linux._create_ca_and_sign") as m_sign:
                                m_sign.return_value = ("bundle", _make_fake_workload_pem())
                                bundle = _generate_cert_linux(linux_config)
                                assert bundle == "bundle"
                                m_keygen.assert_called_with(
                                    module_path="/lib",
                                    token_label="bunker-wif",
                                    pin="pin",
                                    key_type="RSA:2048",
                                    label="cn",
                                )


def _make_fake_workload_pem():
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
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_generate_cert_linux_pkcs11_error(linux_config, mock_pkcs11_lib):
    mock_pkcs11_lib.side_effect = PKCS11Error("CKR_DEVICE_ERROR")
    with patch("wif_bunker.keystore.linux._check_tpm_linux"):
        with patch("wif_bunker.keystore.linux._find_pkcs11_lib", return_value="/lib"):
            with patch("wif_bunker.keystore.linux._ensure_token_via_tpm2_ptool"):
                with patch("wif_bunker.keystore.linux._run_pkcs11_tool_keygen"):
                    with pytest.raises(RuntimeError, match="TPM device error"):
                        _generate_cert_linux(linux_config)
