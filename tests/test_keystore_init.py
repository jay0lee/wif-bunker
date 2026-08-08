import importlib
from unittest.mock import MagicMock, patch

import pytest

from wif_bunker.config import WorkloadConfig


@pytest.fixture
def config():
    cfg = MagicMock(spec=WorkloadConfig)
    cfg.use_yubikey = False
    return cfg


def test_import_win32():
    with patch("sys.platform", "win32"):
        import wif_bunker.keystore

        importlib.reload(wif_bunker.keystore)
        assert "win32" in wif_bunker.keystore._KEYSTORE_GENERATORS


def test_import_linux():
    with patch("sys.platform", "linux"):
        import wif_bunker.keystore

        importlib.reload(wif_bunker.keystore)
        assert "linux" in wif_bunker.keystore._KEYSTORE_GENERATORS


def test_import_darwin():
    with patch("sys.platform", "darwin"):
        import wif_bunker.keystore

        importlib.reload(wif_bunker.keystore)
        assert "darwin" in wif_bunker.keystore._KEYSTORE_GENERATORS


def test_unsupported_os(config):
    with patch("sys.platform", "unknown_os"):
        import wif_bunker.keystore

        importlib.reload(wif_bunker.keystore)
        with pytest.raises(OSError, match="Unsupported Operating System"):
            wif_bunker.keystore.generate_os_keystore_cert(config)


def test_yubikey(config):
    config.use_yubikey = True
    import wif_bunker.keystore

    with patch("wif_bunker.keystore.yubikey.generate_cert_yubikey") as mock_yubikey:
        wif_bunker.keystore.generate_os_keystore_cert(config)
        mock_yubikey.assert_called_once_with(config)


def test_generate_os_keystore_cert_success(config):
    with patch("sys.platform", "darwin"):
        import wif_bunker.keystore

        importlib.reload(wif_bunker.keystore)
        with patch.dict(wif_bunker.keystore._KEYSTORE_GENERATORS, {"darwin": MagicMock()}):
            wif_bunker.keystore.generate_os_keystore_cert(config)
            wif_bunker.keystore._KEYSTORE_GENERATORS["darwin"].assert_called_once_with(config)
