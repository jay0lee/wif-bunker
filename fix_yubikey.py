import re

with open("tests/test_yubikey.py", "a") as f:
    f.write("""

class TestYubikeyUncovered:
    @patch("ykman.device.list_all_devices", create=True)
    def test_get_supported_algorithms_yubikey_target_not_found(self, mock_list):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey
        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = iter([(dev, info)])
        with pytest.raises(RuntimeError, match="not found"):
            get_supported_algorithms_yubikey(serial=9999)

    @patch("ykman.device.list_all_devices", create=True)
    def test_get_supported_algorithms_yubikey_firmware_too_old(self, mock_list):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey
        dev, info = MagicMock(), MagicMock(serial=1234, version=(4, 2, 0))
        mock_list.return_value = iter([(dev, info)])
        with pytest.raises(RuntimeError, match="too old"):
            get_supported_algorithms_yubikey()

    def test_yubikey_config_dir(self):
        from wif_bunker.keystore.yubikey import yubikey_config_dir
        with patch("sys.platform", "win32"), patch("os.environ.get", return_value="C:\\temp"):
            assert str(yubikey_config_dir()) == "C:\\temp\\wif-bunker"
        with patch("sys.platform", "linux"), patch("os.environ.get", return_value="/temp"):
            assert str(yubikey_config_dir()) == "/temp/wif-bunker"

    @patch("ykman.device.list_all_devices", create=True)
    def test_generate_cert_serial_not_found(self, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey
        dev, info = MagicMock(), MagicMock(serial=1234)
        mock_list.return_value = iter([(dev, info)])
        config.yubikey_serial = 9999
        with pytest.raises(RuntimeError, match="not found"):
            generate_cert_yubikey(config)

    @patch("ykman.device.list_all_devices", create=True)
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    def test_generate_cert_firmware_warning(self, mock_piv, mock_conn, mock_list, config, caplog):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey
        dev, info = MagicMock(), MagicMock(serial=1234, version=(4, 3, 0))
        mock_list.return_value = iter([(dev, info)])
        config.yubikey_serial = 1234
        
        # force exception to abort early
        config.key_algorithm = "invalid"
        with pytest.raises(RuntimeError):
            generate_cert_yubikey(config)
        assert "firmware < 5.0.0" in caplog.text

    @patch("ykman.device.list_all_devices", create=True)
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    @patch("wif_bunker.keystore.yubikey._yubikey_config_path")
    def test_generate_cert_no_file(self, mock_path, mock_piv, mock_conn, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey
        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = iter([(dev, info)])
        
        piv = mock_piv.return_value
        piv.authenticate.side_effect = Exception("not default")
        
        mock_p = MagicMock()
        mock_p.exists.return_value = False
        mock_path.return_value = mock_p
        
        with pytest.raises(RuntimeError, match="no credential config file"):
            generate_cert_yubikey(config)

    @patch("ykman.device.list_all_devices", create=True)
    @patch("yubikit.core.smartcard.SmartCardConnection", create=True)
    @patch("yubikit.piv.PivSession", create=True)
    @patch("wif_bunker.keystore.yubikey._yubikey_config_path")
    def test_generate_cert_invalid_slot(self, mock_path, mock_piv, mock_conn, mock_list, config):
        from wif_bunker.keystore.yubikey import generate_cert_yubikey
        dev, info = MagicMock(), MagicMock(serial=1234, version=(5, 4, 3))
        mock_list.return_value = iter([(dev, info)])
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":"123", "management_key":"aabbcc"}'
        mock_path.return_value = mock_p
        
        config.yubikey_slot = "invalid"
        
        with pytest.raises(RuntimeError, match="Invalid YubiKey slot"):
            generate_cert_yubikey(config)

    @patch("os.environ.get", return_value="fake_path")
    @patch("pathlib.Path.exists")
    def test_find_pkcs11_env(self, mock_exists):
        mock_exists.return_value = True
        from wif_bunker.keystore.yubikey import find_pkcs11_library
        assert find_pkcs11_library() == "fake_path"
        
        mock_exists.return_value = False
        with pytest.raises(FileNotFoundError):
            find_pkcs11_library()

    @patch("os.environ.get", return_value=None)
    @patch("pathlib.Path.exists", return_value=False)
    @patch("sys.platform", "win32")
    def test_find_pkcs11_win32_fail(self, mock_exists, mock_env):
        from wif_bunker.keystore.yubikey import find_pkcs11_library
        with pytest.raises(FileNotFoundError, match="Smart Card Minidriver"):
            find_pkcs11_library()
            
    @patch("os.environ.get", return_value=None)
    @patch("pathlib.Path.exists", return_value=False)
    @patch("sys.platform", "darwin")
    def test_find_pkcs11_darwin_fail(self, mock_exists, mock_env):
        from wif_bunker.keystore.yubikey import find_pkcs11_library
        with pytest.raises(FileNotFoundError, match="yubico-piv-tool"):
            find_pkcs11_library()
            
    @patch("os.environ.get", return_value=None)
    @patch("pathlib.Path.exists", return_value=False)
    @patch("sys.platform", "linux")
    def test_find_pkcs11_linux_fail(self, mock_exists, mock_env):
        from wif_bunker.keystore.yubikey import find_pkcs11_library
        with pytest.raises(FileNotFoundError, match="opensc"):
            find_pkcs11_library()

    @patch("wif_bunker.keystore.yubikey.find_pkcs11_library", return_value="opensc.so")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    @patch("subprocess.run")
    def test_build_ecp_pkcs11_config(self, mock_run, mock_dir):
        from wif_bunker.keystore.yubikey import build_ecp_pkcs11_config
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":"123"}'
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        
        mock_run.return_value.stdout = "Slot 12 (0x123)\nCertificate for PIV Authentication"
        
        res = build_ecp_pkcs11_config(1234, "cn")
        assert res["pkcs11"]["user_pin"] == "123"
        assert res["pkcs11"]["slot"] == "123"
        assert res["pkcs11"]["label"] == "Certificate for PIV Authentication"

    def test_precache_yubikey_pin_ncrypt_not_win32(self):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        with patch("sys.platform", "linux"):
            assert precache_yubikey_pin_ncrypt(1234, "issuer") is False

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    def test_precache_no_config(self, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        mock_p = MagicMock()
        mock_p.exists.return_value = False
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        assert precache_yubikey_pin_ncrypt(1234, "issuer") is False

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    def test_precache_bad_config(self, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.side_effect = Exception("error")
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        assert precache_yubikey_pin_ncrypt(1234, "issuer") is False
        
    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    @patch("subprocess.run")
    def test_precache_full(self, mock_run, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        import sys, types
        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.windll = types.ModuleType("windll")
        fake_ctypes.windll.ncrypt = MagicMock()
        fake_ctypes.windll.ncrypt.NCryptOpenStorageProvider.return_value = 0
        fake_ctypes.windll.ncrypt.NCryptOpenKey.return_value = 0
        fake_ctypes.windll.ncrypt.NCryptSetProperty.return_value = 0
        
        # mock ctypes.c_void_p to return an object with an empty list for fields?
        fake_ctypes.c_void_p = MagicMock
        fake_ctypes.byref = MagicMock()
        
        sys.modules["ctypes"] = fake_ctypes
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":"123"}'
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        
        mock_run.return_value.stdout = "key_name"
        
        try:
            assert precache_yubikey_pin_ncrypt(1234, "issuer") is True
        finally:
            del sys.modules["ctypes"]
""")
