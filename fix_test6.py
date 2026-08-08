with open("tests/test_yubikey.py", "a") as f:
    f.write("""

class TestYubikeyRemaining:
    @patch("ykman.device.list_all_devices", create=True)
    def test_get_supported_no_devices(self, mock_list):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey
        mock_list.return_value = iter([])
        with pytest.raises(RuntimeError, match="No YubiKeys found"):
            get_supported_algorithms_yubikey()
            
    @patch("ykman.device.list_all_devices", create=True)
    def test_get_supported_multiple_devices(self, mock_list):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey
        d1, i1 = MagicMock(), MagicMock(serial=1234)
        d2, i2 = MagicMock(), MagicMock(serial=5678)
        mock_list.return_value = iter([(d1, i1), (d2, i2)])
        with pytest.raises(RuntimeError, match="Multiple YubiKeys found"):
            get_supported_algorithms_yubikey()
            
    @patch("ykman.device.list_all_devices", create=True)
    def test_get_supported_multiple_devices_serial(self, mock_list):
        from wif_bunker.keystore.yubikey import get_supported_algorithms_yubikey
        d1, i1 = MagicMock(), MagicMock(serial=1234, version=(5, 7, 0))
        d2, i2 = MagicMock(), MagicMock(serial=5678, version=(5, 4, 3))
        mock_list.return_value = iter([(d1, i1), (d2, i2)])
        algos = get_supported_algorithms_yubikey(serial=1234)
        assert "rsa4096" in algos
        
    def test_yubikey_config_path(self):
        from wif_bunker.keystore.yubikey import _yubikey_config_path
        with patch("wif_bunker.keystore.yubikey.yubikey_config_dir", return_value=Path("/tmp")):
            assert str(_yubikey_config_path(1234)) == str(Path("/tmp/yubikey_1234.json"))

    @patch("pathlib.Path.exists")
    @patch("sys.platform", "linux")
    def test_find_pkcs11_library_success(self, mock_exists):
        from wif_bunker.keystore.yubikey import find_pkcs11_library, _YUBIKEY_PKCS11_SEARCH_PATHS
        def side_effect(path):
            return path == _YUBIKEY_PKCS11_SEARCH_PATHS["linux"][0]
        mock_exists.side_effect = side_effect
        assert find_pkcs11_library() == _YUBIKEY_PKCS11_SEARCH_PATHS["linux"][0]

    @patch("wif_bunker.keystore.yubikey.find_pkcs11_library", return_value="libykcs11.so")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    @patch("subprocess.run")
    def test_build_ecp_pkcs11_config_exceptions(self, mock_run, mock_dir):
        from wif_bunker.keystore.yubikey import build_ecp_pkcs11_config
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.side_effect = Exception("error")
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        
        mock_run.side_effect = Exception("error")
        
        res = build_ecp_pkcs11_config(1234, "cn")
        assert res["pkcs11"]["user_pin"] == ""
        assert res["pkcs11"]["slot"] == "0"
        assert res["pkcs11"]["label"] == "X.509 Certificate for PIV Authentication"

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    def test_precache_empty_pin(self, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":""}'
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        assert precache_yubikey_pin_ncrypt(1234, "issuer") is False

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    def test_precache_open_provider_fail(self, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        import sys, types
        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.windll = types.ModuleType("windll")
        fake_ctypes.windll.ncrypt = MagicMock()
        fake_ctypes.windll.ncrypt.NCryptOpenStorageProvider.return_value = 1
        fake_ctypes.c_void_p = MagicMock
        fake_ctypes.byref = MagicMock()
        sys.modules["ctypes"] = fake_ctypes
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":"123"}'
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        
        try:
            assert precache_yubikey_pin_ncrypt(1234, "issuer") is False
        finally:
            del sys.modules["ctypes"]

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    @patch("subprocess.run")
    def test_precache_empty_key_name(self, mock_run, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        import sys, types
        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.windll = types.ModuleType("windll")
        fake_ctypes.windll.ncrypt = MagicMock()
        fake_ctypes.windll.ncrypt.NCryptOpenStorageProvider.return_value = 0
        fake_ctypes.c_void_p = MagicMock
        fake_ctypes.byref = MagicMock()
        sys.modules["ctypes"] = fake_ctypes
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":"123"}'
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        mock_run.return_value.stdout = ""
        
        try:
            assert precache_yubikey_pin_ncrypt(1234, "issuer") is False
        finally:
            del sys.modules["ctypes"]

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    @patch("subprocess.run")
    def test_precache_open_key_fail(self, mock_run, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        import sys, types
        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.windll = types.ModuleType("windll")
        fake_ctypes.windll.ncrypt = MagicMock()
        fake_ctypes.windll.ncrypt.NCryptOpenStorageProvider.return_value = 0
        fake_ctypes.windll.ncrypt.NCryptOpenKey.return_value = 1
        fake_ctypes.c_void_p = MagicMock
        fake_ctypes.byref = MagicMock()
        sys.modules["ctypes"] = fake_ctypes
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":"123"}'
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        mock_run.return_value.stdout = "key"
        
        try:
            assert precache_yubikey_pin_ncrypt(1234, "issuer") is False
        finally:
            del sys.modules["ctypes"]

    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    @patch("subprocess.run")
    def test_precache_set_property_fail(self, mock_run, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        import sys, types
        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.windll = types.ModuleType("windll")
        fake_ctypes.windll.ncrypt = MagicMock()
        fake_ctypes.windll.ncrypt.NCryptOpenStorageProvider.return_value = 0
        fake_ctypes.windll.ncrypt.NCryptOpenKey.return_value = 0
        fake_ctypes.windll.ncrypt.NCryptSetProperty.return_value = 1
        fake_ctypes.c_void_p = MagicMock
        fake_ctypes.byref = MagicMock()
        sys.modules["ctypes"] = fake_ctypes
        
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = '{"pin":"123"}'
        mock_dir.return_value = MagicMock(__truediv__=lambda s, k: mock_p)
        mock_run.return_value.stdout = "key"
        
        try:
            assert precache_yubikey_pin_ncrypt(1234, "issuer") is False
        finally:
            del sys.modules["ctypes"]
""")
