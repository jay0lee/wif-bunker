with open("tests/test_yubikey.py", "r") as f:
    text = f.read()

text = text.replace(
    'def side_effect(self_obj):\n            return str(self_obj) == _YUBIKEY_PKCS11_SEARCH_PATHS["linux"][0]\n        mock_exists.side_effect = side_effect',
    "mock_exists.return_value = True",
)

# add one more test for the exception
text += """
    @patch("sys.platform", "win32")
    @patch("wif_bunker.keystore.yubikey.yubikey_config_dir")
    def test_precache_exception(self, mock_dir):
        from wif_bunker.keystore.yubikey import precache_yubikey_pin_ncrypt
        import sys, types
        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.windll = types.ModuleType("windll")
        fake_ctypes.windll.ncrypt = MagicMock()
        fake_ctypes.windll.ncrypt.NCryptOpenStorageProvider.side_effect = Exception("error")
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
"""

with open("tests/test_yubikey.py", "w") as f:
    f.write(text)
