with open("tests/test_yubikey.py", "r") as f:
    text = f.read()

text = text.replace("def side_effect(path):", "def side_effect(self_obj):")
text = text.replace(
    'return path == _YUBIKEY_PKCS11_SEARCH_PATHS["linux"][0]',
    'return str(self_obj) == _YUBIKEY_PKCS11_SEARCH_PATHS["linux"][0]',
)
text = text.replace(
    "def test_build_ecp_pkcs11_config_exceptions(self, mock_run, mock_dir):",
    "def test_build_ecp_pkcs11_config_exceptions(self, mock_run, mock_dir, mock_find):",
)

with open("tests/test_yubikey.py", "w") as f:
    f.write(text)
