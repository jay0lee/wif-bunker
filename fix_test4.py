import re

with open("tests/test_yubikey.py", "r") as f:
    text = f.read()

# fix test_find_pkcs11_env signature
text = text.replace(
    "def test_find_pkcs11_env(self, mock_exists):", "def test_find_pkcs11_env(self, mock_exists, mock_env):"
)

# fix test_build_ecp_pkcs11_config signature
text = text.replace(
    "def test_build_ecp_pkcs11_config(self, mock_run, mock_dir):",
    "def test_build_ecp_pkcs11_config(self, mock_run, mock_dir, mock_find):",
)

# fix test_yubikey_config_dir
text = text.replace(
    'assert str(yubikey_config_dir()) == "C:\\\\temp\\\\wif-bunker"',
    'assert str(yubikey_config_dir()) == str(Path("C:\\\\temp") / "wif-bunker")',
)

with open("tests/test_yubikey.py", "w") as f:
    f.write(text)
