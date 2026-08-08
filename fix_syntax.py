with open("tests/test_yubikey.py", "r") as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if "mock_run.return_value.stdout =" in line and "Slot" in line:
        lines[i] = '        mock_run.return_value.stdout = "Slot 12 (0x123)\\nCertificate for PIV Authentication"\n'
    if "mock_run.return_value.stdout =" in line and "Slot" not in line:
        pass  # this is fine
    if 'assert str(yubikey_config_dir()) == "C:\\temp\\wif-bunker"' in line:
        lines[i] = '            assert str(yubikey_config_dir()) == "C:\\\\temp\\\\wif-bunker"\n'
    # Wait, the error was "unterminated string literal", there's an actual newline in the file?
with open("tests/test_yubikey.py", "w") as f:
    f.writelines(lines)
