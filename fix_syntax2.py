with open("tests/test_yubikey.py", "r") as f:
    text = f.read()

text = text.replace(
    '        mock_run.return_value.stdout = "Slot 12 (0x123)\\n\nCertificate for PIV Authentication"',
    '        mock_run.return_value.stdout = "Slot 12 (0x123)\\nCertificate for PIV Authentication"',
)
text = text.replace(
    'mock_run.return_value.stdout = "Slot 12 (0x123)\nCertificate for PIV Authentication"',
    'mock_run.return_value.stdout = "Slot 12 (0x123)\\nCertificate for PIV Authentication"',
)

with open("tests/test_yubikey.py", "w") as f:
    f.write(text)
