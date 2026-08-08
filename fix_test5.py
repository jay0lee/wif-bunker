with open("tests/test_yubikey.py", "r") as f:
    text = f.read()

text = text.replace('"C:\\\\temp"', '"C:/temp"').replace('"C:\\temp"', '"C:/temp"')
text = text.replace(
    'res = build_ecp_pkcs11_config(1234, "cn")',
    'res = build_ecp_pkcs11_config(1234, "Certificate for PIV Authentication")',
)

with open("tests/test_yubikey.py", "w") as f:
    f.write(text)
