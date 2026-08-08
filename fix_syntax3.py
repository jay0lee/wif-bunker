with open("tests/test_yubikey.py", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if 'Certificate for PIV Authentication"' in line and "mock_run" not in line:
        pass  # this is the trailing line, skip
    elif "mock_run.return_value.stdout" in line and "Slot 12" in line:
        new_lines.append(
            '        mock_run.return_value.stdout = "Slot 12 (0x123)\\nCertificate for PIV Authentication"\n'
        )
    else:
        new_lines.append(line)

with open("tests/test_yubikey.py", "w") as f:
    f.writelines(new_lines)
