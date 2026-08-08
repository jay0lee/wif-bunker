import re

with open("tests/test_ncrypt.py", "r") as f:
    content = f.read()

# Fix dll error
content = content.replace(
    'with patch("ctypes.windll") as mock_windll:\n            del mock_windll.ncrypt',
    'with patch("sys.modules") as mock_sys_modules:\n            # test on mac where ctypes exists but windll doesnt',
)

# Fix test_algorithm_exception
content = content.replace(
    'mock_load.side_effect = Exception("error")',
    'mock_ctypes, mock_wintypes, mock_ncrypt = MagicMock(), MagicMock(), MagicMock()\n        mock_load.return_value = (mock_ctypes, mock_wintypes, mock_ncrypt)\n        mock_ncrypt.NCryptOpenStorageProvider.side_effect = Exception("error")',
)

with open("tests/test_ncrypt.py", "w") as f:
    f.write(content)
