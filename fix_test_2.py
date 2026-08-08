import re

with open("tests/test_ncrypt.py", "r") as f:
    content = f.read()

# Fix dll error
content = content.replace(
    'with patch("sys.modules") as mock_sys_modules:\n            # test on mac where ctypes exists but windll doesnt\n            from wif_bunker.keystore.ncrypt import _load_ctypes\n            with pytest.raises(RuntimeError, match="Could not load ncrypt.dll"):\n                _load_ctypes()',
    """import sys, types
        fake_ctypes = types.ModuleType("ctypes")
        fake_ctypes.wintypes = types.ModuleType("wintypes")
        sys.modules["ctypes"] = fake_ctypes
        sys.modules["ctypes.wintypes"] = fake_ctypes.wintypes
        
        try:
            from wif_bunker.keystore.ncrypt import _load_ctypes
            with pytest.raises(RuntimeError, match="Could not load ncrypt.dll"):
                _load_ctypes()
        finally:
            del sys.modules["ctypes"]
            del sys.modules["ctypes.wintypes"]""",
)

with open("tests/test_ncrypt.py", "w") as f:
    f.write(content)
