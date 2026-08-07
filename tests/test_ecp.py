import sys
from pathlib import Path

from wif_bunker.cert import _find_hardmtls_library, _get_hardmtls_lib_name


def test_hardmtls_lib_name_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert _get_hardmtls_lib_name() == "libhardmtls.so"


def test_hardmtls_lib_name_darwin(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert _get_hardmtls_lib_name() == "libhardmtls.dylib"


def test_hardmtls_lib_name_win32(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert _get_hardmtls_lib_name() == "hardmtls.dll"


def test_find_hardmtls_library_bundled(monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr("sys.platform", "linux")
    assert _find_hardmtls_library() is not None
