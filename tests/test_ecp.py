import platform
import sys
from pathlib import Path

from get_ecp import get_default_ecp_dir, get_ecp_binary_names, get_ecp_platform_info
from wif_bunker import _find_ecp_binaries


def test_platform_info_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    assert get_ecp_platform_info() == ("linux", "amd64", ".so", ".tar.gz")


def test_platform_info_darwin(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(platform, "machine", lambda: "arm64")
    assert get_ecp_platform_info() == ("darwin", "arm64", ".dylib", ".tar.gz")


def test_platform_info_win32(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(platform, "machine", lambda: "AMD64")
    assert get_ecp_platform_info() == ("windows", "amd64", ".dll", ".zip")


def test_binary_names_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    assert get_ecp_binary_names() == ("ecp", "libecp.so", "libtls_offload.so")


def test_binary_names_darwin(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(platform, "machine", lambda: "arm64")
    assert get_ecp_binary_names() == ("ecp", "libecp.dylib", "libtls_offload.dylib")


def test_binary_names_win32(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(platform, "machine", lambda: "AMD64")
    # get_ecp.py code says tls_offload.dll, but test prompt said tls_offload.dll
    assert get_ecp_binary_names() == ("ecp.exe", "libecp.dll", "tls_offload.dll")


def test_default_ecp_dir_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: Path("/home/test"))
    assert str(get_default_ecp_dir()) == "/home/test/.config/bunker-ecp"


def test_find_ecp_binaries_bundled(monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    assert _find_ecp_binaries() is not None
