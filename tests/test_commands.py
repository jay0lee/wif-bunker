import subprocess

import pytest

from wif_bunker.keystore.linux import _check_tpm_linux
from wif_bunker.utils import _require_command, require_commands

# ---------------------------------------------------------------------------
# _require_command (legacy, single-command helper)
# ---------------------------------------------------------------------------


def test_require_command_found(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/" + x)
    assert _require_command("mycmd") == "/usr/bin/mycmd"


def test_require_command_not_found(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: None)
    with pytest.raises(RuntimeError):
        _require_command("mycmd")


# ---------------------------------------------------------------------------
# require_commands (batch helper)
# ---------------------------------------------------------------------------


def test_require_commands_all_found(monkeypatch):
    """When every command is on PATH, returns a dict mapping name → path."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/" + x)
    result = require_commands(
        [
            ("git", "git", "sudo apt install git"),
            ("curl", "curl", "sudo apt install curl"),
        ]
    )
    assert result == {"git": "/usr/bin/git", "curl": "/usr/bin/curl"}


def test_require_commands_some_missing_raises(monkeypatch):
    """When some commands are missing, raises RuntimeError listing all of them."""

    def fake_which(name):
        return "/usr/bin/git" if name == "git" else None

    monkeypatch.setattr("shutil.which", fake_which)
    with pytest.raises(RuntimeError, match="Missing 2 required command") as exc_info:
        require_commands(
            [
                ("git", "git", ""),
                ("tpm2_ptool", "tpm2-tools", "sudo apt install tpm2-tools"),
                ("certtool", "gnutls-bin", "sudo apt install gnutls-bin"),
            ]
        )
    msg = str(exc_info.value)
    assert "tpm2_ptool" in msg
    assert "certtool" in msg
    # git should NOT appear in the error since it was found
    assert "git" not in msg


def test_require_commands_empty_list():
    """An empty command list should succeed and return an empty dict."""
    result = require_commands([])
    assert result == {}


# ---------------------------------------------------------------------------
# _check_tpm_linux
# ---------------------------------------------------------------------------


def test_check_tpm_linux_devnode_exists(monkeypatch):
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True)
    monkeypatch.setattr("os.access", lambda path, mode: True)
    _check_tpm_linux()


def test_check_tpm_linux_no_tpm_raises(monkeypatch):
    monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
    monkeypatch.setattr("os.environ.get", lambda x: None)

    def mock_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", mock_run)
    with pytest.raises(RuntimeError):
        _check_tpm_linux()
