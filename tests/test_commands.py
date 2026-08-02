import subprocess

import pytest

from wif_bunker import _check_tpm_linux, _require_command


def test_require_command_found(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/" + x)
    assert _require_command("mycmd") == "/usr/bin/mycmd"


def test_require_command_not_found(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: None)
    with pytest.raises(RuntimeError):
        _require_command("mycmd")


def test_check_tpm_linux_devnode_exists(monkeypatch):
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True)
    _check_tpm_linux()


def test_check_tpm_linux_no_tpm_raises(monkeypatch):
    monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
    monkeypatch.setattr("os.environ.get", lambda x: None)

    def mock_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", mock_run)
    with pytest.raises(RuntimeError):
        _check_tpm_linux()
