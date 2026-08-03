import subprocess
import sys
from pathlib import Path

from wif_bunker import __version__


def test_version_exists():
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_version_flag():
    repo_root = Path(__file__).parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "wif_bunker", "--version"], capture_output=True, text=True, cwd=str(repo_root)
    )
    assert result.returncode == 0
    assert __version__ in result.stdout or result.stdout.strip() != ""
