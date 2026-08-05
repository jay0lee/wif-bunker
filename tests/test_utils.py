import stat
import sys

import pytest

from wif_bunker.utils import preflight_check_write_access, write_secure_file


@pytest.fixture
def readonly_dir(tmp_path):
    d = tmp_path / "readonly"
    d.mkdir()
    d.chmod(0o444)
    yield d
    d.chmod(0o755)


class TestWriteSecureFile:
    def test_writes_content_to_file(self, tmp_path):
        filepath = tmp_path / "test.txt"
        write_secure_file(filepath, "hello world")
        assert filepath.read_text() == "hello world"

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not enforced on Windows")
    def test_creates_file_with_restricted_permissions(self, tmp_path):
        filepath = tmp_path / "test.txt"
        write_secure_file(filepath, "hello world")
        st = filepath.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not enforced on Windows")
    def test_permission_denied_raises_runtime_error(self, readonly_dir):
        filepath = readonly_dir / "test.txt"
        with pytest.raises(RuntimeError, match="Cannot write to"):
            write_secure_file(filepath, "hello world")

    def test_overwrites_existing_file(self, tmp_path):
        filepath = tmp_path / "test.txt"
        write_secure_file(filepath, "first")
        assert filepath.read_text() == "first"
        write_secure_file(filepath, "second")
        assert filepath.read_text() == "second"


class TestPreflightWriteAccess:
    def test_writable_directory_passes(self, tmp_path):
        preflight_check_write_access(tmp_path)

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not enforced on Windows")
    def test_readonly_directory_exits(self, readonly_dir):
        with pytest.raises(SystemExit):
            preflight_check_write_access(readonly_dir)

    def test_probe_file_cleaned_up(self, tmp_path):
        preflight_check_write_access(tmp_path)
        probe = tmp_path / ".wif-bunker-write-test"
        assert not probe.exists()
