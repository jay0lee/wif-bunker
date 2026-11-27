"""Cross-cutting utilities: logging, retry decorator, secure file I/O, and redaction."""

from __future__ import annotations

import ctypes
import logging
import os
import re
import sys
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Default retry backoff cap (re-exported by wif_bunker.config to keep utils a leaf module)
MAX_BACKOFF_SECONDS = 60


# --- Unicode Detection ---
def _supports_unicode() -> bool:
    """Detect whether the terminal supports Unicode symbols."""
    # For frozen PyInstaller builds, PYTHONIOENCODING is ignored and stdout
    # uses the console's native encoding (e.g. cp1252 on Windows).  Always
    # verify that we can actually encode a representative symbol.
    try:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        "\u2713".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    # GHA runners on all platforms (including Windows under bash) support UTF-8
    if os.environ.get("GITHUB_ACTIONS"):
        return True
    if sys.platform == "win32":
        # Windows consoles use cp1252 by default. Only trust UTF-8 if the
        # console code page is 65001 or stdout is explicitly UTF-8.
        try:
            cp = ctypes.windll.kernel32.GetConsoleOutputCP()
            if cp == 65001:
                return True
        except (AttributeError, OSError):
            pass
        try:
            return bool(sys.stdout.encoding and sys.stdout.encoding.lower().startswith("utf"))
        except AttributeError:
            return False
    try:
        return bool(sys.stdout.encoding and sys.stdout.encoding.lower().startswith("utf"))
    except AttributeError:
        return False


_UNICODE = _supports_unicode()
SYM_OK = "\u2705" if _UNICODE else "[OK]"
SYM_WARN = "\u26a0\ufe0f " if _UNICODE else "[!!]"
SYM_FAIL = "\u274c" if _UNICODE else "[FAIL]"
SYM_ARROW = "\u2192" if _UNICODE else "->"
SYM_CHECK = "\u2713" if _UNICODE else "[ok]"
SYM_CROSS = "\u2717" if _UNICODE else "[X]"


# --- Credential Redaction ---
_REDACT_ENABLED = True
_REDACTED = "***REDACTED***"

# Patterns that match sensitive credential values
_TOKEN_PATTERNS = [
    # JSON: "access_token": "ya29.xxx" or "access_token":"ya29.xxx"
    re.compile(r'("access_token"\s*:\s*")([^"]+)(")', re.IGNORECASE),
    # JSON: "id_token": "eyJ..."
    re.compile(r'("id_token"\s*:\s*")([^"]+)(")', re.IGNORECASE),
    # JSON: "refresh_token": "1//xxx"
    re.compile(r'("refresh_token"\s*:\s*")([^"]+)(")', re.IGNORECASE),
    # URL query param: access_token=ya29.xxx (terminated by & or end-of-string)
    re.compile(r"(access_token=)([^&\s]+)", re.IGNORECASE),
]


def set_redaction(enabled: bool) -> None:
    """Enable or disable credential redaction in log output."""
    global _REDACT_ENABLED
    _REDACT_ENABLED = enabled


def redact_tokens(text: str) -> str:
    """Redact bearer tokens and credentials from a string.

    Replaces access_token, id_token, and refresh_token values in JSON
    bodies and URL query parameters with ``***REDACTED***``.

    Redaction is enabled by default and can be disabled with
    ``set_redaction(False)`` (triggered by ``--no-redact`` CLI flag).
    """
    if not _REDACT_ENABLED:
        return text
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(rf"\g<1>{_REDACTED}\g<3>" if pattern.groups == 3 else rf"\g<1>{_REDACTED}", text)
    return text


def yubikey_not_found_hint() -> str:
    """Return platform-specific troubleshooting advice for YubiKey detection."""
    if sys.platform == "linux":
        return "Ensure the YubiKey is plugged in and the pcscd service is running (sudo systemctl restart pcscd)."
    if sys.platform == "darwin":
        return (
            "Ensure the YubiKey is plugged in. Try removing and re-inserting it, "
            "or check System Settings > Privacy & Security for USB device access."
        )
    if sys.platform == "win32":
        return (
            "Ensure the YubiKey is plugged in and the Smart Card service is running "
            "(services.msc > 'Smart Card' > Start)."
        )
    return "Ensure the YubiKey is plugged in."


class _CleanFormatter(logging.Formatter):
    """Strips the level prefix from INFO messages and redacts credentials.

    Redaction is applied to **all** log output, including messages from
    third-party libraries (e.g. ``urllib3`` logging full URLs with
    ``access_token=`` query parameters at DEBUG level).
    """

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno == logging.INFO:
            msg = record.getMessage()
        else:
            msg = super().format(record)
        return redact_tokens(msg)


# --- Pythonic Retry & File Helpers ---
def with_retries(
    max_attempts: int = 25,
    expected_errors: tuple[int, ...] = (403, 404),
    custom_error_text: str | None = None,
    retryable_exceptions: tuple[type[Exception], ...] = (),
    retry_msg: str = "Waiting for propagation",
) -> Callable:
    """Decorator that retries on expected HTTP errors with capped exponential backoff.

    Also retries on any exception type listed in *retryable_exceptions*.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions:
                    if attempt < max_attempts - 1:
                        sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
                        logger.info(
                            "    %s (%d/%d), %ds...",
                            retry_msg,
                            attempt + 1,
                            max_attempts,
                            sleep_time,
                        )
                        time.sleep(sleep_time)
                        continue
                    raise
                except requests.exceptions.HTTPError as exc:
                    status = exc.response.status_code
                    body = exc.response.text
                    is_expected_status = status in expected_errors
                    is_custom_error = custom_error_text and custom_error_text in body
                    if (is_expected_status or is_custom_error) and attempt < max_attempts - 1:
                        sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
                        logger.info(
                            "    %s (%d/%d), %ds...",
                            retry_msg,
                            attempt + 1,
                            max_attempts,
                            sleep_time,
                        )
                        time.sleep(sleep_time)
                        continue
                    # Final attempt or unexpected error — log full detail.
                    logger.error(
                        "HTTP %d from %s FAILED after %d attempts — %s",
                        status,
                        func.__name__,
                        attempt + 1,
                        body,
                    )
                    raise

        return wrapper

    return decorator


def write_secure_file(filepath: Path | str, content: str) -> None:
    """Writes a file to disk enforcing strictly locked down 0600 permissions."""
    filepath = Path(filepath)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        with os.fdopen(os.open(filepath, flags, mode), "w") as out:
            out.write(content)
    except PermissionError as exc:
        raise RuntimeError(
            f"Cannot write to '{filepath}'.\n"
            f"  Directory: {filepath.parent}\n"
            f"  Error: {exc}\n\n"
            "You may not have write permission to the current directory.\n"
            "Try running from a directory you own, for example:\n"
            "  cd %USERPROFILE%\\Desktop && wif-bunker ...  (Windows)\n"
            "  cd ~/Desktop && wif-bunker ...                (macOS/Linux)"
        ) from exc


def preflight_check_write_access(directory: Path) -> None:
    """Verify we can write files to *directory* before starting long-running work.

    Creates and immediately removes a temporary probe file.  Raises
    ``SystemExit`` with a clear message if the directory is not writable.
    """
    probe = directory / ".wif-bunker-write-test"
    try:
        probe.write_text("probe", encoding="utf-8")
        probe.unlink()
    except PermissionError:
        logger.error("")
        logger.error("ERROR: Cannot write to the current directory.")
        logger.error("  Directory: %s", directory)
        logger.error("")
        logger.error("wif-bunker needs to write configuration files (bunker.json,")
        logger.error("adc.json) to the current directory. Please cd to a writable")
        logger.error("location first:")
        logger.error("")
        logger.error("  Windows:    cd %%USERPROFILE%%\\Desktop && wif-bunker ...")
        logger.error("  macOS:      cd ~/Desktop && wif-bunker ...")
        logger.error("  Linux:      cd ~/Desktop && wif-bunker ...")
        logger.error("")
        raise SystemExit(1) from None
