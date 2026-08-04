"""Cross-cutting utilities: logging, retry decorator, secure file I/O, subprocess helpers."""

from __future__ import annotations

import logging
import os
import shutil
import sys
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

import requests

from wif_bunker.config import MAX_BACKOFF_SECONDS

logger = logging.getLogger(__name__)


# --- Unicode Detection ---
def _supports_unicode() -> bool:
    """Detect whether the terminal supports Unicode symbols."""
    if sys.platform == "win32":
        # Windows consoles use cp1252 by default. Only trust UTF-8 if the
        # console code page is 65001 or stdout is explicitly UTF-8.
        import ctypes

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
    # Non-Windows: GHA runners and most modern terminals support UTF-8
    if os.environ.get("GITHUB_ACTIONS"):
        return True
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


class _CleanFormatter(logging.Formatter):
    """Strips the level prefix from INFO messages for a cleaner CLI experience."""

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno == logging.INFO:
            return record.getMessage()
        return super().format(record)


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


def _require_command(name: str, *, package: str = "", install_hint: str = "") -> str:
    """Verify an external command is available on PATH.

    Returns the resolved path.  Raises RuntimeError with install
    instructions if the command is not found.
    """
    path = shutil.which(name)
    if path:
        return path
    msg = f"Required command '{name}' not found on PATH."
    if package:
        msg += f"\n  Package: {package}"
    if install_hint:
        msg += f"\n  Install: {install_hint}"
    raise RuntimeError(msg)


def require_commands(
    commands: list[tuple[str, str, str]],
) -> dict[str, str]:
    """Check all required commands upfront and report every missing one at once.

    Args:
        commands: List of (name, package, install_hint) tuples.

    Returns:
        Dict mapping command name to resolved path.

    Raises:
        RuntimeError: Lists *all* missing commands with install instructions.
    """
    found: dict[str, str] = {}
    missing: list[str] = []
    apt_packages: set[str] = set()

    for name, package, install_hint in commands:
        path = shutil.which(name)
        if path:
            found[name] = path
        else:
            line = f"  • {name}"
            if package:
                line += f"  (package: {package})"
                apt_packages.add(package)
            if install_hint:
                line += f"  — {install_hint}"
            missing.append(line)

    if missing:
        msg = f"Missing {len(missing)} required command(s):\n" + "\n".join(missing)
        if apt_packages:
            pkg_list = " ".join(sorted(apt_packages))
            msg += f"\n\nInstall all with:\n  sudo apt install {pkg_list}"
        raise RuntimeError(msg)

    return found
