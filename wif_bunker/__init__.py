"""WIF Bunker — Hardware-backed X.509 Workload Identity Federation (ADC)."""

from __future__ import annotations

__version__ = "dev"  # Replaced by build process with datetime version

# Tell cryptography to skip loading the OpenSSL legacy provider.
# On OpenSSL 4.x the legacy provider doesn't exist — that's expected
# and desirable.  Without this, cryptography emits a warning from its
# Rust/C extension at import time, before any Python warnings filter
# can intercept it.
import os

os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

from wif_bunker.cli import main  # noqa: F401 — entrypoint  # pylint: disable=cyclic-import
