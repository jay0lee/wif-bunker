"""WIF Bunker — Hardware-backed X.509 Workload Identity Federation (ADC)."""

from __future__ import annotations

__version__ = "dev"  # Replaced by build process with datetime version

# Suppress "OpenSSL 3's legacy provider failed to load" warning.
# On OpenSSL 4.x the legacy provider doesn't exist — that's expected
# and desirable, not something to warn users about.
import warnings

warnings.filterwarnings("ignore", message=r".*legacy provider.*", category=UserWarning)

from wif_bunker.cli import main  # noqa: F401 — entrypoint  # pylint: disable=cyclic-import
