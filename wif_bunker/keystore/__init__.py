"""Platform-specific hardware keystore certificate generators."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable

from wif_bunker.config import CertificateBundle, WorkloadConfig

logger = logging.getLogger(__name__)

# Conditional top-level imports: only the current platform's module is loaded.
# This avoids importing platform-specific native deps (pkcs11, ncrypt, etc.)
# on the wrong OS while keeping imports visible to PyInstaller and debuggers.
if sys.platform.startswith("win32"):
    from wif_bunker.keystore.windows import _generate_cert_windows
elif sys.platform.startswith("darwin"):
    from wif_bunker.keystore.macos import _generate_cert_macos
elif sys.platform.startswith("linux"):
    from wif_bunker.keystore.linux import _generate_cert_linux

_KEYSTORE_GENERATORS: dict[str, Callable[[WorkloadConfig], CertificateBundle]] = {}
if sys.platform.startswith("win32"):
    _KEYSTORE_GENERATORS["win32"] = _generate_cert_windows
elif sys.platform.startswith("darwin"):
    _KEYSTORE_GENERATORS["darwin"] = _generate_cert_macos
elif sys.platform.startswith("linux"):
    _KEYSTORE_GENERATORS["linux"] = _generate_cert_linux


def generate_os_keystore_cert(config: WorkloadConfig) -> CertificateBundle:
    """Dispatches to the platform-specific hardware keystore generator.

    Each generator:
      1. Creates a hardware-backed key (SE/TPM/YubiKey)
      2. Generates an ephemeral CA (software, in-memory)
      3. Signs a workload cert with the CA (same public key as the HW key)
      4. Installs the CA-signed cert back into the OS keystore
      5. Returns the CA cert PEM (trust anchor) + CA CN (for ECP config)
    """
    if config.use_yubikey:
        from wif_bunker.keystore.yubikey import generate_cert_yubikey  # pylint: disable=import-outside-toplevel

        logger.info("Instructing YubiKey to generate non-exportable hardware-backed certificate...")
        return generate_cert_yubikey(config)

    logger.info("Instructing OS to generate non-exportable hardware-backed certificate...")
    for platform_prefix, generator in _KEYSTORE_GENERATORS.items():
        if sys.platform.startswith(platform_prefix):
            return generator(config)
    raise OSError(f"Unsupported Operating System: {sys.platform}")
