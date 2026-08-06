"""Platform-specific hardware keystore certificate generators."""

from __future__ import annotations

import logging
import sys

from wif_bunker.config import CertificateBundle, WorkloadConfig

logger = logging.getLogger(__name__)


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

    if sys.platform.startswith("win32"):
        from wif_bunker.keystore.windows import _generate_cert_windows  # pylint: disable=import-outside-toplevel

        return _generate_cert_windows(config)
    if sys.platform.startswith("darwin"):
        from wif_bunker.keystore.macos import _generate_cert_macos  # pylint: disable=import-outside-toplevel

        return _generate_cert_macos(config)
    if sys.platform.startswith("linux"):
        from wif_bunker.keystore.linux import _generate_cert_linux  # pylint: disable=import-outside-toplevel

        return _generate_cert_linux(config)

    raise OSError(f"Unsupported Operating System: {sys.platform}")
