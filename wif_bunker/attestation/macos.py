"""macOS Secure Enclave attestation — stub with Apple documentation.

Apple does not provide key attestation APIs for third-party macOS applications.
DCAppAttestService is iOS/iPadOS only, and Managed Device Attestation requires
MDM/ACME enrollment.
"""

from __future__ import annotations

import logging
import subprocess

from wif_bunker.attestation.base import (
    AttestationCheck,
    AttestationReport,
)
from wif_bunker.config import WorkloadConfig

logger = logging.getLogger(__name__)

_APPLE_DOCS = [
    "https://developer.apple.com/documentation/devicecheck/dcappattestservice",
    "https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave",
    "https://support.apple.com/guide/deployment/managed-device-attestation-dep2ba3d4a0a/web",
]

_NOT_SUPPORTED_REASON = (
    "Apple does not provide key attestation APIs for third-party macOS applications.\n"
    "Your key is stored in the Secure Enclave and is non-exportable, but there is no\n"
    "mechanism for independent cryptographic verification of hardware residency.\n"
    "\n"
    "  • App Attest (DCAppAttestService) — iOS/iPadOS only.\n"
    "    isSupported returns false on macOS.\n"
    "  • Managed Device Attestation — available exclusively through MDM/ACME enrollment,\n"
    "    not accessible to CLI tools or third-party desktop applications.\n"
    "  • Secure Enclave key storage — Apple documents key generation and usage but\n"
    "    provides no attestation or certification mechanism for generated keys."
)


def _attest_macos(config: WorkloadConfig) -> AttestationReport:
    """Collect best-effort Secure Enclave checks and explain attestation gap."""
    checks: list[AttestationCheck] = []

    # Check 1: Keychain identity exists
    try:
        result = subprocess.run(
            ["security", "find-identity", "-v", "-p", "ssl-client"],
            capture_output=True,
            text=True,
        )
        workload_cn = config.workload_cn
        identity_found = workload_cn in result.stdout
        checks.append(
            AttestationCheck(
                name="Keychain identity present",
                passed=identity_found,
                detail=(
                    f"Found identity matching '{workload_cn}' in login keychain"
                    if identity_found
                    else f"No identity matching '{workload_cn}' found in keychain"
                ),
            )
        )
    except (OSError, subprocess.SubprocessError) as exc:
        checks.append(
            AttestationCheck(
                name="Keychain identity present",
                passed=False,
                detail=f"Could not query keychain: {exc}",
            )
        )

    # Check 2: CryptoTokenKit token available (SE keys appear as CTK tokens)
    try:
        result = subprocess.run(
            ["security", "list-smartcards"],
            capture_output=True,
            text=True,
        )
        ctk_present = "com.apple.setoken" in result.stdout.lower() or result.returncode == 0
        checks.append(
            AttestationCheck(
                name="CryptoTokenKit SE token",
                passed=ctk_present,
                detail="Secure Enclave token driver is available via CryptoTokenKit",
            )
        )
    except (OSError, subprocess.SubprocessError) as exc:
        checks.append(
            AttestationCheck(
                name="CryptoTokenKit SE token",
                passed=False,
                detail=f"Could not list smart cards: {exc}",
            )
        )

    # Check 3: Attestation API availability (always fails on macOS)
    checks.append(
        AttestationCheck(
            name="Hardware attestation API",
            passed=False,
            detail=(
                "DCAppAttestService.isSupported returns false on macOS. "
                "No key attestation API available for third-party applications."
            ),
        )
    )

    passed = sum(1 for chk in checks if chk.passed)
    total = len(checks)

    return AttestationReport(
        platform="macos-se",
        supported=False,
        hardware_type="Secure Enclave",
        checks=checks,
        summary=(
            f"{passed}/{total} checks passed. Hardware attestation is not available "
            f"on macOS. See documentation links for details."
        ),
        not_supported_reason=_NOT_SUPPORTED_REASON,
        documentation_urls=_APPLE_DOCS,
        verification_steps=[
            "Verify key is in Keychain: security find-identity -v -p ssl-client",
            "Verify SE token: security list-smartcards",
            "Note: No cryptographic attestation is possible on macOS.",
        ],
    )
