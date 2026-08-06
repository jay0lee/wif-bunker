"""YubiKey PIV attestation module.

Provides verification of hardware residency using YubiKey PIV attestation.

.. ai-note::
   IMPORTANT FOR AI AGENTS: Before reading, editing, or debugging this file,
   you MUST read docs/attestation-yubikey.md in the repository root.
   That document covers the PIV attestation flow, certificate chain structure
   (legacy vs new 5.7.4+ chains), Yubico OID extensions, import vs generate
   detection, and firmware version gates.  If you make changes to this file,
   update docs/attestation-yubikey.md to match.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from wif_bunker.attestation.base import (
    AttestationArtifact,
    AttestationCheck,
    AttestationReport,
)

if TYPE_CHECKING:
    from wif_bunker.config import WorkloadConfig

logger = logging.getLogger(__name__)


def _get_slot(slot_str: str):
    """Map a string like '9a' to the Yubikit PIV SLOT enum."""
    from yubikit.piv import SLOT

    mapping = {
        "9a": SLOT.AUTHENTICATION,
        "9c": SLOT.SIGNATURE,
        "9d": SLOT.KEY_MANAGEMENT,
        "9e": SLOT.CARD_AUTH,
    }
    return mapping.get(slot_str.lower(), SLOT.AUTHENTICATION)


def _verify_yubico_chain(attest_cert: cx509.Certificate, f9_cert: cx509.Certificate) -> AttestationCheck:
    """Verify that the attestation cert chains to the Yubico Root CA.

    Supports both legacy 2-level chains (Root → F9 → attest) and newer
    multi-level chains (Root → Intermediate B1 → PIV B1 → F9 → attest)
    introduced in firmware 5.7.4+.
    """
    # Find roots dir
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        roots_dir = Path(sys._MEIPASS) / "wif_bunker" / "attestation" / "roots" / "yubico"
    else:
        roots_dir = Path(__file__).parent / "roots" / "yubico"

    if not roots_dir.exists() or not any(roots_dir.glob("*.pem")):
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail="No Yubico root CA certificates bundled. Chain verification skipped.",
        )

    all_certs = []
    for pem_file in sorted(roots_dir.glob("*.pem")):
        try:
            all_certs.append(cx509.load_pem_x509_certificate(pem_file.read_bytes()))
        except Exception:
            pass

    if not all_certs:
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail="Could not load Yubico root certificates.",
        )

    def _verify_signature(issuer_cert: cx509.Certificate, subject_cert: cx509.Certificate) -> bool:
        """Verify subject_cert was signed by issuer_cert."""
        pub = issuer_cert.public_key()
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    subject_cert.signature_hash_algorithm,
                )
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    ec.ECDSA(subject_cert.signature_hash_algorithm),
                )
            else:
                return False
        except Exception:
            return False
        return True

    def _find_issuer(cert: cx509.Certificate) -> cx509.Certificate | None:
        """Find the bundled cert whose subject matches cert's issuer."""
        try:
            issuer_bytes = cert.issuer.public_bytes()
        except Exception:
            return None
        for c in all_certs:
            try:
                if c.subject.public_bytes() == issuer_bytes:
                    return c
            except Exception:
                pass
        return None

    # Step 1: Verify F9 signed the attest cert
    if not _verify_signature(f9_cert, attest_cert):
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail="Workload key attestation certificate not signed by F9 key.",
        )

    # Step 2: Walk up from F9's issuer through intermediates to a root
    current = f9_cert
    max_depth = 5  # Prevent infinite loops
    for _ in range(max_depth):
        issuer_cert = _find_issuer(current)
        if issuer_cert is None:
            try:
                issuer_str = current.issuer.rfc4514_string()
            except Exception:
                issuer_str = "(unparseable issuer)"
            return AttestationCheck(
                name="Attestation chain verified",
                passed=False,
                detail=f"Could not find Yubico CA '{issuer_str}'.",
            )

        if not _verify_signature(issuer_cert, current):
            return AttestationCheck(
                name="Attestation chain verified",
                passed=False,
                detail=f"Certificate not signed by issuer: {current.subject.rfc4514_string()}",
            )

        # Check if we've reached a self-signed root
        if issuer_cert.subject.public_bytes() == issuer_cert.issuer.public_bytes():
            return AttestationCheck(
                name="Attestation chain verified",
                passed=True,
                detail="Attestation chain verified successfully against Yubico Root CA.",
            )

        current = issuer_cert

    return AttestationCheck(
        name="Attestation chain verified",
        passed=False,
        detail="Chain too deep — could not reach a Yubico root CA.",
    )


def _parse_attested_properties(attest_cert: cx509.Certificate) -> str:
    """Extract cryptographically-proven device properties from a Yubico attestation cert.

    Parses Yubico's private OID arc (1.3.6.1.4.1.41482.3.*) to extract:
    - Firmware version (.3.3): 3 raw bytes
    - Serial number (.3.7): DER-encoded INTEGER
    - Form factor (.3.9): 1 raw byte
    - PIN + Touch policy (.3.8): 2 raw bytes

    Returns a pipe-separated string of properties, or empty string if none found.
    """
    yubico_arc = "1.3.6.1.4.1.41482.3"
    pin_policy_map = {1: "Never", 2: "Once", 3: "Always"}
    touch_policy_map = {1: "Never", 2: "Always", 3: "Cached"}
    form_factor_map = {
        0x01: "USB-A Keychain",
        0x02: "USB-A Nano",
        0x03: "USB-C Keychain",
        0x04: "USB-C Nano",
        0x05: "USB-C/Lightning",
        0x81: "USB-A Keychain (FIPS)",
        0x82: "USB-A Nano (FIPS)",
        0x83: "USB-C Keychain (FIPS)",
        0x84: "USB-C Nano (FIPS)",
        0x85: "USB-C/Lightning (FIPS)",
    }

    def _get_ext_bytes(oid_suffix: str) -> bytes | None:
        try:
            ext = attest_cert.extensions.get_extension_for_oid(cx509.ObjectIdentifier(f"{yubico_arc}.{oid_suffix}"))
            val = ext.value.value
            return val if isinstance(val, bytes) else None
        except cx509.ExtensionNotFound:
            return None

    proven_props: list[str] = []

    # Firmware version (.3.3): 3 bytes — major, minor, patch
    fw = _get_ext_bytes("3")
    if fw and len(fw) >= 3:
        proven_props.append(f"Firmware: {fw[0]}.{fw[1]}.{fw[2]}")

    # Serial number (.3.7): DER-encoded INTEGER (tag=0x02, length, value)
    sn = _get_ext_bytes("7")
    if sn:
        if len(sn) >= 3 and sn[0] == 0x02:
            sn_int = int.from_bytes(sn[2 : 2 + sn[1]], "big")
        else:
            sn_int = int.from_bytes(sn, "big")
        proven_props.append(f"Serial: {sn_int}")

    # Form factor (.3.9): 1 byte
    ff = _get_ext_bytes("9")
    if ff and len(ff) >= 1:
        proven_props.append(f"Form factor: {form_factor_map.get(ff[0], f'Unknown (0x{ff[0]:02x})')}")

    # PIN + Touch policy (.3.8): 2 raw bytes
    pol = _get_ext_bytes("8")
    if pol and len(pol) >= 2:
        pin_str = pin_policy_map.get(pol[0], f"Unknown ({pol[0]})")
        touch_str = touch_policy_map.get(pol[1], f"Unknown ({pol[1]})")
        proven_props.append(f"PIN policy: {pin_str}, Touch policy: {touch_str}")
    elif pol and len(pol) == 1:
        pin_str = pin_policy_map.get(pol[0], f"Unknown ({pol[0]})")
        proven_props.append(f"PIN policy: {pin_str}")

    return " | ".join(proven_props)


def attest_yubikey(config: WorkloadConfig) -> AttestationReport:
    """Run full hardware attestation for a PIV key on a YubiKey."""
    # All yubikit/ykman imports inside functions (lazy)
    try:
        import ykman.device
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.piv import SLOT, PivSession
    except ImportError:
        return AttestationReport(
            platform="yubikey",
            supported=False,
            hardware_type="YubiKey",
            not_supported_reason="yubikey-manager not installed. Run 'pip install wif-bunker[yubikey]'.",
            summary="YubiKey attestation requires the yubikey-manager package.",
        )

    checks = []
    artifacts = []
    ek_details = None
    tpm_info = None

    try:
        devices = ykman.device.list_all_devices()
    except Exception as e:
        logger.warning(f"Failed to list YubiKeys: {e}")
        devices = []

    # Check 1: YubiKey detected
    if not devices:
        checks.append(
            AttestationCheck(
                name="YubiKey detected",
                passed=False,
                detail="No YubiKey detected. Ensure device is plugged in and pcscd is running (Linux: sudo apt install pcscd).",
            )
        )
        return AttestationReport(
            platform="yubikey",
            supported=True,
            hardware_type="YubiKey",
            checks=checks,
            summary="No YubiKey with PIV support detected. Ensure the device is plugged in and pcscd is running.",
        )

    if len(devices) > 1 and not config.yubikey_serial:
        serials = [info.serial for dev, info in devices if info.serial]
        checks.append(
            AttestationCheck(
                name="YubiKey detected",
                passed=False,
                detail=f"Multiple YubiKeys found ({serials}). Specify one using --yubikey-serial.",
            )
        )
        return AttestationReport(
            platform="yubikey",
            supported=True,
            hardware_type="YubiKey",
            checks=checks,
            summary="Multiple YubiKeys detected. Please specify the serial number of the one to attest.",
        )

    target_dev = None
    target_info = None
    for dev, info in devices:
        if config.yubikey_serial:
            if info.serial == config.yubikey_serial:
                target_dev = dev
                target_info = info
                break
        else:
            target_dev = dev
            target_info = info
            break

    if not target_dev or not target_info:
        checks.append(
            AttestationCheck(
                name="YubiKey detected",
                passed=False,
                detail=f"YubiKey with serial {config.yubikey_serial} not found.",
            )
        )
        return AttestationReport(
            platform="yubikey",
            supported=True,
            hardware_type="YubiKey",
            checks=checks,
            summary=f"YubiKey with serial {config.yubikey_serial} not found.",
        )

    serial = target_info.serial
    version = target_info.version
    form_factor = getattr(target_info, "form_factor", "Unknown")
    form_factor_name = str(form_factor)

    major, minor, patch = version

    checks.append(
        AttestationCheck(
            name="YubiKey detected",
            passed=True,
            detail=f"Found YubiKey (S/N: {serial}, Firmware: {major}.{minor}.{patch}, Form Factor: {form_factor_name})",
        )
    )

    tpm_info = {
        "device_type": "YubiKey",
        "serial": serial,
        "firmware": f"{major}.{minor}.{patch}",
        "form_factor": form_factor_name,
    }

    # Check 2: PIV firmware version
    if version < (4, 3, 0):
        checks.append(
            AttestationCheck(
                name="PIV firmware version",
                passed=False,
                detail=f"Firmware {major}.{minor}.{patch} does not support attestation (requires >= 4.3.0).",
            )
        )
        return AttestationReport(
            platform="yubikey",
            supported=True,
            hardware_type="YubiKey",
            checks=checks,
            summary="YubiKey firmware version is too old to support attestation.",
            tpm_info=tpm_info,
        )
    elif version < (5, 0, 0):
        checks.append(
            AttestationCheck(
                name="PIV firmware version",
                passed=True,
                detail=f"Firmware {major}.{minor}.{patch} supports attestation, but < 5.0.0 (no serial in attestation cert).",
            )
        )
    else:
        checks.append(
            AttestationCheck(
                name="PIV firmware version",
                passed=True,
                detail=f"Firmware {major}.{minor}.{patch} supports attestation.",
            )
        )

    # Connect to device
    try:
        conn = target_dev.open_connection(SmartCardConnection)
        piv = PivSession(conn)
    except Exception as e:
        checks.append(
            AttestationCheck(
                name="Key attestation certificate",
                passed=False,
                detail=f"Failed to connect to YubiKey PIV applet: {e}",
            )
        )
        return AttestationReport(
            platform="yubikey",
            supported=True,
            hardware_type="YubiKey",
            checks=checks,
            summary="Failed to communicate with YubiKey.",
            tpm_info=tpm_info,
        )

    # Check 3: Key attestation certificate
    slot = _get_slot(config.yubikey_slot or "9a")

    try:
        attest_cert = piv.attest_key(slot)
        checks.append(
            AttestationCheck(
                name="Key attestation certificate",
                passed=True,
                detail=f"Successfully extracted attestation certificate for slot {slot.name}.",
            )
        )
        artifacts.append(
            AttestationArtifact(
                filename="key_attestation.pem",
                content=attest_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                description="Hardware residency certificate for the workload key",
            )
        )
    except Exception:
        checks.append(
            AttestationCheck(
                name="Key attestation certificate",
                passed=False,
                detail=f"Failed to attest key in slot {slot.name}. It may have been imported rather than generated on-device.",
            )
        )
        return AttestationReport(
            platform="yubikey",
            supported=True,
            hardware_type="YubiKey",
            checks=checks,
            summary="Your workload key is stored on a YubiKey but was imported, not generated on-device. Hardware residency cannot be cryptographically proven.",
            tpm_info=tpm_info,
        )

    # Check 4: Attestation chain verified
    try:
        f9_cert = piv.get_certificate(SLOT.ATTESTATION)
        artifacts.append(
            AttestationArtifact(
                filename="f9_attestation.pem",
                content=f9_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                description="YubiKey Device Attestation Certificate (F9)",
            )
        )

        try:
            f9_cert_issuer = f9_cert.issuer.rfc4514_string()
        except Exception:
            f9_cert_issuer = "Unknown"

        ek_details = {
            "issuer": f9_cert_issuer,
            "serial": f9_cert.serial_number,
        }

        chain_check = _verify_yubico_chain(attest_cert, f9_cert)
        checks.append(chain_check)
    except Exception as e:
        checks.append(
            AttestationCheck(
                name="Attestation chain verified",
                passed=False,
                detail=f"Failed to read F9 attestation certificate: {e}",
            )
        )

    proven_detail = _parse_attested_properties(attest_cert)

    if proven_detail:
        checks.append(
            AttestationCheck(
                name="Attested device properties",
                passed=True,
                detail=proven_detail,
            )
        )
    else:
        checks.append(
            AttestationCheck(
                name="Attested device properties",
                passed=True,
                detail="No device properties found in attestation certificate (older firmware may omit these)",
            )
        )

    # Check verdicts
    check_map = {chk.name: chk.passed for chk in checks}
    # For a key to be proven, it must have passed:
    # Key attestation certificate, Attestation chain verified
    key_proven = check_map.get("Key attestation certificate", False) and check_map.get(
        "Attestation chain verified", False
    )

    if key_proven:
        summary = (
            f"Cryptographically proven: your workload private key was generated on this YubiKey "
            f"(S/N: {serial}, firmware {major}.{minor}.{patch}) and cannot be extracted. "
            f"The attestation chain is verified against Yubico's root CA."
        )
    elif check_map.get("Key attestation certificate", False):
        summary = "Your workload key is stored on a YubiKey but the attestation chain could not be verified."
    else:
        summary = (
            "Your workload key is stored on a YubiKey but was imported, not generated on-device. "
            "Hardware residency cannot be cryptographically proven."
        )

    return AttestationReport(
        platform="yubikey",
        supported=True,
        hardware_type="YubiKey",
        artifacts=artifacts,
        checks=checks,
        summary=summary,
        platform_info=None,
        ek_details=ek_details,
        tpm_info=tpm_info,
    )
