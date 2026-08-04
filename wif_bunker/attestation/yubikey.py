"""YubiKey PIV attestation module.

Provides verification of hardware residency using YubiKey PIV attestation.
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
    """Verify that the attestation cert chains to the Yubico Root CA."""
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

    roots = []
    for pem_file in sorted(roots_dir.glob("*.pem")):
        try:
            roots.append(cx509.load_pem_x509_certificate(pem_file.read_bytes()))
        except Exception:
            pass

    if not roots:
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail="Could not load Yubico root certificates.",
        )

    # First verify F9 issued the attest_cert
    try:
        issuer_pub = f9_cert.public_key()
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            issuer_pub.verify(
                attest_cert.signature,
                attest_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                attest_cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(
                attest_cert.signature,
                attest_cert.tbs_certificate_bytes,
                ec.ECDSA(attest_cert.signature_hash_algorithm),
            )
        else:
            return AttestationCheck(
                name="Attestation chain verified",
                passed=False,
                detail=f"Unsupported F9 key type: {type(issuer_pub).__name__}",
            )
    except Exception as e:
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail=f"Workload key attestation certificate not signed by F9 key: {e}",
        )

    # Now verify Root CA issued F9 cert
    try:
        f9_issuer_bytes = f9_cert.issuer.public_bytes()
    except Exception:
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail="Could not read F9 certificate issuer field.",
        )

    issuer_cert = None
    for root in roots:
        try:
            if root.subject.public_bytes() == f9_issuer_bytes:
                issuer_cert = root
                break
        except Exception:
            pass

    if not issuer_cert:
        try:
            issuer_str = f9_cert.issuer.rfc4514_string()
        except Exception:
            issuer_str = "(unparseable issuer)"
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail=f"Could not find Yubico root CA '{issuer_str}'.",
        )

    try:
        root_pub = issuer_cert.public_key()
        if isinstance(root_pub, rsa.RSAPublicKey):
            root_pub.verify(
                f9_cert.signature,
                f9_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                f9_cert.signature_hash_algorithm,
            )
        elif isinstance(root_pub, ec.EllipticCurvePublicKey):
            root_pub.verify(
                f9_cert.signature,
                f9_cert.tbs_certificate_bytes,
                ec.ECDSA(f9_cert.signature_hash_algorithm),
            )
        else:
            return AttestationCheck(
                name="Attestation chain verified",
                passed=False,
                detail=f"Unsupported root key type: {type(root_pub).__name__}",
            )
    except Exception as e:
        return AttestationCheck(
            name="Attestation chain verified",
            passed=False,
            detail=f"F9 certificate not signed by Yubico root CA: {e}",
        )

    return AttestationCheck(
        name="Attestation chain verified",
        passed=True,
        detail="Attestation chain verified successfully against Yubico Root CA.",
    )


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

    # Check 5: PIN policy
    # OID 1.3.6.1.4.1.41482.3.7
    pin_policy_oid = cx509.ObjectIdentifier("1.3.6.1.4.1.41482.3.7")
    try:
        ext = attest_cert.extensions.get_extension_for_oid(pin_policy_oid)
        val = ext.value.value
        if isinstance(val, bytes):
            # Parse DER integer: 02 01 XX
            if len(val) >= 3 and val[0] == 0x02 and val[1] == 0x01:
                policy_val = val[2]
                policy_map = {1: "Never", 2: "Once", 3: "Always"}
                policy_str = policy_map.get(policy_val, f"Unknown ({policy_val})")
            else:
                policy_str = f"Unknown encoding ({val.hex()})"
        else:
            policy_str = str(val)

        checks.append(AttestationCheck(name="PIN policy", passed=True, detail=f"Policy: {policy_str}"))
    except cx509.ExtensionNotFound:
        checks.append(
            AttestationCheck(name="PIN policy", passed=True, detail="Unknown (firmware may not include policy info)")
        )

    # Check 6: Touch policy
    # OID 1.3.6.1.4.1.41482.3.8
    touch_policy_oid = cx509.ObjectIdentifier("1.3.6.1.4.1.41482.3.8")
    try:
        ext = attest_cert.extensions.get_extension_for_oid(touch_policy_oid)
        val = ext.value.value
        if isinstance(val, bytes):
            if len(val) >= 3 and val[0] == 0x02 and val[1] == 0x01:
                policy_val = val[2]
                policy_map = {1: "Never", 2: "Always", 3: "Cached"}
                policy_str = policy_map.get(policy_val, f"Unknown ({policy_val})")
            else:
                policy_str = f"Unknown encoding ({val.hex()})"
        else:
            policy_str = str(val)

        checks.append(AttestationCheck(name="Touch policy", passed=True, detail=f"Policy: {policy_str}"))
    except cx509.ExtensionNotFound:
        checks.append(
            AttestationCheck(name="Touch policy", passed=True, detail="Unknown (firmware may not include policy info)")
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
