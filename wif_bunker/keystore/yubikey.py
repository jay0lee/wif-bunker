"""YubiKey keystore: PIV key generation and certificate management.

.. ai-note::
   IMPORTANT FOR AI AGENTS: Before reading, editing, or debugging this file,
   you MUST read docs/keystore-yubikey.md in the repository root.
   That document covers the PIV security initialization sequence (PIN/PUK/
   management key), generate_key parameters, slot mapping, firmware version
   gates, PKCS#11 library discovery, and the import-vs-generate distinction.
   If you make changes to this file, update docs/keystore-yubikey.md to match.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.utils import generate_pin

logger = logging.getLogger(__name__)


def get_supported_algorithms_yubikey(serial: int | None = None) -> list[str]:
    """Probe a connected YubiKey for supported algorithms.

    Detects the YubiKey's firmware version and returns the list of
    wif-bunker algorithm names it supports.

    Args:
        serial: YubiKey serial number.  Required if multiple YubiKeys
            are connected.

    Returns:
        List of supported algorithm names.

    Raises:
        RuntimeError: if no YubiKey is found or multiple without serial.
    """
    from ykman.device import list_all_devices  # pylint: disable=import-outside-toplevel

    devices = list(list_all_devices())
    if not devices:
        raise RuntimeError("No YubiKeys found. On Linux, ensure 'pcscd' service is running.")

    target_info = None
    if len(devices) > 1 and serial is None:
        serials = [str(info.serial) for _, info in devices]
        raise RuntimeError(f"Multiple YubiKeys found: {', '.join(serials)}. Specify one with --yubikey-serial.")

    if serial is not None:
        for _, info in devices:
            if info.serial == serial:
                target_info = info
                break
        if not target_info:
            raise RuntimeError(f"YubiKey with serial {serial} not found.")
    else:
        _, target_info = devices[0]

    if target_info.version < (4, 3, 0):
        raise RuntimeError(f"YubiKey firmware {target_info.version} too old. Requires >= 4.3.0 for attestation.")

    supported = ["es256", "es384", "rsa2048"]
    if target_info.version >= (5, 7, 0):
        supported.append("rsa4096")

    return supported


def yubikey_config_dir() -> Path:
    """Return the platform-specific directory for YubiKey config files."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "wif-bunker"


def _yubikey_config_path(serial: int) -> Path:
    """Returns the path to the YubiKey credential configuration file."""
    return yubikey_config_dir() / f"yubikey_{serial}.json"


def generate_cert_yubikey(config: WorkloadConfig) -> CertificateBundle:
    """Generates a YubiKey-backed certificate via ykman/yubikit."""
    # Lazy imports to avoid requiring yubikit on non-YubiKey platforms
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import (
        DEFAULT_MANAGEMENT_KEY,
        KEY_TYPE,
        MANAGEMENT_KEY_TYPE,
        PIN_POLICY,
        SLOT,
        TOUCH_POLICY,
        PivSession,
    )

    _YUBIKEY_SLOT_MAP = {
        "9a": SLOT.AUTHENTICATION,
        "9c": SLOT.SIGNATURE,
        "9d": SLOT.KEY_MANAGEMENT,
        "9e": SLOT.CARD_AUTH,
    }

    # 1. Detection
    devices = list(list_all_devices())
    if not devices:
        raise RuntimeError(
            "No YubiKeys found. On Linux, ensure 'pcscd' service is running (e.g. sudo systemctl start pcscd)."
        )

    target_dev = None
    target_info = None

    if len(devices) > 1 and not config.yubikey_serial:
        serials = [str(info.serial) for _, info in devices]
        raise RuntimeError(f"Multiple YubiKeys found: {', '.join(serials)}. Please specify one using --yubikey-serial.")

    if config.yubikey_serial:
        for dev, info in devices:
            if str(info.serial) == str(config.yubikey_serial):
                target_dev = dev
                target_info = info
                break
        if not target_dev:
            raise RuntimeError(f"YubiKey with serial {config.yubikey_serial} not found.")
    else:
        target_dev, target_info = devices[0]
        # Write back auto-detected serial so downstream steps
        # (e.g. build_ecp_pkcs11_config) can find the credential file.
        config.yubikey_serial = target_info.serial

    # 2. Firmware validation
    if target_info.version < (4, 3, 0):
        raise RuntimeError(f"YubiKey firmware {target_info.version} too old. Requires >= 4.3.0 for attestation.")
    if target_info.version < (5, 0, 0):
        logger.warning("YubiKey firmware < 5.0.0 does not include serial number in attestation certificate.")

    # 3. Algorithm mapping
    key_algo_map = {
        "es256": KEY_TYPE.ECCP256,
        "es384": KEY_TYPE.ECCP384,
        "rsa2048": KEY_TYPE.RSA2048,
        "rsa4096": KEY_TYPE.RSA4096,
    }

    key_type = key_algo_map.get(config.key_algorithm)
    if not key_type:
        raise RuntimeError(f"Key algorithm {config.key_algorithm} is not supported by the YubiKey keystore.")

    if key_type == KEY_TYPE.RSA4096 and target_info.version < (5, 7, 0):
        raise RuntimeError("RSA4096 requires YubiKey firmware 5.7+.")

    # 4. Security initialization
    with target_dev.open_connection(SmartCardConnection) as conn:
        piv = PivSession(conn)

        is_default = False
        try:
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            is_default = True
        except Exception:
            logger.debug("YubiKey management key is not default", exc_info=True)

        cfg_path = _yubikey_config_path(target_info.serial)

        if is_default:
            logger.info("Initializing YubiKey with randomized credentials...")
            new_pin = generate_pin(length=8)  # PIV spec: max 8 chars
            new_puk = generate_pin(length=8)
            new_mgm = secrets.token_bytes(24)

            piv.change_pin("123456", new_pin)
            piv.change_puk("12345678", new_puk)
            piv.set_management_key(MANAGEMENT_KEY_TYPE.TDES, new_mgm)

            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            cfg = {
                "pin": new_pin,
                "puk": new_puk,
                "management_key": new_mgm.hex(),
            }
            cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            cfg_path.chmod(0o600)

            pin = new_pin
            mgm = new_mgm
            # Authenticate again with new key just in case
            piv.authenticate(mgm)
        else:
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
                pin = cfg["pin"]
                mgm = bytes.fromhex(cfg["management_key"])
                piv.authenticate(mgm)
            else:
                raise RuntimeError(
                    "YubiKey management key is not default, but no credential config file "
                    f"was found at {cfg_path}. Please provide credentials manually or reset the PIV applet."
                )

        piv.verify_pin(pin)

        # 5. Key generation
        slot_str = getattr(config, "yubikey_slot", "9a").lower()
        slot = _YUBIKEY_SLOT_MAP.get(slot_str)
        if not slot:
            raise RuntimeError(f"Invalid YubiKey slot: {slot_str}")

        touch_str = getattr(config, "yubikey_touch_policy", "never").upper()
        touch_policy = getattr(TOUCH_POLICY, touch_str, TOUCH_POLICY.NEVER)

        logger.info(f"Generating {config.key_algorithm} key in slot {slot_str}...")
        pub_key = piv.generate_key(slot, key_type, pin_policy=PIN_POLICY.ONCE, touch_policy=touch_policy)

        # 6. Public key export
        pub_key_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # 7. Cert signing
        bundle, workload_pem = _create_ca_and_sign(pub_key_pem, config)

        # 8. Cert import
        cert_obj = cx509.load_pem_x509_certificate(workload_pem.encode("utf-8"))
        piv.put_certificate(slot, cert_obj)

        logger.info("Successfully imported CA-signed certificate into YubiKey.")

        # 9. Return CertificateBundle
        return bundle


# --- YubiKey PKCS#11 library search paths ---
_YUBIKEY_PKCS11_SEARCH_PATHS: dict[str, list[str]] = {
    "linux": [
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
        "/usr/local/lib/opensc-pkcs11.so",
        "/usr/lib/pkcs11/opensc-pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/libykcs11.so",
        "/usr/lib/aarch64-linux-gnu/libykcs11.so",
        "/usr/local/lib/libykcs11.so",
        "/usr/lib/libykcs11.so",
    ],
    "darwin": [
        "/opt/homebrew/lib/libykcs11.dylib",
        "/usr/local/lib/libykcs11.dylib",
    ],
    "win32": [
        r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
        r"C:\Program Files (x86)\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
    ],
}


def find_pkcs11_library() -> str:
    """Locate the PKCS#11 shared library for YubiKey ECP mTLS."""
    env_path = os.environ.get("YKCS11_MODULE")
    if env_path:
        if Path(env_path).exists():
            logger.info("    Using PKCS#11 library from YKCS11_MODULE: %s", env_path)
            return env_path
        raise FileNotFoundError(f"YKCS11_MODULE set to '{env_path}' but file does not exist.")

    for platform_prefix, candidates in _YUBIKEY_PKCS11_SEARCH_PATHS.items():
        if sys.platform.startswith(platform_prefix):
            for candidate in candidates:
                if Path(candidate).exists():
                    logger.info("    Found YubiKey PKCS#11 library: %s", candidate)
                    return candidate
    if sys.platform.startswith("win32"):
        hint = (
            "The YubiKey PKCS#11 library (libykcs11.dll) is required for mTLS.\n"
            "\n"
            "  Install the Yubico PIV Tool:\n"
            "    1. Download the .msi installer from:\n"
            "       https://developers.yubico.com/yubico-piv-tool/Releases/\n"
            "    2. Run the installer (adds libykcs11.dll to Program Files)\n"
            "    3. Re-run wif-bunker\n"
        )
    elif sys.platform.startswith("darwin"):
        hint = (
            "The YubiKey PKCS#11 library (libykcs11.dylib) is required for mTLS.\n"
            "\n"
            "  Install: brew install yubico-piv-tool\n"
        )
    else:
        hint = (
            "The YubiKey PKCS#11 library (libykcs11.so) is required for mTLS.\n"
            "\n"
            "  Install: sudo apt install opensc\n"
            "  Or:      sudo apt install libykcs11-1\n"
        )
    raise FileNotFoundError(
        f"Could not find a PKCS#11 module for YubiKey.\n\n"
        f"{hint}\n"
        f"Or set the YKCS11_MODULE environment variable to the library path."
    )


def build_ecp_pkcs11_config(serial: int | None, workload_cn: str) -> dict:
    yk_module = find_pkcs11_library()
    _is_opensc = "opensc" in yk_module.lower()

    # Load PIN from stored YubiKey config.
    yk_config_path = yubikey_config_dir() / f"yubikey_{serial or 'default'}.json"
    yk_pin = ""
    if yk_config_path.exists():
        try:
            yk_cfg = json.loads(yk_config_path.read_text(encoding="utf-8"))
            yk_pin = yk_cfg.get("pin", "")
        except Exception:
            logger.debug("Failed to read YubiKey config file", exc_info=True)

    # ECP uses the PKCS#11 CKA_LABEL to find the cert object.
    if _is_opensc:
        yk_label = "Certificate for PIV Authentication"
    else:
        yk_label = "X.509 Certificate for PIV Authentication"

    # Discover the PKCS#11 slot ID for the target serial via pkcs11-tool.
    yk_slot = "0"
    try:
        _slot_result = subprocess.run(
            ["pkcs11-tool", "--module", yk_module, "--list-slots"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        _target_label = workload_cn if _is_opensc else f"YubiKey PIV #{serial}"
        _last_hex = None
        for _line in _slot_result.stdout.splitlines():
            _sm = re.search(r"Slot\s+\d+\s+\(0x([0-9a-fA-F]+)\)", _line)
            if _sm:
                _last_hex = _sm.group(1)
            if _target_label in _line and _last_hex is not None:
                yk_slot = _last_hex
                break
    except Exception:
        logger.debug("Failed to discover PKCS#11 slot ID", exc_info=True)

    logger.info("    YubiKey PKCS#11 module=%s slot=0x%s label=%r", yk_module, yk_slot, yk_label)
    return {
        "pkcs11": {
            "module": yk_module,
            "slot": yk_slot,
            "label": yk_label,
            "user_pin": yk_pin,
        },
    }
