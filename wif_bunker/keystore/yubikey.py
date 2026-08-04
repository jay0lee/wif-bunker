"""YubiKey keystore: PIV key generation and certificate management."""

from __future__ import annotations

import json
import logging
import os
import secrets
import string
import sys
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig

logger = logging.getLogger(__name__)


def _yubikey_config_path(serial: int) -> Path:
    """Returns the path to the YubiKey credential configuration file."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", "~")).expanduser()
    else:
        base = Path.home() / ".config"
    return base / "wif-bunker" / f"yubikey_{serial}.json"


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
            pass

        cfg_path = _yubikey_config_path(target_info.serial)

        if is_default:
            logger.info("Initializing YubiKey with randomized credentials...")
            alphabet = string.ascii_letters + string.digits
            new_pin = "".join(secrets.choice(alphabet) for _ in range(8))
            new_puk = "".join(secrets.choice(alphabet) for _ in range(8))
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
