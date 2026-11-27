"""Pluggable hardware signer loader backed by ``jay0lee/dpop-signers``.

WIF Bunker does not provision or manage private keys — it loads a pre-existing
key via one of the ``dpop-signer-*`` packages (or a PEM key via
``google.auth.dpop.SoftwareDPoPSigner`` for CI/testing).

Every loaded signer exposes the ``DPoPSigner`` interface:
  - ``algorithm``: ``"ES256"`` or ``"RS256"``
  - ``public_jwk``: RFC 7517 public JWK mapping
  - ``key_id`` / ``thumbprint``: key identifier string
  - ``sign(data: bytes) -> bytes``: RFC 7515 JWS signature bytes
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from google.auth.dpop import SoftwareDPoPSigner

logger = logging.getLogger(__name__)

_SIGNER_DOCS_BASE = "https://github.com/jay0lee/dpop-signers/tree/main"

SIGNER_DOC_URLS: dict[str, str] = {
    "linux-tpm": f"{_SIGNER_DOCS_BASE}/linux-tpm",
    "windows-certstore": f"{_SIGNER_DOCS_BASE}/windows-certstore",
    "macos-secureenclave": f"{_SIGNER_DOCS_BASE}/macos-secureenclave",
    "yubikey": f"{_SIGNER_DOCS_BASE}/yubikey",
    "pkcs11": f"{_SIGNER_DOCS_BASE}/pkcs11",
    "fido2-previewsign": f"{_SIGNER_DOCS_BASE}/fido2-previewsign",
    "software": "https://github.com/jay0lee/wif-bunker",
}


def _parse_int_handle(value: int | str) -> int:
    """Parse a TPM persistent handle given as an int or hex/decimal string."""
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0)


def _docs_hint(signer_type: str) -> str:
    url = SIGNER_DOC_URLS.get(signer_type)
    if url:
        return f"\nKey provisioning & troubleshooting docs: {url}"
    return ""


def load_signer(signer_cfg: dict[str, Any]) -> Any:
    """Instantiate a hardware/software signer from a ``signer`` config dict.

    Expected ``signer_cfg`` formats:
      - ``{"type": "linux-tpm", "handle": "0x81000001", "tcti": ..., "auth": ..., "key_id": ...}``
      - ``{"type": "windows-certstore", "subject": "...", "thumbprint": "...", "store_location": "current_user"}``
      - ``{"type": "macos-secureenclave", "label": "...", "tag": "..."}``
      - ``{"type": "yubikey", "slot": "9c", "serial": ..., "pin": "..."}``
      - ``{"type": "pkcs11", "uri": "pkcs11:...", ...}``
      - ``{"type": "fido2-previewsign", "credential_file": "/path/to/cred.json", "pin": ...}``
      - ``{"type": "software", "key_file": "/path/to/key.pem", "key_id": ...}``

    Raises:
        ValueError: If ``type`` is unknown or required parameters are missing.
        RuntimeError: If the signer package is missing or fails to initialize.
    """
    if not isinstance(signer_cfg, dict) or not signer_cfg.get("type"):
        raise ValueError("Signer configuration must be a dict containing a 'type' field.")

    stype = str(signer_cfg["type"]).strip().lower()
    loader = _SIGNER_LOADERS.get(stype)
    if loader is None:
        raise ValueError(f"Unknown signer type '{stype}'. Supported types: {', '.join(sorted(SIGNER_DOC_URLS))}.")

    try:
        return loader(signer_cfg)
    except (ValueError, RuntimeError):
        raise
    except ImportError as exc:
        raise RuntimeError(
            f"Signer backend '{stype}' is not available on this platform or its package is not installed: {exc}"
            f"{_docs_hint(stype)}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to initialize '{stype}' signer: {exc}{_docs_hint(stype)}") from exc


def _load_linux_tpm(cfg: dict[str, Any]) -> Any:
    from dpop_signer_linux_tpm import LinuxTPMDPoPSigner  # pylint: disable=import-outside-toplevel,import-error

    raw_handle = cfg.get("handle", 0x81000001)
    handle = _parse_int_handle(raw_handle)
    tcti = cfg.get("tcti") or os.environ.get("TPM2TOOLS_TCTI")
    return LinuxTPMDPoPSigner(
        handle=handle,
        tcti=tcti,
        auth=cfg.get("auth"),
        key_id=cfg.get("key_id"),
    )


def _load_windows_certstore(cfg: dict[str, Any]) -> Any:
    from dpop_signer_windows_certstore import (  # pylint: disable=import-outside-toplevel,import-error
        WindowsCertStoreDPoPSigner,
    )

    subject = cfg.get("subject")
    thumbprint = cfg.get("thumbprint")
    if not subject and not thumbprint:
        raise ValueError("windows-certstore signer requires either 'subject' or 'thumbprint'.")
    return WindowsCertStoreDPoPSigner(
        subject=subject,
        thumbprint=thumbprint,
        key_id=cfg.get("key_id"),
        store_location=cfg.get("store_location", "current_user"),
    )


def _load_macos_secureenclave(cfg: dict[str, Any]) -> Any:
    from dpop_signer_macos_secureenclave import SecureEnclaveDPoPSigner  # pylint: disable=import-outside-toplevel

    label = cfg.get("label")
    tag = cfg.get("tag")
    if not label and not tag:
        raise ValueError("macos-secureenclave signer requires either 'label' or 'tag'.")
    kwargs: dict[str, Any] = {}
    if label:
        kwargs["label"] = label
    if tag:
        kwargs["tag"] = tag
    if cfg.get("key_id"):
        kwargs["key_id"] = cfg["key_id"]
    return SecureEnclaveDPoPSigner(**kwargs)


def _load_yubikey(cfg: dict[str, Any]) -> Any:
    from dpop_signer_yubikey import YubiKeyDPoPSigner  # pylint: disable=import-outside-toplevel

    kwargs: dict[str, Any] = {
        "slot": cfg.get("slot", "9c"),
    }
    if cfg.get("serial") is not None:
        kwargs["serial"] = int(cfg["serial"])
    if cfg.get("pin") is not None:
        kwargs["pin"] = cfg["pin"]
    if cfg.get("key_id"):
        kwargs["key_id"] = cfg["key_id"]
    return YubiKeyDPoPSigner(**kwargs)


def _load_pkcs11(cfg: dict[str, Any]) -> Any:
    from dpop_signer_pkcs11 import PKCS11DPoPSigner  # pylint: disable=import-outside-toplevel

    uri = cfg.get("uri")
    kwargs: dict[str, Any] = {}
    for field_name in ("module_path", "token_label", "key_label", "pin", "slot_id", "token_serial", "key_id"):
        if cfg.get(field_name) is not None:
            kwargs[field_name] = cfg[field_name]
    if uri:
        return PKCS11DPoPSigner(uri, **kwargs)
    if not kwargs:
        raise ValueError("pkcs11 signer requires 'uri' or explicit module/token/key parameters.")
    return PKCS11DPoPSigner(**kwargs)


def _load_fido2_previewsign(cfg: dict[str, Any]) -> Any:
    from dpop_signer_fido2_previewsign import Fido2PreviewSignDPoPSigner  # pylint: disable=import-outside-toplevel

    cred_file = cfg.get("credential_file")
    if cred_file:
        cred_path = Path(cred_file)
        if not cred_path.exists():
            raise ValueError(f"FIDO2 credential file not found: {cred_path}")
        cred_data = json.loads(cred_path.read_text(encoding="utf-8"))
    else:
        cred_data = {k: v for k, v in cfg.items() if k not in ("type", "pin")}

    if not cred_data.get("credential_id"):
        raise ValueError("fido2-previewsign signer requires 'credential_file' or credential metadata.")

    if cfg.get("pin") is not None:
        cred_data["pin"] = cfg["pin"]
    return Fido2PreviewSignDPoPSigner.from_dict(cred_data)


def _load_software(cfg: dict[str, Any]) -> Any:
    """Load a pre-existing PEM private key via ``SoftwareDPoPSigner`` (for CI/testing)."""
    key_file = cfg.get("key_file")
    if not key_file:
        raise ValueError("software signer requires 'key_file' pointing to a PEM private key.")
    key_path = Path(key_file)
    if not key_path.exists():
        raise ValueError(f"Software private key file not found: {key_path}")
    password = cfg.get("password")
    pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=pwd_bytes)
    return SoftwareDPoPSigner(private_key, key_id=cfg.get("key_id"))


_SIGNER_LOADERS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "linux-tpm": _load_linux_tpm,
    "windows-certstore": _load_windows_certstore,
    "macos-secureenclave": _load_macos_secureenclave,
    "yubikey": _load_yubikey,
    "pkcs11": _load_pkcs11,
    "fido2-previewsign": _load_fido2_previewsign,
    "software": _load_software,
}
