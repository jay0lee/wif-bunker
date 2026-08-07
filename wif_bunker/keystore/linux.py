"""Linux/TPM 2.0 keystore: PKCS#11 key generation and certificate management.

Uses ``python-pkcs11`` to interact with the TPM via ``libtpm2_pkcs11.so``
directly. Token initialization uses ``pkcs11-tool`` (from OpenSC); all
other operations use the PKCS#11 C API with no subprocess calls.

System requirements: ``libtpm2_pkcs11.so`` and ``pkcs11-tool``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pkcs11
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pkcs11 import Attribute, CertificateType, KeyType, Mechanism, ObjectClass, TokenFlag
from pkcs11.util.ec import encode_named_curve_parameters

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig

logger = logging.getLogger(__name__)


# ── PKCS#11 mechanism → wif-bunker algorithm mapping ──

_ALGO_TO_PKCS11 = {
    "ecc256": {
        "key_type": KeyType.EC,
        "params": encode_named_curve_parameters("secp256r1"),
        "mechanism": Mechanism.ECDSA,
    },
    "ecc384": {
        "key_type": KeyType.EC,
        "params": encode_named_curve_parameters("secp384r1"),
        "mechanism": Mechanism.ECDSA,
    },
    "rsa2048": {
        "key_type": KeyType.RSA,
        "key_length": 2048,
        "mechanism": Mechanism.RSA_PKCS,
    },
    "rsa3072": {
        "key_type": KeyType.RSA,
        "key_length": 3072,
        "mechanism": Mechanism.RSA_PKCS,
    },
    "rsa4096": {
        "key_type": KeyType.RSA,
        "key_length": 4096,
        "mechanism": Mechanism.RSA_PKCS,
    },
}


# ── .so path discovery ──

_PKCS11_LIB_PATHS = [
    # Debian/Ubuntu x86_64
    "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
    # Debian/Ubuntu aarch64
    "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
    # Fedora/RHEL x86_64
    "/usr/lib64/pkcs11/libtpm2_pkcs11.so",
    # Arch Linux
    "/usr/lib/pkcs11/libtpm2_pkcs11.so",
    # Generic/manual install
    "/usr/local/lib/pkcs11/libtpm2_pkcs11.so",
]


def _find_pkcs11_lib() -> str:
    """Discover the path to ``libtpm2_pkcs11.so``.

    Search order:
      1. ``TPM2_PKCS11_MODULE`` environment variable (user override)
      2. ``p11-kit list-modules`` output (desktop Linux standard)
      3. Well-known filesystem paths (Debian, Fedora, Arch, etc.)

    Returns the absolute path to the shared library.
    Raises RuntimeError if the library cannot be found.
    """
    # 1. User override
    env_path = os.environ.get("TPM2_PKCS11_MODULE")
    if env_path and Path(env_path).exists():
        logger.debug("    PKCS#11 module from TPM2_PKCS11_MODULE: %s", env_path)
        return env_path

    # 2. Ask p11-kit
    p11kit_path = _query_p11kit()
    if p11kit_path:
        logger.debug("    PKCS#11 module from p11-kit: %s", p11kit_path)
        return p11kit_path

    # 3. Well-known paths
    for path in _PKCS11_LIB_PATHS:
        if Path(path).exists():
            logger.debug("    PKCS#11 module found at: %s", path)
            return path

    raise RuntimeError(
        "Could not find libtpm2_pkcs11.so.\n"
        "\n"
        "  Set TPM2_PKCS11_MODULE=/path/to/libtpm2_pkcs11.so\n"
        "  or verify libtpm2-pkcs11 is installed on your system."
    )


def _query_p11kit() -> str | None:
    """Query p11-kit for the tpm2_pkcs11 module path."""
    import shutil  # pylint: disable=import-outside-toplevel
    import subprocess  # pylint: disable=import-outside-toplevel

    if not shutil.which("p11-kit"):
        return None

    try:
        result = subprocess.run(
            ["p11-kit", "list-modules"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("module:") and "tpm2" in line.lower():
                path = line.split(":", 1)[1].strip()
                if Path(path).exists():
                    return path
    except (subprocess.TimeoutExpired, OSError):
        pass

    return None


# ── TPM availability check ──


def _check_tpm_linux() -> None:
    """Pre-validate TPM availability on Linux.

    Checks for hardware TPM device (/dev/tpmrm0) or software TPM.
    Raises RuntimeError with actionable guidance if no TPM is accessible.
    """
    tpm_device = Path("/dev/tpmrm0")
    if tpm_device.exists():
        if os.access(tpm_device, os.R_OK | os.W_OK):
            return

        import grp  # pylint: disable=import-outside-toplevel
        import pwd  # pylint: disable=import-outside-toplevel

        username = pwd.getpwuid(os.getuid()).pw_name
        try:
            device_group = grp.getgrgid(tpm_device.stat().st_gid).gr_name
            user_groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
        except (KeyError, OSError):
            device_group = "tss"
            user_groups = []

        raise RuntimeError(
            f"/dev/tpmrm0 exists but is not accessible by user '{username}'.\n"
            f"\n"
            f"  The device is owned by group '{device_group}', "
            f"but '{username}' is not a member.\n"
            f"  Current groups: {', '.join(user_groups) or '(none)'}\n"
            f"\n"
            f"  Fix:\n"
            f"    sudo usermod -aG {device_group} {username}\n"
            f"\n"
            f"  Then log out and back in, or run:\n"
            f"    newgrp {device_group}"
        )

    if os.environ.get("TPM2TOOLS_TCTI"):
        return
    try:
        import socket  # pylint: disable=import-outside-toplevel

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect(("127.0.0.1", 2321))
            return
    except (OSError, ConnectionRefusedError):
        pass

    raise RuntimeError(
        "No TPM device found.\n"
        "\n"
        "  wif-bunker requires a TPM 2.0 for hardware-backed keys.\n"
        "  Ensure the TPM is enabled in BIOS/UEFI and check:\n"
        "    ls -la /dev/tpmrm0\n"
        "\n"
        "  For development/testing, a software TPM (swtpm) can be\n"
        "  used by setting the TPM2TOOLS_TCTI environment variable."
    )


# ── Algorithm probing via PKCS#11 mechanisms ──


def get_supported_algorithms_linux() -> list[str]:
    """Probe the TPM for all supported algorithms via PKCS#11 mechanisms.

    Returns a list of wif-bunker algorithm names (e.g. ``["es256", "rsa2048"]``)
    that the TPM hardware supports.
    """
    from wif_bunker.config import _KEY_ALGORITHMS  # pylint: disable=import-outside-toplevel

    _check_tpm_linux()

    lib_path = _find_pkcs11_lib()
    try:
        lib = pkcs11.lib(lib_path)
        slots = lib.get_slots(token_present=True)
        if not slots:
            slots = lib.get_slots()
            if not slots:
                raise RuntimeError(
                    "No PKCS#11 slots available.\n  Verify libtpm2_pkcs11.so is installed and the TPM is accessible."
                )

        mechs = slots[0].get_mechanisms()
    except pkcs11.PKCS11Error as exc:
        raise RuntimeError(f"Could not query PKCS#11 mechanisms: {exc}") from exc

    supported = []
    for algo_name, algo_info in _KEY_ALGORITHMS.items():
        if "linux" not in algo_info["platforms"]:
            continue
        tpm2_algo = algo_info["linux_tpm2"]
        pkcs11_info = _ALGO_TO_PKCS11.get(tpm2_algo)
        if pkcs11_info and pkcs11_info["mechanism"] in mechs:
            supported.append(algo_name)

    return supported


# ── Token management ──

_TOKEN_LABEL = "bunker-wif"


def _cleanup_existing_token(lib, pin: str) -> None:
    """Remove our objects from an existing token. Never touches other tokens.

    Production-safe: only destroys objects in our token (bunker-wif),
    never wipes the store or evicts unknown persistent handles.
    """
    try:
        token = lib.get_token(token_label=_TOKEN_LABEL)
    except (pkcs11.NoSuchToken, pkcs11.PKCS11Error):
        return

    try:
        with token.open(user_pin=pin, rw=True) as session:
            for obj in session.get_objects():
                try:
                    obj.destroy()
                    logger.debug("    Destroyed PKCS#11 object: %s", obj)
                except pkcs11.PKCS11Error as exc:
                    logger.debug("    Could not destroy object: %s", exc)
    except pkcs11.PKCS11Error as exc:
        logger.debug("    Could not open token for cleanup: %s", exc)

def _ensure_token_via_tpm2_ptool(pin: str, tpm_store: str) -> None:
    """Create our PKCS#11 token via ``tpm2_ptool`` if it doesn't exist.

    Must be called **before** ``pkcs11.lib()`` loads the module, because
    ``tpm2_ptool addtoken`` modifies the SQLite store directly and the
    in-process ``libtpm2_pkcs11.so`` only reads it at ``C_Initialize`` time.

    This is a no-op if ``tpm2_ptool`` is not available (non-TPM setups)
    or if a token with our label already exists in the store.
    """
    import shutil
    import subprocess

    tpm2_ptool = shutil.which("tpm2_ptool")
    if not tpm2_ptool:
        return

    # Check if our token already exists by listing tokens.
    try:
        result = subprocess.run(
            [tpm2_ptool, "listtokens", "--path", tpm_store],
            capture_output=True, text=True, check=False,
        )
        if _TOKEN_LABEL in result.stdout:
            logger.debug("    Token '%s' already exists in tpm2-pkcs11 store", _TOKEN_LABEL)
            return
    except FileNotFoundError:
        return

    # Ensure the store is initialized (creates primary object id=1).
    subprocess.run(
        [tpm2_ptool, "init", "--path", tpm_store],
        capture_output=True, text=True, check=False,
    )

    # Create the token with both PINs.
    try:
        subprocess.run(
            [
                tpm2_ptool, "addtoken",
                "--pid=1",
                "--sopin", pin,
                "--userpin", pin,
                "--label", _TOKEN_LABEL,
                "--path", tpm_store,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug(
            "    Created PKCS#11 token '%s' via tpm2_ptool addtoken",
            _TOKEN_LABEL,
        )
    except subprocess.CalledProcessError as exc:
        logger.debug(
            "    tpm2_ptool addtoken failed (will try pkcs11-tool later): %s\n"
            "    stderr: %s",
            exc, exc.stderr,
        )


def _init_token(lib, pin: str, module_path: str):
    """Initialize or find our PKCS#11 token.

    If our token exists, returns it. Otherwise finds a usable slot
    and creates a new token via ``pkcs11-tool`` (fallback for non-TPM
    PKCS#11 modules).

    On tpm2-pkcs11, ``_ensure_token_via_tpm2_ptool`` should have already
    created the token before the library was loaded.
    """
    import subprocess

    # 1. Check if our token already exists (normal path after tpm2_ptool)
    try:
        return lib.get_token(token_label=_TOKEN_LABEL)
    except (pkcs11.NoSuchToken, pkcs11.PKCS11Error):
        pass

    # 2. Fallback: find a usable slot and use pkcs11-tool.
    #    A slot is usable if:
    #      - its token is NOT initialized, OR
    #      - its token has a default/empty label (fresh store)
    #    We skip slots whose token has a non-empty label that
    #    isn't ours — those belong to other applications.
    for slot in lib.get_slots():
        try:
            token = slot.get_token()
            if TokenFlag.TOKEN_INITIALIZED in token.flags:
                label = (token.label or "").strip()
                if label and label != _TOKEN_LABEL:
                    logger.debug(
                        "    Skipping slot %s: token '%s' belongs to another app",
                        slot.slot_id, label,
                    )
                    continue
                logger.debug(
                    "    Found slot %s with default/empty token, will re-init as '%s'",
                    slot.slot_id, _TOKEN_LABEL,
                )
            else:
                logger.debug(
                    "    Found uninitialized slot %s, will init as '%s'",
                    slot.slot_id, _TOKEN_LABEL,
                )
        except (pkcs11.PKCS11Error, pkcs11.TokenNotPresent):
            pass

        try:
            slot_id = slot.slot_id
            subprocess.run(
                [
                    "pkcs11-tool",
                    "--module", module_path,
                    "--init-token",
                    "--slot", str(slot_id),
                    "--label", _TOKEN_LABEL,
                    "--so-pin", pin,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.debug("    Initialized PKCS#11 token '%s' via pkcs11-tool", _TOKEN_LABEL)

            # Initialize the user PIN — may fail on libtpm2_pkcs11
            # (CKR_SESSION_READ_ONLY) but works on OpenSC/SoftHSM.
            subprocess.run(
                [
                    "pkcs11-tool",
                    "--module", module_path,
                    "--init-pin",
                    "--token-label", _TOKEN_LABEL,
                    "--so-pin", pin,
                    "--new-pin", pin,
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            return lib.get_token(token_label=_TOKEN_LABEL)
        except subprocess.CalledProcessError as exc:
            logger.debug(
                "    pkcs11-tool init failed on slot %s: %s\n"
                "    stderr: %s",
                slot.slot_id, exc, getattr(exc, "stderr", ""),
            )
            continue

    raise RuntimeError(
        "No available PKCS#11 slot for token initialization.\n"
        "\n"
        "  All slots are occupied by other tokens.\n"
        "  Verify the TPM PKCS#11 store is not corrupted."
    )


# ── Public key extraction ──


def _extract_public_key_pem(pub_key) -> str:
    """Extract the public key from a PKCS#11 key object and return as PEM.

    Converts PKCS#11 key attributes into a ``cryptography`` public key
    object, then serializes to PEM for ``_create_ca_and_sign``.
    """
    key_type = pub_key.key_type

    if key_type == KeyType.EC:
        ec_point = pub_key[Attribute.EC_POINT]

        # EC_POINT is DER-encoded OCTET STRING wrapping the uncompressed point.
        # DER: 04 <len> 04 <x> <y>  — skip the outer OCTET STRING wrapper.
        if isinstance(ec_point, (bytes, bytearray)):
            raw = ec_point
        else:
            raw = bytes(ec_point)

        if raw[0] == 0x04 and len(raw) > 2 and raw[2] == 0x04:
            raw_point = raw[2:]
        else:
            raw_point = raw

        if len(raw_point) == 65:  # 1 + 32 + 32 → P-256
            curve = ec.SECP256R1()
        elif len(raw_point) == 97:  # 1 + 48 + 48 → P-384
            curve = ec.SECP384R1()
        else:
            raise RuntimeError(f"Unexpected EC point length: {len(raw_point)}")

        crypto_pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, raw_point)

    elif key_type == KeyType.RSA:
        modulus_bytes = pub_key[Attribute.MODULUS]
        exponent_bytes = pub_key[Attribute.PUBLIC_EXPONENT]
        modulus = int.from_bytes(bytes(modulus_bytes), "big")
        exponent = int.from_bytes(bytes(exponent_bytes), "big")
        crypto_pub = rsa.RSAPublicNumbers(exponent, modulus).public_key()

    else:
        raise RuntimeError(f"Unsupported PKCS#11 key type: {key_type}")

    return crypto_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


# ── Main certificate generation ──


def _generate_cert_linux(config: WorkloadConfig) -> CertificateBundle:
    """Generate a TPM 2.0-backed certificate via PKCS#11.

    Uses ``python-pkcs11`` to interact with ``libtpm2_pkcs11.so`` directly.
    Token initialization uses ``pkcs11-tool``; all other operations happen
    via the PKCS#11 C API.
    """
    _check_tpm_linux()
    lib_path = _find_pkcs11_lib()

    tpm2_algo = config.key_algo_config["linux_tpm2"]
    pkcs11_info = _ALGO_TO_PKCS11.get(tpm2_algo)
    if not pkcs11_info:
        raise RuntimeError(f"Unsupported algorithm for Linux TPM: {config.key_algorithm}")

    # Set TPM2_PKCS11_STORE — required by libtpm2_pkcs11.so
    tpm_store = Path.home() / ".tpm2_pkcs11"
    tpm_store.mkdir(parents=True, exist_ok=True)
    os.environ["TPM2_PKCS11_STORE"] = str(tpm_store)

    # Ensure our PKCS#11 token exists BEFORE loading the library.
    # tpm2_ptool addtoken modifies the SQLite store directly, and
    # libtpm2_pkcs11.so reads it only at C_Initialize time.  Creating
    # the token first avoids stale-cache issues entirely.
    _ensure_token_via_tpm2_ptool(config.linux_tpm_pin, str(tpm_store))

    try:
        lib = pkcs11.lib(lib_path)

        # 1. Clean up any previous objects in our token
        _cleanup_existing_token(lib, config.linux_tpm_pin)

        # 2. Find or initialize our token
        token = _init_token(lib, config.linux_tpm_pin, lib_path)
        logger.debug("    Using PKCS#11 token: %s", token)

        with token.open(user_pin=config.linux_tpm_pin, rw=True) as session:
            # 3. Generate key pair in the TPM
            logger.debug("    Generating %s key pair in TPM...", config.key_algorithm)

            if pkcs11_info["key_type"] == KeyType.EC:
                pub, _priv = session.generate_keypair(
                    KeyType.EC,
                    key_length=None,
                    mechanism=Mechanism.EC_KEY_PAIR_GEN,
                    store=True,
                    label=config.workload_cn,
                    attrs={Attribute.EC_PARAMS: pkcs11_info["params"]},
                )
            else:
                pub, _priv = session.generate_keypair(
                    KeyType.RSA,
                    key_length=pkcs11_info["key_length"],
                    store=True,
                    label=config.workload_cn,
                )

            logger.debug("    Key pair generated. Extracting public key...")

            # 4. Extract public key as PEM
            pub_key_pem = _extract_public_key_pem(pub)
            logger.debug("    Public key extracted successfully.")

            # 5. Create CA-signed workload cert
            bundle, workload_pem = _create_ca_and_sign(pub_key_pem, config)

            # 6. Import signed cert into PKCS#11 token
            workload_cert = cx509.load_pem_x509_certificate(workload_pem.encode())
            workload_der = workload_cert.public_bytes(serialization.Encoding.DER)

            # Link cert to key via CKA_ID
            key_id = pub[Attribute.ID]

            session.create_object(
                {
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
                    Attribute.LABEL: config.workload_cn,
                    Attribute.VALUE: workload_der,
                    Attribute.TOKEN: True,
                    Attribute.ID: key_id,
                }
            )

            logger.info("    CA-signed workload cert imported into TPM PKCS#11 store.")

        return bundle

    except pkcs11.PKCS11Error as exc:
        _handle_pkcs11_error(exc)
        raise  # unreachable but keeps type checker happy


def _handle_pkcs11_error(exc: pkcs11.PKCS11Error) -> None:
    """Convert PKCS#11 errors to actionable RuntimeError messages."""
    err_str = str(exc)

    if "CKR_TOKEN_NOT_RECOGNIZED" in err_str or "CKR_SLOT_ID_INVALID" in err_str:
        raise RuntimeError(
            "TPM PKCS#11 token not recognized.\n"
            "\n"
            "  The PKCS#11 store may be corrupted. Try:\n"
            "    rm -rf ~/.tpm2_pkcs11 && wif-bunker --cert-only"
        ) from exc

    if "CKR_DEVICE_ERROR" in err_str:
        raise RuntimeError(
            "TPM device error.\n"
            "\n"
            "  The TPM is not responding. Check:\n"
            "    ls -la /dev/tpmrm0\n"
            "\n"
            "  For development, start a software TPM:\n"
            "    swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 "
            "--server type=tcp,port=2321 --ctrl type=tcp,port=2322 &\n"
            "    export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'"
        ) from exc

    if "CKR_PIN_INCORRECT" in err_str:
        raise RuntimeError(
            "PKCS#11 PIN incorrect.\n"
            "\n"
            "  The stored PIN does not match the token. This can happen if\n"
            "  the token was recreated. Try:\n"
            "    rm -rf ~/.tpm2_pkcs11 && wif-bunker --cert-only"
        ) from exc

    raise RuntimeError(f"PKCS#11 operation failed: {exc}") from exc
