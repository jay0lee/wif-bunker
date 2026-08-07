"""Linux/TPM 2.0 keystore: PKCS#11 key generation and certificate management.

Uses ``python-pkcs11`` to interact with the TPM via ``libtpm2_pkcs11.so``.
Key pair generation uses ``pkcs11-tool`` for compatibility with
``libtpm2_pkcs11``'s strict template requirements.

System requirements: ``libtpm2_pkcs11.so``, ``pkcs11-tool``, and
optionally ``tpm2_ptool`` (for automatic token creation).
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
        "key_length": 256,
        "params": encode_named_curve_parameters("secp256r1"),
        "mechanism": Mechanism.ECDSA,
    },
    "ecc384": {
        "key_type": KeyType.EC,
        "key_length": 384,
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
        if not pkcs11_info or pkcs11_info["mechanism"] not in mechs:
            continue

        # Check key size limits — some TPMs support the mechanism
        # (e.g. ECDSA) but only for specific key sizes (e.g. 256-bit only).
        key_bits = pkcs11_info.get("key_length", 0)
        if key_bits:
            try:
                mech_info = slots[0].get_mechanism_info(pkcs11_info["mechanism"])
                if key_bits < mech_info.min_key_length or key_bits > mech_info.max_key_length:
                    logger.debug(
                        "    %s: key size %d outside mechanism range [%d, %d]",
                        algo_name, key_bits, mech_info.min_key_length, mech_info.max_key_length,
                    )
                    continue
            except pkcs11.PKCS11Error:
                pass  # Can't query info — assume supported

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

def _ensure_token_via_tpm2_ptool(pin: str, tpm_store: str, module_path: str) -> None:
    """Create our PKCS#11 token via ``tpm2_ptool`` if it doesn't exist.

    Must be called **before** ``pkcs11.lib()`` loads the module, because
    ``tpm2_ptool addtoken`` modifies the SQLite store directly and the
    in-process ``libtpm2_pkcs11.so`` only reads it at ``C_Initialize`` time.

    If the token exists but the PIN doesn't match (e.g. from a previous
    run that used a different random PIN), the token is removed and
    recreated. This is safe because ``bunker-wif`` is our own token.
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
            # Token exists — verify our PIN works by forcing a login.
            # (--list-objects without --login succeeds even with wrong PIN
            # because it only lists public objects.)
            verify = subprocess.run(
                [
                    "pkcs11-tool",
                    "--module", module_path,
                    "--token-label", _TOKEN_LABEL,
                    "--login",
                    "--pin", pin,
                    "--list-objects",
                ],
                capture_output=True, text=True, check=False,
            )
            if verify.returncode == 0:
                logger.debug("    Token '%s' exists and PIN is valid", _TOKEN_LABEL)
                return

            # PIN mismatch — remove and recreate.
            logger.debug(
                "    Token '%s' exists but PIN is invalid, recreating",
                _TOKEN_LABEL,
            )
            subprocess.run(
                [tpm2_ptool, "rmtoken", "--label", _TOKEN_LABEL, "--path", tpm_store],
                capture_output=True, text=True, check=False,
            )
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
            "    tpm2_ptool addtoken failed: %s\n"
            "    stderr: %s",
            exc, exc.stderr,
        )


def _init_token(lib, pin: str, module_path: str):
    """Find our PKCS#11 token.

    The token should already exist — created by either:
      - CI's 'Reset TPM to clean state' step (via tpm2_ptool addtoken)
      - ``_ensure_token_via_tpm2_ptool`` (called before lib was loaded)
      - Manual setup by the user
    """
    try:
        return lib.get_token(token_label=_TOKEN_LABEL)
    except (pkcs11.NoSuchToken, pkcs11.PKCS11Error) as exc:
        raise RuntimeError(
            f"PKCS#11 token '{_TOKEN_LABEL}' not found.\n"
            "\n"
            "  The TPM PKCS#11 store must be initialized with a token\n"
            "  before WIF Bunker can generate keys.  Run:\n"
            "\n"
            "    tpm2_ptool init --path=~/.tpm2_pkcs11\n"
            "    tpm2_ptool addtoken --pid=1 --sopin=PIN --userpin=PIN "
            "--label=bunker-wif --path=~/.tpm2_pkcs11\n"
        ) from exc


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


# ── TPM-compatible key generation via pkcs11-tool ──


def _run_pkcs11_tool_keygen(
    module_path: str, token_label: str, pin: str,
    key_type: str, label: str,
) -> None:
    """Generate a key pair using ``pkcs11-tool``.

    ``python-pkcs11``'s ``generate_keypair()`` sets capability attributes
    (``CKA_ENCRYPT``, ``CKA_VERIFY``, etc.) that ``libtpm2_pkcs11`` rejects
    for EC keys.  Using ``pkcs11-tool --keypairgen`` avoids this entirely.

    Must be called **before** opening a python-pkcs11 session on the same
    token, because ``pkcs11-tool`` opens its own session.

    Args:
        module_path: Path to libtpm2_pkcs11.so.
        token_label: PKCS#11 token label.
        pin: User PIN for the token.
        key_type: pkcs11-tool key type string (e.g. 'EC:prime256v1', 'RSA:2048').
        label: Label to assign to the generated key objects.
    """
    import subprocess

    try:
        result = subprocess.run(
            [
                "pkcs11-tool",
                "--module", module_path,
                "--token-label", token_label,
                "--pin", pin,
                "--keypairgen",
                "--key-type", key_type,
                "--label", label,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("    pkcs11-tool keygen output: %s", result.stdout.strip())
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"pkcs11-tool --keypairgen failed for {key_type}:\n"
            f"  stdout: {exc.stdout.strip()}\n"
            f"  stderr: {exc.stderr.strip()}"
        ) from exc


def _find_key_objects(session, label: str):
    """Find public and private key objects by label in the session."""
    pub = None
    priv = None
    for obj in session.get_objects({Attribute.LABEL: label}):
        obj_class = obj[Attribute.CLASS]
        if obj_class == ObjectClass.PUBLIC_KEY:
            pub = obj
        elif obj_class == ObjectClass.PRIVATE_KEY:
            priv = obj

    if pub is None or priv is None:
        raise RuntimeError(
            f"Key pair not found in PKCS#11 session for label '{label}' "
            f"(pub={pub}, priv={priv})"
        )

    return pub, priv


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

    # ── All subprocess/external operations BEFORE pkcs11.lib() ──
    # libtpm2_pkcs11.so caches tokens and objects at C_Initialize time.
    # Any modifications to the SQLite store after that are invisible.

    # 1. Ensure our token exists
    _ensure_token_via_tpm2_ptool(config.linux_tpm_pin, str(tpm_store), lib_path)

    # 2. Generate key pair via pkcs11-tool
    logger.debug("    Generating %s key pair in TPM...", config.key_algorithm)
    if pkcs11_info["key_type"] == KeyType.EC:
        ec_curve = {
            "ecc256": "prime256v1",
            "ecc384": "secp384r1",
        }.get(tpm2_algo)
        pkcs11_key_type = f"EC:{ec_curve}"
    else:
        pkcs11_key_type = f"RSA:{pkcs11_info['key_length']}"

    _run_pkcs11_tool_keygen(
        module_path=lib_path,
        token_label=_TOKEN_LABEL,
        pin=config.linux_tpm_pin,
        key_type=pkcs11_key_type,
        label=config.workload_cn,
    )

    # ── Now load the library — it will see our token AND keys ──
    try:
        lib = pkcs11.lib(lib_path)
        token = lib.get_token(token_label=_TOKEN_LABEL)
        logger.debug("    Using PKCS#11 token: %s", token)

        with token.open(user_pin=config.linux_tpm_pin, rw=True) as session:
            # 3. Find the generated key objects
            pub, _priv = _find_key_objects(session, config.workload_cn)

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
