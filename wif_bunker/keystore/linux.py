"""Linux/TPM 2.0 keystore: PKCS#11 key generation and certificate management.

.. ai-note::
   IMPORTANT FOR AI AGENTS: Before reading, editing, or debugging this file,
   you MUST read docs/keystore-linux-tpm.md in the repository root.
   That document covers the tpm2_ptool commands, PKCS#11 URI format,
   NV handle cleanup (the "No Space Left" bug), the Ubuntu tpm2_ptool
   wrapper bug, SQLite schema gotchas, and algorithm mapping.
   If you make changes to this file, update docs/keystore-linux-tpm.md
   to match.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.utils import require_commands, write_secure_file

logger = logging.getLogger(__name__)


def _resolve_tpm2_ptool() -> list[str]:
    """Resolve a working tpm2_ptool command.

    ``tpm2_ptool`` is a system CLI tool installed via the OS package manager
    (e.g. ``python3-tpm2-pkcs11-tools`` on Ubuntu).  We call it via subprocess
    just like ``certtool``, ``pkcs11-tool``, and other system tools.
    """
    ptool_path = shutil.which("tpm2_ptool")
    if ptool_path:
        try:
            probe = subprocess.run(
                ["tpm2_ptool", "listprimaries"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if probe.returncode == 0:
                return ["tpm2_ptool"]
            # Wrapper exists but doesn't work — log stderr for diagnostics
            logger.debug(
                "tpm2_ptool returned exit code %d: %s",
                probe.returncode,
                probe.stderr.strip()[:200],
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("tpm2_ptool probe failed: %s", exc)

    raise RuntimeError(
        "tpm2_ptool is not working.\n"
        "\n"
        "  tpm2_ptool is required to manage TPM PKCS#11 tokens.\n"
        "  Verify it is installed and functional:\n"
        "    tpm2_ptool listprimaries"
    )


def _check_tpm_linux() -> None:
    """Pre-validate TPM availability on Linux.

    Checks for hardware TPM device (/dev/tpmrm0) or software TPM.
    Raises RuntimeError with actionable guidance if no TPM is accessible.
    """
    # 1. Hardware TPM device node
    tpm_device = Path("/dev/tpmrm0")
    if tpm_device.exists():
        if os.access(tpm_device, os.R_OK | os.W_OK):
            return  # Hardware TPM available and accessible

        # Device exists but user can't access it — almost always a group issue
        import grp
        import pwd

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

    # 2. Check for software TPM (swtpm) via TCTI env or port probe
    if os.environ.get("TPM2TOOLS_TCTI"):
        return  # User has explicitly configured a TCTI (e.g. swtpm)
    try:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect(("127.0.0.1", 2321))
            return  # swtpm is listening on the default port
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


def _check_tpm_algorithm(algo: str) -> None:
    """Verify the TPM supports the requested algorithm before key creation.

    Uses ``tpm2_testparms`` to probe the TPM for algorithm support.
    Raises RuntimeError with a clear message if the algorithm/curve is
    not supported by the hardware.
    """
    # Map tpm2_ptool algorithm names to tpm2_testparms parameter strings
    testparms_map = _TPM2_TESTPARMS_MAP
    testparms_arg = testparms_map.get(algo)
    if not testparms_arg:
        return  # Unknown algo — let tpm2_ptool handle it

    tpm2_testparms = shutil.which("tpm2_testparms")
    if not tpm2_testparms:
        return  # Can't check — proceed and let tpm2_ptool fail naturally

    result = subprocess.run(
        ["tpm2_testparms", testparms_arg],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Build a helpful error message
        curve_name = {"ecc256": "P-256", "ecc384": "P-384"}.get(algo, algo)
        supported_info = ""
        if algo.startswith("ecc"):
            # Query supported ECC curves for a better message
            cap_result = subprocess.run(
                ["tpm2_getcap", "ecc-curves"],
                capture_output=True,
                text=True,
            )
            if cap_result.returncode == 0 and cap_result.stdout.strip():
                supported_info = f"\n  Supported ECC curves: {cap_result.stdout.strip()}"
        raise RuntimeError(
            f"This TPM does not support {curve_name} ({algo}).{supported_info}\n"
            f"\n"
            f"  Many firmware TPMs (Intel PTT, AMD fTPM) only support P-256.\n"
            f"  Try a different algorithm: --key-algorithm es256"
        )


# Shared mapping between _check_tpm_algorithm and get_supported_algorithms_linux
_TPM2_TESTPARMS_MAP = {
    "ecc256": "ecc256:ecdsa",
    "ecc384": "ecc384:ecdsa",
    "rsa2048": "rsa2048",
    "rsa3072": "rsa3072",
    "rsa4096": "rsa4096",
}


def get_supported_algorithms_linux() -> list[str]:
    """Probe the TPM for all supported algorithms.

    Returns a list of wif-bunker algorithm names (e.g. ``["es256", "rsa2048"]``)
    that the TPM hardware supports.

    Requires ``tpm2_testparms`` to be installed.
    """
    from wif_bunker.config import _KEY_ALGORITHMS  # pylint: disable=import-outside-toplevel

    _check_tpm_linux()

    tpm2_testparms = shutil.which("tpm2_testparms")
    if not tpm2_testparms:
        raise RuntimeError("tpm2_testparms not found.\n  Ensure tpm2-tools is installed and on PATH.")

    supported = []
    for algo_name, algo_info in _KEY_ALGORITHMS.items():
        if "linux" not in algo_info["platforms"]:
            continue
        tpm2_algo = algo_info["linux_tpm2"]
        testparms_arg = _TPM2_TESTPARMS_MAP.get(tpm2_algo)
        if not testparms_arg:
            continue
        result = subprocess.run(
            ["tpm2_testparms", testparms_arg],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            supported.append(algo_name)
    return supported


def _evict_bunker_persistent_handles(tpm_store: Path, ptool_cmd: list[str], log: logging.Logger) -> None:
    """Evict only persistent handles owned by our 'bunker-wif' token.

    tpm2_ptool rmtoken removes the PKCS#11 token from the SQLite store
    but does NOT evict the TPM primary object from NV storage.  We must
    clean up our own handles to avoid orphans that cause addprimary to
    fail on subsequent runs.

    IMPORTANT: We only evict handles we can prove belong to our token.
    Other applications (disk encryption, Secure Boot, VPN keys, etc.)
    may have their own persistent handles — we must never touch those.
    """
    import re  # pylint: disable=import-outside-toplevel

    if not tpm_store.exists():
        return

    # 1. Ask tpm2_ptool for our token's primary object handle(s).
    #    listprimaries shows the esys-tr / persistent handle for each PID.
    our_handles: list[str] = []
    try:
        result = subprocess.run(
            [*ptool_cmd, "listprimaries"],
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "TPM2_PKCS11_STORE": str(tpm_store)},
        )
        # Output lines contain handle values like "0x81000001"
        our_handles = re.findall(r"0x[0-9A-Fa-f]+", result.stdout)
    except Exception as exc:
        log.debug("    Could not list primaries from store: %s", exc)

    if not our_handles:
        # Fallback: if the store DB is corrupt or listprimaries fails,
        # check if there's ONLY one persistent handle in the TPM and
        # the store directory exists (implying we created it).
        # If multiple handles exist, we can't tell which is ours — skip.
        try:
            cap = subprocess.run(
                ["tpm2_getcap", "handles-persistent"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            all_handles = re.findall(r"0x[0-9A-Fa-f]+", cap.stdout)
            if len(all_handles) == 1:
                our_handles = all_handles
                log.debug("    Fallback: single persistent handle %s likely ours.", all_handles[0])
            elif all_handles:
                log.debug(
                    "    %d persistent handles found but cannot identify ours — skipping eviction.",
                    len(all_handles),
                )
        except Exception as exc:
            log.debug("    Could not enumerate persistent handles: %s", exc)

    for h in our_handles:
        try:
            subprocess.run(
                ["tpm2_evictcontrol", "-c", h],
                capture_output=True,
                text=True,
                timeout=10,
            )
            log.debug("    Evicted bunker-wif persistent handle %s.", h)
        except Exception as exc:
            log.debug("    Could not evict handle %s: %s", h, exc)


def _generate_cert_linux(config: WorkloadConfig) -> CertificateBundle:
    """Generates a TPM 2.0-backed certificate via PKCS#11 toolchain (Ubuntu 24+)."""
    # Pre-validate all required commands upfront.
    ptool_cmd = _resolve_tpm2_ptool()
    require_commands(
        [
            ("p11tool", "gnutls-bin", "sudo apt install gnutls-bin"),
            ("pkcs11-tool", "opensc", "sudo apt install opensc"),
            ("certtool", "gnutls-bin", "sudo apt install gnutls-bin"),
        ]
    )

    # Check TPM availability.
    _check_tpm_linux()

    # Verify the requested algorithm is supported by this TPM.
    tpm_algo = config.key_algo_config["linux_tpm2"]
    _check_tpm_algorithm(tpm_algo)

    tpm_store = Path.home() / ".tpm2_pkcs11"
    os.environ["TPM2_PKCS11_STORE"] = str(tpm_store)

    try:
        # 1. Clean up any previous token + its TPM persistent handles.
        #    rmtoken removes the logical token from the SQLite store;
        #    _evict_bunker_persistent_handles evicts the TPM primary.
        #
        #    IMPORTANT: We do NOT wipe the store directory (shutil.rmtree).
        #    The SQLite DB schema is created by the system libtpm2_pkcs11.so
        #    package.  If we delete it and let tpm2_ptool (Python) recreate
        #    it, the new DB may have a different schema version, causing
        #    "no such table: schema" → CKR_OPERATION_NOT_INITIALIZED when
        #    the C library tries to read it.
        if tpm_store.exists():
            subprocess.run(
                [*ptool_cmd, "rmtoken", "--label=bunker-wif"],
                capture_output=True,
                text=True,
            )  # Ignore errors — token may not exist yet.

        _evict_bunker_persistent_handles(tpm_store, ptool_cmd, logger)

        # 2. Initialize PKCS#11 store — ONLY if the DB doesn't exist yet.
        #
        #    CRITICAL: tpm2_ptool init (Python) creates a SQLite schema that
        #    may be incompatible with the system libtpm2_pkcs11.so (C library).
        #    If the DB already exists (created by pkcs11-tool or a previous
        #    init), re-running init after rmtoken can corrupt/migrate the
        #    schema, causing "no such table: schema" → CKR_OPERATION_NOT_INITIALIZED.
        #
        #    On a second run, rmtoken + evictcontrol is sufficient cleanup;
        #    the DB file and its schema are preserved for the C library.
        tpm_store.mkdir(parents=True, exist_ok=True)
        db_file = tpm_store / "tpm2_pkcs11.sqlite3"
        if not db_file.exists():
            init_result = subprocess.run(
                [*ptool_cmd, "init"],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.debug("    tpm2_ptool init: %s", init_result.stdout.strip())
        else:
            logger.debug("    PKCS#11 store DB exists — skipping tpm2_ptool init to preserve schema.")

        token_result = subprocess.run(
            [
                *ptool_cmd,
                "addtoken",
                "--pid=1",
                f"--sopin={config.linux_tpm_pin}",
                f"--userpin={config.linux_tpm_pin}",
                "--label=bunker-wif",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("    tpm2_ptool addtoken: %s", token_result.stdout.strip())

        key_result = subprocess.run(
            [
                *ptool_cmd,
                "addkey",
                f"--algorithm={config.key_algo_config['linux_tpm2']}",
                "--label=bunker-wif",
                f"--key-label={config.workload_cn}",
                f"--userpin={config.linux_tpm_pin}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("    tpm2_ptool addkey: %s", key_result.stdout.strip())

        # Verify the token is visible via p11-kit before calling certtool
        try:
            p11_result = subprocess.run(
                ["p11tool", "--list-tokens"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            logger.debug("    p11tool --list-tokens:\n%s", p11_result.stdout)
            if "bunker-wif" not in p11_result.stdout:
                logger.warning("    Token 'bunker-wif' not visible to p11tool!")
                # Try listing via pkcs11-tool as fallback diagnostic
                try:
                    pkcs11_result = subprocess.run(
                        ["pkcs11-tool", "--module", "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so", "-T"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    logger.debug("    pkcs11-tool -T:\n%s", pkcs11_result.stdout)
                except Exception:
                    pass
        except Exception as p11_err:
            logger.debug("    p11tool check failed: %s", p11_err)

        # 2. Generate a temporary self-signed cert to extract the public key
        cert_cfg = f'cn = "{config.workload_cn}"\nexpiration_days = 365\ntls_www_client\n'
        write_secure_file("cert.cfg", cert_cfg)

        # Set GNUTLS_PIN so certtool can access the token without
        # relying solely on pin-value in the PKCS#11 URI.
        os.environ["GNUTLS_PIN"] = config.linux_tpm_pin

        pkcs11_uri = (
            f"pkcs11:token=bunker-wif;object={config.workload_cn};type=private;pin-value={config.linux_tpm_pin}"
        )
        subprocess.run(
            [
                "certtool",
                "--generate-self-signed",
                "--load-privkey",
                pkcs11_uri,
                "--template",
                "cert.cfg",
                "--outfile",
                "bunker-workload-selfsigned.pem",
            ],
            check=True,
            capture_output=True,
        )

        se_pem = Path("bunker-workload-selfsigned.pem").read_text(encoding="utf-8").strip()

        # 3. Create CA-signed workload cert
        bundle, workload_pem = _create_ca_and_sign(se_pem, config)

        # 4. Write the CA-signed cert and import into PKCS#11 store
        #    addcert needs --key-id (CKA_ID from addkey) and prompts for PIN.
        Path("bunker-workload-public.pem").write_text(workload_pem, encoding="utf-8")

        # Extract CKA_ID from addkey output
        key_id = None
        for line in key_result.stdout.splitlines():
            if "CKA_ID" in line and key_id is None:
                key_id = line.split("'")[1] if "'" in line else line.split()[-1]
        if not key_id:
            raise RuntimeError("Could not extract CKA_ID from tpm2_ptool addkey output: " + key_result.stdout)
        logger.debug("    Using CKA_ID: %s", key_id)

        subprocess.run(
            [
                *ptool_cmd,
                "addcert",
                "--label=bunker-wif",
                f"--key-id={key_id}",
                "bunker-workload-public.pem",
            ],
            input=config.linux_tpm_pin + "\n",
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("    CA-signed workload cert imported into TPM PKCS#11 store.")

        return bundle

    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        cmd_name = exc.cmd[0] if isinstance(exc.cmd, list) else str(exc.cmd)
        # Parse known error patterns for actionable guidance.
        if "Could not load tcti" in stderr or "No standard TCTI" in stderr:
            raise RuntimeError(
                f"TPM communication failed (command: {cmd_name}).\n"
                "The TPM tools are installed but cannot connect to a TPM device.\n"
                "\n"
                "  Options:\n"
                "    1. Verify the kernel resource manager exists:\n"
                "         ls -la /dev/tpmrm0\n"
                "\n"
                "    2. For development, start a software TPM:\n"
                "         swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 "
                "--server type=tcp,port=2321 --ctrl type=tcp,port=2322 &\n"
                "         export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'"
            ) from exc
        if "timed out" in stderr:
            raise RuntimeError(
                f"TPM resource manager timed out (command: {cmd_name}).\n"
                "The kernel TPM resource manager is not responding.\n"
                "\n"
                "  Verify: ls -la /dev/tpmrm0\n"
                "\n"
                "  If using a software TPM, set the TCTI environment variable:\n"
                "    export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'"
            ) from exc
        if "/dev/tpmrm0" in stderr or "/dev/tpm0" in stderr:
            raise RuntimeError(
                f"No TPM device found (command: {cmd_name}).\n"
                "The system does not have /dev/tpmrm0 or /dev/tpm0.\n"
                "\n"
                "  For development/testing, use a software TPM (swtpm)."
            ) from exc
        if "insufficient space" in stderr or "0x14b" in stderr.lower():
            raise RuntimeError(
                f"TPM NV storage is full (command: {cmd_name}).\n"
                "  Previous runs left persistent handles that were not evicted.\n"
                "\n"
                "  To fix, evict stale handles:\n"
                "    # List persistent handles:\n"
                "    tpm2_getcap handles-persistent\n"
                "    # Evict each one (use caution — only evict handles you own):\n"
                "    tpm2_evictcontrol -c 0x81000001\n"
                "\n"
                "  Or if using tpm2_pkcs11, remove the token properly:\n"
                "    export TPM2_PKCS11_STORE=~/.tpm2_pkcs11\n"
                "    tpm2_ptool rmtoken --label=bunker-wif"
            ) from exc
        # Fallback: include the raw error with the failing command.
        raise RuntimeError(
            f"Linux TPM operation failed (command: {cmd_name}, exit code: {exc.returncode}).\n  stderr: {stderr[:500]}"
        ) from exc
