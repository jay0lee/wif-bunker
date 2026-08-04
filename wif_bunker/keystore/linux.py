"""Linux/TPM 2.0 keystore: PKCS#11 key generation and certificate management."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.utils import _require_command, write_secure_file

logger = logging.getLogger(__name__)


def _resolve_tpm2_ptool() -> list[str]:
    """Resolve a working tpm2_ptool command.

    On Ubuntu 26.04, the system wrapper at /usr/bin/tpm2_ptool is broken:
    the easy_install entry-point hardcodes a version that doesn't match the
    installed Python package.  We detect this by running ``tpm2_ptool --help``
    and, if it fails with an importlib/entry_point error, fall back to
    invoking the module directly via ``python3 -m tpm2_pkcs11.tpm2_ptool``.
    """
    ptool_path = shutil.which("tpm2_ptool")
    if ptool_path:
        try:
            probe = subprocess.run(
                ["tpm2_ptool", "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if probe.returncode == 0:
                return ["tpm2_ptool"]
        except (subprocess.TimeoutExpired, OSError):
            pass
        # Binary exists but is broken — check stderr for entry_point crash
        logger.debug(
            "tpm2_ptool wrapper is broken (likely Ubuntu packaging bug), "
            "falling back to python3 -m tpm2_pkcs11.tpm2_ptool"
        )

    # Fall back to invoking the Python module directly
    python = sys.executable or shutil.which("python3") or "python3"
    try:
        probe = subprocess.run(
            [python, "-m", "tpm2_pkcs11.tpm2_ptool", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if probe.returncode == 0:
            return [python, "-m", "tpm2_pkcs11.tpm2_ptool"]
    except (subprocess.TimeoutExpired, OSError):
        pass

    raise RuntimeError(
        "tpm2_ptool is not working.\n"
        "\n"
        "  The system wrapper may be broken (Ubuntu packaging bug).\n"
        "  Install: sudo apt install libtpm2-pkcs11-1 "
        "libtpm2-pkcs11-tools python3-tpm2-pkcs11-tools"
    )


def _check_tpm_linux() -> None:
    """Pre-validate TPM availability on Linux.

    Checks for hardware TPM device (/dev/tpmrm0) or software TPM.
    Raises RuntimeError with actionable guidance if no TPM is accessible.
    """
    # 1. Hardware TPM device node
    tpm_device = Path("/dev/tpmrm0")
    if tpm_device.exists():
        return  # Hardware TPM available

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
        "No TPM device or service found.\n"
        "\n"
        "  wif_bunker requires a TPM 2.0 for hardware-backed keys.\n"
        "\n"
        "  Options:\n"
        "    1. Hardware TPM — check that /dev/tpmrm0 exists:\n"
        "         ls -la /dev/tpmrm0\n"
        "       If missing, ensure the TPM is enabled in BIOS/UEFI.\n"
        "\n"
        "    2. Software TPM (development/testing) — install and start swtpm:\n"
        "         sudo apt install swtpm swtpm-tools\n"
        "         mkdir -p /tmp/swtpm\n"
        "         swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 "
        "--server type=tcp,port=2321 --ctrl type=tcp,port=2322 &\n"
        "         export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'"
    )


def _generate_cert_linux(config: WorkloadConfig) -> CertificateBundle:
    """Generates a TPM 2.0-backed certificate via PKCS#11 toolchain (Ubuntu 24+)."""
    # Pre-validate required commands.
    ptool_cmd = _resolve_tpm2_ptool()
    _require_command("p11tool", package="gnutls-bin", install_hint="sudo apt install gnutls-bin")
    _require_command("pkcs11-tool", package="opensc", install_hint="sudo apt install opensc")
    # Also need certtool from gnutls-bin for CSR generation.
    _require_command("certtool", package="gnutls-bin", install_hint="sudo apt install gnutls-bin")

    # Check TPM availability.
    _check_tpm_linux()

    tpm_store = Path.home() / ".tpm2_pkcs11"
    os.environ["TPM2_PKCS11_STORE"] = str(tpm_store)
    tpm_store.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Initialize TPM PKCS#11 token and generate hardware-backed key
        init_result = subprocess.run(
            [*ptool_cmd, "init"],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("    tpm2_ptool init: %s", init_result.stdout.strip())

        # Remove existing token if present (reuse flow).
        subprocess.run(
            [*ptool_cmd, "rmtoken", "--label=bunker-wif"],
            capture_output=True,
            text=True,
        )  # Ignore errors — token may not exist yet.

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
        # Fallback: include the raw error with the failing command.
        raise RuntimeError(
            f"Linux TPM operation failed (command: {cmd_name}, "
            f"exit code: {exc.returncode}).\n"
            f"  stderr: {stderr[:500]}\n"
            "\n"
            "  Ensure libtpm2-pkcs11-tools and gnutls-bin are installed:\n"
            "    sudo apt install libtpm2-pkcs11-1 libtpm2-pkcs11-tools "
            "python3-tpm2-pkcs11-tools gnutls-bin opensc"
        ) from exc
