"""macOS Secure Enclave keystore: CryptoTokenKit key generation and cert management."""

from __future__ import annotations

import logging
import platform
import subprocess
import tempfile
import time
from pathlib import Path

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.utils import require_commands

logger = logging.getLogger(__name__)


def get_supported_algorithms_macos() -> list[str]:
    """Return algorithms supported by the macOS Secure Enclave.

    Apple Secure Enclave always supports P-256 and P-384.
    RSA is not supported by the Secure Enclave.
    """
    return ["es256", "es384"]


def _macos_login_keychain() -> str:
    """Returns the path to the macOS login keychain."""
    return str(Path.home() / "Library/Keychains/login.keychain-db")


def _generate_cert_macos(config: WorkloadConfig) -> CertificateBundle:
    """Generates a Secure Enclave-backed certificate via CryptoTokenKit (macOS 15+).

    Flow:
      1. Delete stale CTK identities from previous runs
      2. sc_auth create-ctk-identity → SE key + throwaway self-signed cert
      3. sc_auth identities          → look up the key's SHA-1 hash
      4. sc_auth create-ctk-csr      → proper CSR signed by the SE key
      5. Ephemeral CA signs the CSR  → CA-signed workload cert + import-ctk-certificate
    """
    # Pre-validate required commands.
    require_commands(
        [
            ("security", "", "Built-in macOS command — should always be at /usr/bin/security"),
            ("sc_auth", "", "Built-in macOS command — requires macOS 10.15+. Check /usr/bin/sc_auth"),
        ]
    )

    mac_ver_str = platform.mac_ver()[0]
    if mac_ver_str:
        major_ver = int(mac_ver_str.split(".")[0])
        if major_ver < 15:
            raise RuntimeError(
                f"Hardware-backed mTLS via CryptoTokenKit requires macOS 15+. Current version: {mac_ver_str}"
            )

    _tmpdir = tempfile.TemporaryDirectory(prefix="bunker_")  # pylint: disable=consider-using-with
    work_dir = Path(_tmpdir.name)

    try:
        # 0. Clean up stale CTK identities and login keychain certs
        #    from previous runs. Each run creates a new SE key; old
        #    ones are orphaned.
        id_result = subprocess.run(
            ["sc_auth", "identities"],
            check=True,
            capture_output=True,
            text=True,
        )
        for line in id_result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].startswith("bunker-"):
                old_hash = parts[0].strip()
                subprocess.run(
                    ["sc_auth", "delete-ctk-identity", "-h", old_hash],
                    capture_output=True,
                )
                logger.info("    Cleaned up stale CTK identity: %s", parts[1])

        # Also remove stale bunker-workload certs from the login keychain.
        login_kc = _macos_login_keychain()
        find_result = subprocess.run(
            ["security", "find-certificate", "-c", "bunker-workload", "-a", "-Z", login_kc],
            capture_output=True,
            text=True,
        )
        for line in find_result.stdout.splitlines():
            if "SHA-1" in line:
                sha1 = line.split()[-1]
                subprocess.run(
                    ["security", "delete-certificate", "-Z", sha1, login_kc],
                    capture_output=True,
                )

        # 1. Generate Secure Enclave key (+ throwaway self-signed cert)
        subprocess.run(
            [
                "sc_auth",
                "create-ctk-identity",
                "-l",
                config.workload_cn,
                "-N",
                config.workload_cn,
                "-k",
                config.key_algo_config["macos_sc_auth"],
                "-t",
                "none",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("    Secure Enclave key created: %s", config.workload_cn)

        # 2. Look up the key's SHA-1 hash from sc_auth identities.
        #    Retry briefly — the CTK token may need a moment to register
        #    the new identity after creation and stale identity deletion.
        #    CI runners (especially macOS ARM64) can be slow; allow up to ~10s.
        key_hash: str | None = None
        for _attempt in range(10):
            id_result = subprocess.run(
                ["sc_auth", "identities"],
                check=True,
                capture_output=True,
                text=True,
            )
            for line in id_result.stdout.splitlines():
                if config.workload_cn in line:
                    key_hash = line.split()[0]
            if key_hash:
                break
            time.sleep(1)
        if not key_hash:
            raise RuntimeError(
                f"Could not find key hash for '{config.workload_cn}' in sc_auth identities output:\n{id_result.stdout}"
            )
        logger.info("    SE key hash: %s", key_hash)

        # 3. Generate a CSR from the SE key (sc_auth appends .csr to filename)
        csr_basename = str(work_dir / "workload_csr")
        subprocess.run(
            [
                "sc_auth",
                "create-ctk-csr",
                "-h",
                key_hash,
                "-N",
                config.workload_cn,
                "-f",
                csr_basename,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        csr_path = Path(f"{csr_basename}.csr")
        if not csr_path.exists():
            raise FileNotFoundError(f"CSR not found at {csr_path} after sc_auth create-ctk-csr")
        csr_pem = csr_path.read_text(encoding="utf-8").strip()
        logger.info("    CSR generated from SE key.")

        # 4. Ephemeral CA signs the CSR → CA-signed workload cert
        bundle, workload_pem = _create_ca_and_sign(csr_pem, config)

        # 5. Replace the throwaway self-signed cert on the CTK identity
        #    with the CA-signed cert.  This links the cert to the SE key
        #    as a proper identity (visible in "My Certificates").
        workload_cert_path = work_dir / "workload_signed.pem"
        workload_cert_path.write_text(workload_pem)
        subprocess.run(
            [
                "sc_auth",
                "import-ctk-certificate",
                "-f",
                str(workload_cert_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("    CA-signed cert linked to SE key via import-ctk-certificate.")

        return bundle

    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        cmd_name = exc.cmd[0] if isinstance(exc.cmd, list) else str(exc.cmd)
        if "-25293" in stderr or "errSecAuthFailed" in stderr:
            raise RuntimeError(
                f"Secure Enclave key generation denied (command: {cmd_name}).\n"
                "macOS blocked access to the Secure Enclave.\n"
                "\n"
                "  Possible causes:\n"
                "    - Running in a VM without SE support\n"
                "    - User denied the biometric/passcode prompt"
            ) from exc
        raise RuntimeError(
            f"macOS certificate generation failed (command: {cmd_name}, "
            f"exit code: {exc.returncode}).\n"
            f"  stderr: {stderr[:500]}"
        ) from exc
    finally:
        _tmpdir.cleanup()
