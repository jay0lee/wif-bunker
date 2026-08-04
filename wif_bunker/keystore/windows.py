"""Windows CNG/TPM keystore: key generation via NCrypt and certificate management.

Creates TPM-backed keys directly via NCrypt ctypes (no certreq dependency)
and imports certificates via PowerShell CNG classes.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization

from wif_bunker.cert import _create_ca_and_sign
from wif_bunker.config import CertificateBundle, WorkloadConfig
from wif_bunker.keystore import ncrypt
from wif_bunker.utils import SYM_WARN, require_commands

# Ensures Cert: drive + PKI cmdlets work in both Windows PowerShell 5.1 and PowerShell 7+.
# Microsoft.PowerShell.Security provides the Cert: drive; PKI provides Import-Certificate.
_PS_CERT_PREAMBLE = (
    "Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue; "
    "Import-Module PKI -ErrorAction SilentlyContinue; "
)

logger = logging.getLogger(__name__)


def _generate_cert_windows(config: WorkloadConfig) -> CertificateBundle:
    """Generates a TPM 2.0-backed certificate via NCrypt + PowerShell.

    Flow:
      1. Clean up stale bunker-workload-* certs from previous runs
      2. Create TPM key via NCrypt ctypes (with attestation support)
      3. Export public key from TPM
      4. Ephemeral CA signs a workload cert for that public key
      5. PowerShell imports cert + binds it to the TPM key container

    Unlike the previous certreq-based flow, this approach:
    - Does NOT require certreq.exe
    - Does NOT install the ephemeral CA into the Root trust store
    - Does NOT trigger a Windows security dialog
    - Creates keys that support NCryptCreateClaim attestation
    """
    require_commands([
        ("powershell", "", "Built-in Windows command — ensure PowerShell is on PATH"),
    ])

    algo = config.key_algo_config
    ncrypt_algo = algo["ncrypt_algo"]
    ncrypt_key_length = algo.get("ncrypt_key_length")

    key_handle = None

    try:
        # 0. Clean up stale bunker-workload certs from previous runs.
        ps_cleanup = (
            f"{_PS_CERT_PREAMBLE}"
            "Get-ChildItem Cert:\\CurrentUser\\My | "
            "Where-Object { $_.Subject -like 'CN=bunker-workload-*' } | "
            "Remove-Item -Force"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cleanup],
            capture_output=True,
            text=True,
        )
        logger.info("    Cleaned up stale bunker-workload certs from CurrentUser store.")

        # Also clean up any stale NCrypt key container with the same name.
        ncrypt.delete_key(config.workload_cn, soft_key=config.soft_key)

        # 1. Create TPM key via NCrypt ctypes.
        if config.soft_key:
            logger.warning(
                "    %s  --soft-key: using software keys (NOT TPM-backed). "
                "For production use, remove --soft-key to use the TPM.",
                SYM_WARN,
            )
        key_handle = ncrypt.create_tpm_key(
            key_name=config.workload_cn,
            algorithm=ncrypt_algo,
            key_length=ncrypt_key_length,
            soft_key=config.soft_key,
        )

        # 2. Export public key from TPM.
        pub_key_pem = ncrypt.export_public_key_pem(key_handle, ncrypt_algo)
        logger.info("    Public key exported from TPM: %s", config.workload_cn)

        # 3. Ephemeral CA signs a workload cert using the TPM's public key.
        bundle, workload_pem = _create_ca_and_sign(pub_key_pem, config)

        # 4. Import cert into CurrentUser\My and bind to TPM key.
        #    Uses crypt32.dll to set CERT_KEY_PROV_INFO — this is what
        #    certreq -accept does internally, but without requiring the
        #    issuing CA in the Root trust store.
        workload_cert_obj = cx509.load_pem_x509_certificate(workload_pem.encode())
        workload_der = workload_cert_obj.public_bytes(serialization.Encoding.DER)

        provider_name = ncrypt.MS_SOFTWARE_KSP if config.soft_key else ncrypt.MS_PLATFORM_CRYPTO_PROVIDER
        ncrypt.import_cert_to_store(workload_der, config.workload_cn, provider_name)

        # 5. Verify the cert was imported successfully.
        workload_thumbprint = workload_cert_obj.fingerprint(hashes.SHA1()).hex().upper()
        ps_verify = (
            f"{_PS_CERT_PREAMBLE}"
            f"@(Get-ChildItem Cert:\\CurrentUser\\My | "
            f"Where-Object {{ $_.Thumbprint -eq '{workload_thumbprint}' }}).Count"
        )
        verify_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_verify],
            capture_output=True,
            text=True,
        )
        if verify_result.stdout.strip() != "1":
            raise RuntimeError(
                f"Workload cert was not found in CurrentUser\\My store "
                f"after import (thumbprint: {workload_thumbprint})."
            )

        return bundle

    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise RuntimeError(
            f"Windows certificate generation failed (PowerShell, "
            f"exit code: {exc.returncode}).\n"
            f"  stdout: {(exc.stdout or '')[:300]}\n"
            f"  stderr: {stderr[:500]}"
        ) from exc
    except RuntimeError:
        # Re-raise RuntimeError directly (from ncrypt.py or our own checks)
        raise
    except Exception as exc:
        raise RuntimeError(f"Windows certificate generation failed: {exc}") from exc
    finally:
        if key_handle is not None:
            ncrypt.free_object(key_handle)


def _find_ecp_binaries() -> tuple[Path, Path, Path]:
    """Locates pre-installed ECP binaries.

    Search order:
      1. Bundled alongside the wif-bunker binary (<binary_dir>/ecp/)
      2. Default platform location (~/.config/bunker-ecp or %LOCALAPPDATA%\\Google\\ECP)

    Returns:
        (ecp_binary, ecp_client_lib, tls_offload_lib) paths.

    Raises:
        FileNotFoundError: if ECP binaries are not found in any location.
    """
    from get_ecp import get_default_ecp_dir, get_ecp_binary_names  # pylint: disable=import-outside-toplevel

    ecp_bin_name, libecp_name, tls_offload_name = get_ecp_binary_names()

    # Determine the directory containing the wif-bunker binary.
    if getattr(sys, "frozen", False):
        binary_dir = Path(sys.executable).parent
    else:
        binary_dir = Path(__file__).parent

    # Search locations in priority order.
    search_dirs = [
        binary_dir / "ecp",  # Bundled alongside binary
        get_default_ecp_dir(),  # Platform default
    ]

    for ecp_dir in search_dirs:
        ecp_bin = ecp_dir / ecp_bin_name
        client = ecp_dir / libecp_name
        offload = ecp_dir / tls_offload_name
        if ecp_bin.exists() and client.exists() and offload.exists():
            logger.info("    Using ECP binaries from %s", ecp_dir)
            _add_ecp_to_path(ecp_dir)
            return ecp_bin, client, offload

    raise FileNotFoundError(
        "ECP binaries not found. Install them with:\n"
        "    python get_ecp.py\n"
        "\n"
        f"Searched: {[str(d) for d in search_dirs]}"
    )


def _add_ecp_to_path(ecp_dir: Path) -> None:
    """Ensures the ECP binary directory is discoverable for DLL loading."""
    ecp_dir_str = str(ecp_dir)

    # os.add_dll_directory() is the ONLY mechanism that works on
    # Python 3.8+ for DLL dependency resolution on Windows.
    if sys.platform == "win32" and ecp_dir.is_dir():
        os.add_dll_directory(ecp_dir_str)

    # Also add to PATH for the current process.
    current_path = os.environ.get("PATH", "")
    if ecp_dir_str not in current_path:
        os.environ["PATH"] = ecp_dir_str + os.pathsep + current_path
