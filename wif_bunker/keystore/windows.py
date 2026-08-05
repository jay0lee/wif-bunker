"""Windows CNG/TPM keystore: key generation via NCrypt and certificate management.

Creates TPM-backed keys directly via NCrypt ctypes (no certreq dependency)
and imports certificates via PowerShell CNG classes.
"""

from __future__ import annotations

import logging
import subprocess

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


def get_supported_algorithms_windows(soft_key: bool = False) -> list[str]:
    """Probe the CNG key storage provider for supported algorithms.

    Creates (and immediately deletes) a transient key for each algorithm
    to test whether the provider supports it.

    Args:
        soft_key: If True, probe the Software KSP instead of the TPM.

    Returns:
        List of supported wif-bunker algorithm names.
    """
    from wif_bunker.config import _KEY_ALGORITHMS  # pylint: disable=import-outside-toplevel

    supported = []
    for algo_name, algo_info in _KEY_ALGORITHMS.items():
        if "win32" not in algo_info["platforms"]:
            continue
        ncrypt_algo = algo_info["ncrypt_algo"]
        ncrypt_key_length = algo_info.get("ncrypt_key_length")
        if ncrypt.test_algorithm(ncrypt_algo, ncrypt_key_length, soft_key=soft_key):
            supported.append(algo_name)
    return supported


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
    require_commands(
        [
            ("powershell", "", "Built-in Windows command — ensure PowerShell is on PATH"),
        ]
    )

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
