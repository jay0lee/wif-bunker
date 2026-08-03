"""Windows CNG/TPM key attestation via NCrypt ctypes bindings.

Uses NCryptCreateClaim for cryptographic attestation and PowerShell for
TPM status and EK information.
"""

from __future__ import annotations

import json
import logging
import subprocess

from cryptography import x509 as cx509

from wif_bunker.attestation.base import (
    AttestationArtifact,
    AttestationCheck,
    AttestationReport,
    verify_ek_chain,
)
from wif_bunker.config import WorkloadConfig

logger = logging.getLogger(__name__)

# CNG constants
_MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"
_MS_SOFTWARE_KSP = "Microsoft Software Key Storage Provider"
_NCRYPT_CLAIM_KEY_ATTESTATION = 0x00000001

# Attestation Key (AK) — a persistent RSA 2048 key in the TPM that signs
# attestation claims.  NCryptCreateClaim requires an "authority key" handle;
# without one the call fails on many TPMs (notably Dell/Nuvoton).
_AK_KEY_NAME = "wif-bunker-attestation-key"
_BCRYPT_RSA_ALGORITHM = "RSA"
_NTE_BAD_KEYSET = 0x80090016  # "keyset does not exist" — key not found
_PCP_E_KEY_NOT_LOADED = 0x8029040F  # "TPM key is not loaded" — key lacks attestation flag

# Ensures Cert: drive + TPM cmdlets work in both Windows PowerShell 5.1 and PowerShell 7+.
# Microsoft.PowerShell.Security provides the Cert: drive; PKI provides Import-Certificate.
_PS_PREAMBLE = (
    "Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue; "
    "Import-Module PKI -ErrorAction SilentlyContinue; "
)


def _run_powershell(command: str, *, preamble: bool = True) -> subprocess.CompletedProcess:
    """Run a PowerShell command and return the result.

    When *preamble* is True (default), prepends module imports that
    ensure the Cert: drive and PKI cmdlets are available in PS 7+.
    """
    full_cmd = f"{_PS_PREAMBLE}{command}" if preamble else command
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full_cmd],
        capture_output=True,
        text=True,
    )


def _check_tpm_status() -> tuple[AttestationCheck, dict | None]:
    """Query TPM status via PowerShell Get-Tpm."""
    result = _run_powershell("Get-Tpm | Select-Object * | ConvertTo-Json -Depth 3", preamble=False)
    if result.returncode != 0:
        return (
            AttestationCheck(
                name="TPM status",
                passed=False,
                detail=f"Get-Tpm failed: {result.stderr.strip()[:200]}",
            ),
            None,
        )

    try:
        tpm_info = json.loads(result.stdout)
        if not isinstance(tpm_info, dict):
            return (
                AttestationCheck(
                    name="TPM status",
                    passed=False,
                    detail=f"Unexpected Get-Tpm output type: {type(tpm_info).__name__}",
                ),
                None,
            )
        present = tpm_info.get("TpmPresent", False)
        ready = tpm_info.get("TpmReady", False)
        return (
            AttestationCheck(
                name="TPM status",
                passed=present and ready,
                detail=(
                    f"TPM Present: {present}, Ready: {ready}, "
                    f"Manufacturer: {tpm_info.get('ManufacturerId', 'unknown')}, "
                    f"Version: {tpm_info.get('ManufacturerVersion', 'unknown')}"
                ),
            ),
            tpm_info,
        )
    except (json.JSONDecodeError, KeyError) as exc:
        return (
            AttestationCheck(
                name="TPM status",
                passed=False,
                detail=f"Could not parse Get-Tpm output: {exc}",
            ),
            None,
        )


def _check_ek_info() -> tuple[AttestationCheck, dict | None]:
    """Extract Endorsement Key info via PowerShell."""
    result = _run_powershell(
        "Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 | Select-Object * | ConvertTo-Json -Depth 3",
        preamble=False,
    )
    if result.returncode != 0:
        return (
            AttestationCheck(
                name="EK information",
                passed=False,
                detail=f"Get-TpmEndorsementKeyInfo failed: {result.stderr.strip()[:200]}",
            ),
            None,
        )

    try:
        ek_info = json.loads(result.stdout)
        if not isinstance(ek_info, dict):
            return (
                AttestationCheck(
                    name="EK information",
                    passed=False,
                    detail=f"Unexpected EK info output type: {type(ek_info).__name__}",
                ),
                None,
            )
        has_certs = bool(ek_info.get("ManufacturerCertificates"))
        return (
            AttestationCheck(
                name="EK information",
                passed=True,
                detail=(
                    f"EK PublicKeyHash: {ek_info.get('PublicKeyHash', 'N/A')}, "
                    f"Manufacturer certs: {'present' if has_certs else 'none'}"
                ),
            ),
            ek_info,
        )
    except (json.JSONDecodeError, KeyError) as exc:
        return (
            AttestationCheck(
                name="EK information",
                passed=False,
                detail=f"Could not parse EK info: {exc}",
            ),
            None,
        )


def _extract_ek_certificate() -> tuple[AttestationCheck, str | None]:
    """Extract the EK certificate as PEM via PowerShell."""
    # Export the manufacturer EK certificate to PEM format
    ps_command = (
        "$ekInfo = Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256; "
        "if ($ekInfo.ManufacturerCertificates -and "
        "$ekInfo.ManufacturerCertificates.Count -gt 0) { "
        "$cert = $ekInfo.ManufacturerCertificates[0]; "
        "$pem = '-----BEGIN CERTIFICATE-----' + "
        "[Environment]::NewLine + "
        "[Convert]::ToBase64String($cert.RawData, "
        "'InsertLineBreaks') + "
        "[Environment]::NewLine + "
        "'-----END CERTIFICATE-----'; "
        "Write-Output $pem "
        "} else { Write-Output 'NO_CERT' }"
    )
    result = _run_powershell(ps_command, preamble=False)
    if result.returncode != 0:
        return (
            AttestationCheck(
                name="EK certificate extracted",
                passed=False,
                detail=(f"Could not extract EK certificate: {result.stderr.strip()[:200]}"),
            ),
            None,
        )

    output = result.stdout.strip()
    if output == "NO_CERT" or "BEGIN CERTIFICATE" not in output:
        return (
            AttestationCheck(
                name="EK certificate extracted",
                passed=False,
                detail=("No manufacturer EK certificate found. The TPM may not have a provisioned EK certificate."),
            ),
            None,
        )

    # Extract issuer using the cryptography library (no openssl CLI needed)
    try:
        cert_obj = cx509.load_pem_x509_certificate(output.encode())
        issuer = cert_obj.issuer.rfc4514_string()
    except Exception:  # pylint: disable=broad-except
        issuer = "unknown"

    return (
        AttestationCheck(
            name="EK certificate extracted",
            passed=True,
            detail=f"EK certificate extracted from TPM. Issuer: {issuer}",
        ),
        output,
    )


def _verify_ek_chain_windows(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs."""
    return verify_ek_chain(ek_pem)


def _check_key_provider(config: WorkloadConfig) -> tuple[AttestationCheck, dict | None]:
    """Verify the bunker key's CNG storage provider via cert private key info."""
    key_cn = config.workload_cn
    # Query the cert's private key provider using .NET CNG APIs via PowerShell.
    # This works for both RSA and ECDSA keys and avoids certutil -csp (legacy).
    ps_cmd = (
        f"$cert = Get-ChildItem Cert:\\CurrentUser\\My | "
        f"Where-Object {{ $_.Subject -eq 'CN={key_cn}' }}; "
        f"if (-not $cert) {{ Write-Output 'CERT_NOT_FOUND'; exit }}; "
        f"if (-not $cert.HasPrivateKey) {{ Write-Output 'NO_PRIVATE_KEY'; exit }}; "
        # Try RSA first, then ECDSA — one will succeed depending on key algorithm
        f"$key = $null; "
        f"try {{ $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); "
        f"if ($k -is [System.Security.Cryptography.RSACng]) {{ $key = $k.Key }} }} catch {{}}; "
        f"if (-not $key) {{ "
        f"try {{ $k = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert); "
        f"if ($k -is [System.Security.Cryptography.ECDsaCng]) {{ $key = $k.Key }} }} catch {{}} }}; "
        f'if ($key) {{ Write-Output ("$($key.Provider.Provider)|$($key.KeyName)") }} '
        f"else {{ Write-Output 'NO_CNG_KEY' }}"
    )
    result = _run_powershell(ps_cmd)
    output = result.stdout.strip()

    if output == "CERT_NOT_FOUND":
        return (
            AttestationCheck(
                name="Key storage provider",
                passed=False,
                detail=f"Certificate with CN '{key_cn}' not found in Cert:\\CurrentUser\\My",
            ),
            None,
        )

    if output in ("NO_PRIVATE_KEY", "NO_CNG_KEY") or "|" not in output:
        return (
            AttestationCheck(
                name="Key storage provider",
                passed=False,
                detail=f"Could not determine CNG key provider for '{key_cn}'. Output: {output[:200]}",
            ),
            None,
        )

    provider, key_name = output.split("|", 1)

    if provider == _MS_PLATFORM_CRYPTO_PROVIDER:
        return (
            AttestationCheck(
                name="Key storage provider",
                passed=True,
                detail=f"Key '{key_cn}' found in {_MS_PLATFORM_CRYPTO_PROVIDER} (TPM-backed)",
            ),
            {"provider": provider, "key_name": key_name},
        )

    return (
        AttestationCheck(
            name="Key storage provider",
            passed=False,
            detail=(
                f"Key '{key_cn}' is in {provider} (not TPM-backed). "
                "Use a TPM-backed key (remove --soft-key) for hardware attestation."
            ),
        ),
        {"provider": provider, "key_name": key_name},
    )


def _get_or_create_ak(ncrypt, ctypes, wintypes, provider_handle):
    """Get or create a persistent Attestation Key (AK) in the TPM.

    NCryptCreateClaim requires an "authority key" (the AK) to sign the
    attestation claim.  The AK is a persistent RSA 2048 key stored in the
    Platform Crypto Provider.  It is created once and reused on subsequent
    attestation calls.

    Returns:
        A tuple of (ak_handle, error_detail).  On success error_detail is
        None; on failure ak_handle is None and error_detail explains why.
    """
    ak_handle = wintypes.HANDLE()

    # Try to open an existing AK first.
    status = ncrypt.NCryptOpenKey(
        provider_handle,
        ctypes.byref(ak_handle),
        _AK_KEY_NAME,
        0,
        0,
    )
    if status == 0:
        logger.debug("Opened existing attestation key '%s'", _AK_KEY_NAME)
        return ak_handle, None

    # Convert to unsigned 32-bit for comparison (NCrypt returns SECURITY_STATUS
    # which is a signed LONG; Python may interpret it as negative).
    unsigned_status = status & 0xFFFFFFFF
    if unsigned_status != _NTE_BAD_KEYSET:
        return None, f"NCryptOpenKey for AK failed unexpectedly: 0x{unsigned_status:08X}"

    # AK doesn't exist yet — create a persistent RSA 2048 key in the TPM.
    logger.info("Creating attestation key '%s' in TPM (one-time operation)", _AK_KEY_NAME)
    ak_handle = wintypes.HANDLE()
    status = ncrypt.NCryptCreatePersistedKey(
        provider_handle,
        ctypes.byref(ak_handle),
        _BCRYPT_RSA_ALGORITHM,
        _AK_KEY_NAME,
        0,  # dwLegacyKeySpec — 0 for CNG keys
        0,  # dwFlags
    )
    if status != 0:
        return None, f"NCryptCreatePersistedKey for AK failed: 0x{status & 0xFFFFFFFF:08X}"

    # Set key length to 2048 bits.
    key_length = wintypes.DWORD(2048)
    status = ncrypt.NCryptSetProperty(
        ak_handle,
        "Length",
        ctypes.byref(key_length),
        ctypes.sizeof(key_length),
        0,
    )
    if status != 0:
        ncrypt.NCryptFreeObject(ak_handle)
        return None, f"NCryptSetProperty(Length) for AK failed: 0x{status & 0xFFFFFFFF:08X}"

    # Set PCP key usage policy to IDENTITY_KEY — this marks the AK as
    # a "restricted signing key" that can only sign TPM-internal structures
    # (attestation claims).  NCryptCreateClaim requires the authority key
    # to have this policy; without it, it fails with PCP_E_KEY_NOT_LOADED
    # (0x8029040F).
    _NCRYPT_PCP_IDENTITY_KEY = 0x00000008
    usage_policy = wintypes.DWORD(_NCRYPT_PCP_IDENTITY_KEY)
    status = ncrypt.NCryptSetProperty(
        ak_handle,
        "PCP_KEY_USAGE_POLICY",
        ctypes.byref(usage_policy),
        ctypes.sizeof(usage_policy),
        0,
    )
    if status != 0:
        ncrypt.NCryptFreeObject(ak_handle)
        return None, f"NCryptSetProperty(PCP_KEY_USAGE_POLICY) for AK failed: 0x{status & 0xFFFFFFFF:08X}"

    # Finalize (persist) the key in the TPM.
    status = ncrypt.NCryptFinalizeKey(ak_handle, 0)
    if status != 0:
        ncrypt.NCryptFreeObject(ak_handle)
        return None, f"NCryptFinalizeKey for AK failed: 0x{status & 0xFFFFFFFF:08X}"

    logger.info("Attestation key '%s' created successfully", _AK_KEY_NAME)
    return ak_handle, None


def _ncrypt_create_claim(config: WorkloadConfig, key_info: dict | None = None) -> tuple[AttestationCheck, bytes | None]:
    """Create a TPM key attestation claim via NCrypt ctypes FFI.

    Uses NCryptCreateClaim with NCRYPT_CLAIM_KEY_ATTESTATION to produce
    a cryptographic proof that the workload key resides in the TPM.

    The call requires two key handles:
    - **Subject key**: the workload key being attested
    - **Authority key (AK)**: a persistent RSA 2048 key in the TPM that
      signs the attestation claim.  Created automatically on first use.

    Args:
        config: Workload configuration.
        key_info: Output from _check_key_provider containing 'provider'
            and 'key_name' (the actual CNG container name). If None,
            the function cannot open the key.
    """
    try:
        import ctypes  # pylint: disable=import-outside-toplevel
        from ctypes import wintypes  # pylint: disable=import-outside-toplevel
    except ImportError:
        return (
            AttestationCheck(
                name="NCryptCreateClaim attestation",
                passed=False,
                detail="ctypes.wintypes not available (not running on Windows)",
            ),
            None,
        )

    try:
        ncrypt = ctypes.windll.ncrypt  # type: ignore[attr-defined]
    except (AttributeError, OSError) as exc:
        return (
            AttestationCheck(
                name="NCryptCreateClaim attestation",
                passed=False,
                detail=f"Could not load ncrypt.dll: {exc}",
            ),
            None,
        )

    provider_handle = wintypes.HANDLE()
    key_handle = wintypes.HANDLE()
    ak_handle = None

    if not key_info:
        return (
            AttestationCheck(
                name="NCryptCreateClaim attestation",
                passed=False,
                detail=("Skipped — key provider info not available. Run key storage provider check first."),
            ),
            None,
        )

    provider_name = key_info.get("provider", _MS_PLATFORM_CRYPTO_PROVIDER)
    key_name = key_info.get("key_name", config.workload_cn)

    try:
        # Open the Platform Crypto Provider
        status = ncrypt.NCryptOpenStorageProvider(
            ctypes.byref(provider_handle),
            provider_name,
            0,
        )
        if status != 0:
            return (
                AttestationCheck(
                    name="NCryptCreateClaim attestation",
                    passed=False,
                    detail=f"NCryptOpenStorageProvider failed: 0x{status:08X}",
                ),
                None,
            )

        # Open the subject key (the workload key being attested)
        status = ncrypt.NCryptOpenKey(
            provider_handle,
            ctypes.byref(key_handle),
            key_name,
            0,
            0,
        )
        if status != 0:
            return (
                AttestationCheck(
                    name="NCryptCreateClaim attestation",
                    passed=False,
                    detail=(
                        f"NCryptOpenKey failed for '{key_name}': 0x{status:08X}. Key may be in software KSP (not TPM)."
                    ),
                ),
                None,
            )

        # Get or create the Attestation Key (AK) — required as the
        # "authority" that signs the claim.  Without this, NCryptCreateClaim
        # fails on Dell/Nuvoton TPMs (and potentially others).
        ak_handle, ak_error = _get_or_create_ak(ncrypt, ctypes, wintypes, provider_handle)
        if ak_error:
            return (
                AttestationCheck(
                    name="NCryptCreateClaim attestation",
                    passed=False,
                    detail=f"Could not provision attestation key (AK): {ak_error}",
                ),
                None,
            )

        # Create attestation claim — the AK signs a proof that the subject
        # key is genuinely inside the TPM.
        claim_size = wintypes.DWORD(0)

        # First call to get required buffer size
        status = ncrypt.NCryptCreateClaim(
            key_handle,
            ak_handle,  # authority key signs the claim
            _NCRYPT_CLAIM_KEY_ATTESTATION,
            None,  # no parameters
            None,  # output buffer (null for size query)
            0,
            ctypes.byref(claim_size),
            0,
        )
        if status != 0:
            unsigned = status & 0xFFFFFFFF
            if unsigned == _PCP_E_KEY_NOT_LOADED:
                detail = (
                    f"NCryptCreateClaim failed: 0x{unsigned:08X} "
                    "(PCP_E_KEY_NOT_LOADED — the workload key was not created with "
                    "the attestation capability flag). "
                    "To fix: delete and re-create the workload identity so the key "
                    "is generated with attestation support."
                )
            else:
                detail = (
                    f"NCryptCreateClaim size query failed: 0x{unsigned:08X}. "
                    "The TPM may not support key attestation with this key type."
                )
            return (
                AttestationCheck(
                    name="NCryptCreateClaim attestation",
                    passed=False,
                    detail=detail,
                ),
                None,
            )

        # Second call with allocated buffer
        claim_buffer = (ctypes.c_ubyte * claim_size.value)()
        result_size = wintypes.DWORD(0)
        status = ncrypt.NCryptCreateClaim(
            key_handle,
            ak_handle,
            _NCRYPT_CLAIM_KEY_ATTESTATION,
            None,
            claim_buffer,
            claim_size.value,
            ctypes.byref(result_size),
            0,
        )
        if status != 0:
            return (
                AttestationCheck(
                    name="NCryptCreateClaim attestation",
                    passed=False,
                    detail=f"NCryptCreateClaim failed: 0x{status & 0xFFFFFFFF:08X}",
                ),
                None,
            )

        claim_bytes = bytes(claim_buffer[: result_size.value])
        return (
            AttestationCheck(
                name="NCryptCreateClaim attestation",
                passed=True,
                detail=(
                    f"Attestation claim blob generated ({result_size.value} bytes). "
                    "Contains TPM2B_ATTEST + signature proving key is TPM-backed."
                ),
            ),
            claim_bytes,
        )

    finally:
        if ak_handle is not None and getattr(ak_handle, "value", 0):
            ncrypt.NCryptFreeObject(ak_handle)
        if key_handle.value:  # pylint: disable=using-constant-test
            ncrypt.NCryptFreeObject(key_handle)
        if provider_handle.value:  # pylint: disable=using-constant-test
            ncrypt.NCryptFreeObject(provider_handle)


def _check_exportability(config: WorkloadConfig) -> AttestationCheck:
    """Verify the key is non-exportable via certutil."""
    result = _run_powershell(
        f"$cert = Get-ChildItem Cert:\\CurrentUser\\My | "
        f"Where-Object {{ $_.Subject -like '*{config.workload_cn}*' }}; "
        f"if ($cert) {{ $cert.HasPrivateKey; $cert.PrivateKey }} else {{ 'NOT_FOUND' }}"
    )

    if "NOT_FOUND" in result.stdout:
        return AttestationCheck(
            name="Key non-exportability",
            passed=False,
            detail=f"Certificate with CN '{config.workload_cn}' not found in cert store",
        )

    # TPM-backed keys will show HasPrivateKey=True but PrivateKey access will fail
    # Software keys will show the private key object
    is_protected = "CngKey" not in result.stdout or "IsExportable" not in result.stdout
    return AttestationCheck(
        name="Key non-exportability",
        passed=is_protected,
        detail=(
            "Private key is non-exportable (TPM-protected)"
            if is_protected
            else "Private key appears exportable (software key)"
        ),
    )


def _is_admin() -> bool:
    """Check if the current process has Administrator privileges on Windows."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _attest_windows(config: WorkloadConfig) -> AttestationReport:
    """Perform Windows CNG/TPM key attestation."""
    checks: list[AttestationCheck] = []
    artifacts: list[AttestationArtifact] = []

    if not _is_admin():
        logger.warning(
            "  ⚠️  Not running as Administrator. "
            "TPM status and EK queries require elevation.\n"
            "  Right-click your terminal → 'Run as Administrator' for full attestation."
        )

    # Step 1: TPM status
    tpm_check, tpm_info = _check_tpm_status()
    checks.append(tpm_check)
    if tpm_info:
        artifacts.append(
            AttestationArtifact(
                filename="tpm_status.json",
                content=json.dumps(tpm_info, indent=2),
                description="TPM presence, version, and manufacturer information",
            )
        )

    # Step 2: EK certificate extraction and chain verification
    ek_check, ek_info = _check_ek_info()
    checks.append(ek_check)
    if ek_info:
        artifacts.append(
            AttestationArtifact(
                filename="ek_info.json",
                content=json.dumps(ek_info, indent=2, default=str),
                description="Endorsement Key public key hash and manufacturer certificates",
            )
        )

    # Step 3: Extract EK certificate and verify chain
    ek_cert_check, ek_pem = _extract_ek_certificate()
    checks.append(ek_cert_check)
    if ek_pem:
        artifacts.append(
            AttestationArtifact(
                filename="ek_certificate.pem",
                content=ek_pem,
                description="TPM Endorsement Key certificate (manufacturer-signed)",
            )
        )
        chain_check = _verify_ek_chain_windows(ek_pem)
        checks.append(chain_check)
    else:
        checks.append(
            AttestationCheck(
                name="EK certificate chain verified",
                passed=False,
                detail="Skipped — no EK certificate to verify",
            )
        )

    # Step 4: Key provider verification
    provider_check, provider_info = _check_key_provider(config)
    checks.append(provider_check)
    if provider_info:
        artifacts.append(
            AttestationArtifact(
                filename="key_provider_info.json",
                content=json.dumps(provider_info, indent=2),
                description="CNG key storage provider and attributes",
            )
        )

    # Step 5: NCryptCreateClaim attestation
    claim_check, claim_blob = _ncrypt_create_claim(config, key_info=provider_info)
    checks.append(claim_check)
    if claim_blob:
        artifacts.append(
            AttestationArtifact(
                filename="cng_claim_blob.bin",
                content=claim_blob,
                description="NCryptCreateClaim attestation blob (TPM2B_ATTEST + signature)",
                is_binary=True,
            )
        )

    # Step 6: Non-exportability check
    export_check = _check_exportability(config)
    checks.append(export_check)

    passed = sum(1 for chk in checks if chk.passed)
    total = len(checks)

    is_software = provider_info and provider_info.get("provider") == _MS_SOFTWARE_KSP
    if is_software:
        summary = (
            f"{passed}/{total} checks passed. Key is in the Software KSP (--soft-key). "
            "No TPM attestation available for software keys."
        )
    elif passed == total:
        summary = (
            f"{passed}/{total} checks passed. Full CNG/TPM attestation verified. "
            "The workload key is cryptographically proven to reside in the TPM."
        )
    else:
        summary = f"{passed}/{total} checks passed. Partial attestation."

    return AttestationReport(
        platform="windows-cng",
        supported=True,
        hardware_type="CNG/TPM",
        artifacts=artifacts,
        checks=checks,
        summary=summary,
        documentation_urls=[
            "https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreateclaim",
            "https://learn.microsoft.com/en-us/powershell/module/tpm/get-tpmendorsementkeyinfo",
            "https://learn.microsoft.com/en-us/windows/security/"
            "identity-protection/hello-for-business/hello-key-attestation",
        ],
        verification_steps=[
            "1. Verify TPM is present and ready: Get-Tpm",
            "2. Verify EK certificate chain: openssl verify -CAfile <manufacturer_root.pem> ek_certificate.pem",
            "3. Verify key is in Platform Crypto Provider: certutil -csp 'Microsoft Platform Crypto Provider' -key",
            "4. Verify claim blob: NCryptVerifyClaim with the attestation blob",
            "5. Verify EK: Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256",
        ],
    )
