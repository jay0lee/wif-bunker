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
    _decode_manufacturer_id,
    parse_ek_details,
    verify_ek_chain,
)
from wif_bunker.config import WorkloadConfig

logger = logging.getLogger(__name__)

# CNG constants
_MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"
_MS_SOFTWARE_KSP = "Microsoft Software Key Storage Provider"

# For TPM PCP attestation, the correct claim type is NCRYPT_CLAIM_PLATFORM
# (0x10000).  NOT NCRYPT_CLAIM_AUTHORITY_ONLY (0x1) which is for VBS.
# With NCRYPT_CLAIM_PLATFORM, hAuthorityKey is NULL — the TPM itself is the
# authority — and the PCR mask is passed via NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK.
_NCRYPT_CLAIM_PLATFORM = 0x00010000
_NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK = 51  # NCRYPTBUFFER type for PCR mask
_NCRYPTBUFFER_VERSION = 0  # NCryptBufferDesc.ulVersion

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
        mfr_name = _decode_manufacturer_id(tpm_info.get("ManufacturerId", 0))
        version = tpm_info.get("ManufacturerVersion", "unknown")
        return (
            AttestationCheck(
                name="TPM status",
                passed=present and ready,
                detail=(f"TPM Present: {present}, Ready: {ready}, Manufacturer: {mfr_name}, FW: {version}"),
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
            {},
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
            {},
        )

    # Extract detailed info using the cryptography library
    details = parse_ek_details(output)

    # Build rich detail string
    detail_parts = [f"Issuer: {details.get('issuer', 'unknown')}"]
    if "serial" in details:
        # Show first 20 chars of serial for readability
        serial = details["serial"]
        detail_parts.append(f"Serial: {serial[:20]}{'...' if len(serial) > 20 else ''}")
    if "tpm_model" in details:
        detail_parts.append(f"TPM Model: {details['tpm_model']}")
    if "not_before" in details:
        detail_parts.append(f"Valid: {details['not_before']} to {details.get('not_after', '?')}")

    return (
        AttestationCheck(
            name="EK certificate extracted",
            passed=True,
            detail="EK certificate extracted from TPM. " + ", ".join(detail_parts),
        ),
        output,
        details,
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

    # ---------------------------------------------------------------
    # Declare argtypes/restype for every ncrypt function we call.
    # WITHOUT these, ctypes defaults to c_int (32-bit) for return
    # values AND may truncate 64-bit HANDLE arguments on 64-bit
    # Windows, causing NCryptCreateClaim to receive garbage handles.
    # ---------------------------------------------------------------
    ncrypt.NCryptOpenStorageProvider.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    ncrypt.NCryptOpenStorageProvider.restype = ctypes.c_long

    ncrypt.NCryptOpenKey.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    ncrypt.NCryptOpenKey.restype = ctypes.c_long

    ncrypt.NCryptCreatePersistedKey.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    ncrypt.NCryptCreatePersistedKey.restype = ctypes.c_long

    ncrypt.NCryptSetProperty.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    ncrypt.NCryptSetProperty.restype = ctypes.c_long

    ncrypt.NCryptGetProperty.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    ncrypt.NCryptGetProperty.restype = ctypes.c_long

    ncrypt.NCryptFinalizeKey.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ncrypt.NCryptFinalizeKey.restype = ctypes.c_long

    ncrypt.NCryptCreateClaim.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    ncrypt.NCryptCreateClaim.restype = ctypes.c_long

    ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
    ncrypt.NCryptFreeObject.restype = ctypes.c_long

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

        # Create TPM platform attestation claim.
        #
        # For TPM PCP keys, the correct claim type is NCRYPT_CLAIM_PLATFORM
        # (0x10000) with hAuthorityKey=NULL — the TPM itself is the authority.
        # This is fundamentally different from VBS attestation which uses
        # NCRYPT_CLAIM_AUTHORITY_ONLY (0x1) with an explicit authority key.
        #
        # Build the NCryptBufferDesc with a PCR mask.  PCR 0 (firmware)
        # and PCR 7 (Secure Boot policy) are the standard boot-state PCRs.

        # NCryptBuffer struct: { cbBuffer, BufferType, pvBuffer }
        class NCryptBuffer(ctypes.Structure):
            _fields_ = [
                ("cbBuffer", wintypes.DWORD),
                ("BufferType", wintypes.DWORD),
                ("pvBuffer", ctypes.c_void_p),
            ]

        # NCryptBufferDesc struct: { ulVersion, cBuffers, pBuffers }
        class NCryptBufferDesc(ctypes.Structure):
            _fields_ = [
                ("ulVersion", wintypes.DWORD),
                ("cBuffers", wintypes.DWORD),
                ("pBuffers", ctypes.POINTER(NCryptBuffer)),
            ]

        # PCR mask: include PCR 0 (firmware) and PCR 7 (Secure Boot policy)
        pcr_mask = wintypes.DWORD((1 << 0) | (1 << 7))
        pcr_buffer = NCryptBuffer(
            cbBuffer=ctypes.sizeof(pcr_mask),
            BufferType=_NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK,
            pvBuffer=ctypes.cast(ctypes.byref(pcr_mask), ctypes.c_void_p),
        )
        buffers_array = (NCryptBuffer * 1)(pcr_buffer)
        param_list = NCryptBufferDesc(
            ulVersion=_NCRYPTBUFFER_VERSION,
            cBuffers=1,
            pBuffers=buffers_array,
        )

        # First call: query claim size
        claim_size = wintypes.DWORD(0)
        status = ncrypt.NCryptCreateClaim(
            key_handle,
            None,  # hAuthorityKey — NULL for TPM platform claims
            _NCRYPT_CLAIM_PLATFORM,
            ctypes.byref(param_list),
            None,
            0,
            ctypes.byref(claim_size),
            0,
        )

        if status != 0:
            unsigned = status & 0xFFFFFFFF
            logger.info(
                "NCryptCreateClaim(NCRYPT_CLAIM_PLATFORM) failed: 0x%08X",
                unsigned,
            )
            return (
                AttestationCheck(
                    name="NCryptCreateClaim attestation",
                    passed=False,
                    detail=(
                        f"NCryptCreateClaim(NCRYPT_CLAIM_PLATFORM) failed: "
                        f"0x{unsigned:08X}. "
                        "The TPM may not support platform key attestation "
                        "or the key may require different creation flags."
                    ),
                ),
                None,
            )

        # Second call: retrieve the claim blob
        claim_buffer = (ctypes.c_ubyte * claim_size.value)()
        result_size = wintypes.DWORD(0)
        status = ncrypt.NCryptCreateClaim(
            key_handle,
            None,  # hAuthorityKey — NULL for TPM platform claims
            _NCRYPT_CLAIM_PLATFORM,
            ctypes.byref(param_list),
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
                    detail=f"NCryptCreateClaim (buffer fill) failed: 0x{status & 0xFFFFFFFF:08X}",
                ),
                None,
            )

        claim_bytes = bytes(claim_buffer[: result_size.value])
        logger.info("NCryptCreateClaim succeeded (%d bytes)", result_size.value)
        return (
            AttestationCheck(
                name="NCryptCreateClaim attestation",
                passed=True,
                detail=(
                    f"Platform attestation claim generated ({result_size.value} bytes). "
                    "Contains TPM2_Certify proof that the key resides in the TPM."
                ),
            ),
            claim_bytes,
        )

    finally:
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


# ── TBS (TPM Base Services) Platform Certificate Discovery ──────────
#
# TCG defines NV index 0x01C08000 for the Platform Certificate.
# We probe for it using raw TPM2 commands via the TBS API (tbs.dll).
# This avoids any PowerShell dependency and works at the TPM level.

_PLATFORM_CERT_NV_INDEX = 0x01C08000

# TPM2 command codes
_TPM2_CC_NV_READ_PUBLIC = 0x00000169
_TPM2_CC_NV_READ = 0x0000014E

# TPM2 tags
_TPM_ST_NO_SESSIONS = 0x8001
_TPM_ST_SESSIONS = 0x8002

# TPM2 auth
_TPM_RS_PW = 0x40000009  # Password session handle

# TBS constants
_TBS_COMMAND_PRIORITY_NORMAL = 200


def _tbs_submit_command(tbs_ctx, tbs, ctypes, cmd_bytes: bytes) -> bytes | None:
    """Submit a raw TPM2 command via TBS and return the response."""
    cmd_buf = (ctypes.c_ubyte * len(cmd_bytes))(*cmd_bytes)
    resp_buf = (ctypes.c_ubyte * 4096)()
    resp_len = ctypes.c_uint32(4096)

    status = tbs.Tbsip_Submit_Command(
        tbs_ctx,
        0,  # locality
        _TBS_COMMAND_PRIORITY_NORMAL,
        cmd_buf,
        len(cmd_bytes),
        resp_buf,
        ctypes.byref(resp_len),
    )
    if status != 0:
        logger.debug("Tbsip_Submit_Command failed: 0x%08X", status)
        return None

    return bytes(resp_buf[: resp_len.value])


def _tpm2_nv_read_public(tbs_ctx, tbs, ctypes, nv_index: int) -> int | None:
    """Send TPM2_NV_ReadPublic to check if NV index exists and get size.

    Returns the data size in bytes, or None if the index doesn't exist.
    """
    import struct

    # Build command: tag(2) + size(4) + commandCode(4) + nvIndex(4) = 14 bytes
    cmd = struct.pack(
        ">HII I",
        _TPM_ST_NO_SESSIONS,
        14,  # total command size
        _TPM2_CC_NV_READ_PUBLIC,
        nv_index,
    )
    resp = _tbs_submit_command(tbs_ctx, tbs, ctypes, cmd)
    if resp is None or len(resp) < 10:
        return None

    # Parse response header
    _tag, _size, rc = struct.unpack_from(">HII", resp, 0)
    if rc != 0:
        logger.debug("TPM2_NV_ReadPublic failed: 0x%08X (index may not exist)", rc)
        return None

    # Parse TPM2B_NV_PUBLIC: size(2) + TPMS_NV_PUBLIC
    # TPMS_NV_PUBLIC: nvIndex(4) + nameAlg(2) + attributes(4) + authPolicy_size(2) + authPolicy + dataSize(2)
    if len(resp) < 14:
        return None
    nv_public_size = struct.unpack_from(">H", resp, 10)[0]
    if nv_public_size < 12 or len(resp) < 12 + nv_public_size:
        return None

    # Skip nvIndex(4) + nameAlg(2) + attributes(4) = 10 bytes into nvPublic
    offset = 12 + 10  # after TPM2B_NV_PUBLIC header
    auth_policy_size = struct.unpack_from(">H", resp, offset)[0]
    offset += 2 + auth_policy_size
    data_size = struct.unpack_from(">H", resp, offset)[0]
    return data_size


def _tpm2_nv_read(tbs_ctx, tbs, ctypes, nv_index: int, size: int) -> bytes | None:
    """Send TPM2_NV_Read to read data from an NV index.

    Uses empty-password auth (TPM_RS_PW with no HMAC).
    May need to read in chunks for large data.
    """
    import struct

    result = b""
    max_chunk = 1024  # TPM implementations typically allow 1024 bytes per read
    offset = 0

    while offset < size:
        chunk_size = min(max_chunk, size - offset)

        # Build command with password auth session
        # Header: tag(2) + size(4) + commandCode(4) = 10
        # Handles: authHandle(4) + nvIndex(4) = 8
        # Auth area size(4) + auth session(9) = 13
        # Parameters: size(2) + offset(2) = 4
        # Total = 35
        auth_area = struct.pack(
            ">I HB H",
            _TPM_RS_PW,  # sessionHandle
            0,  # nonceSize = 0
            0,  # sessionAttributes = 0
            0,  # hmacSize = 0 (empty password)
        )
        total_size = 10 + 8 + 4 + len(auth_area) + 4
        cmd = struct.pack(
            ">HII II I",
            _TPM_ST_SESSIONS,
            total_size,
            _TPM2_CC_NV_READ,
            nv_index,  # authHandle
            nv_index,  # nvIndex
            len(auth_area),  # authorizationSize
        )
        cmd += auth_area
        cmd += struct.pack(">HH", chunk_size, offset)

        resp = _tbs_submit_command(tbs_ctx, tbs, ctypes, cmd)
        if resp is None or len(resp) < 10:
            return None

        _tag, _resp_size, rc = struct.unpack_from(">HII", resp, 0)
        if rc != 0:
            logger.debug("TPM2_NV_Read failed at offset %d: 0x%08X", offset, rc)
            return None

        # Parse response: header(10) + parameterSize(4) + TPM2B_MAX_NV_BUFFER(size(2) + data)
        if len(resp) < 16:
            return None
        _param_size = struct.unpack_from(">I", resp, 10)[0]
        data_len = struct.unpack_from(">H", resp, 14)[0]
        data_start = 16
        if len(resp) < data_start + data_len:
            return None
        result += resp[data_start : data_start + data_len]
        offset += data_len

    return result


def _check_platform_certificate() -> dict | None:
    """Attempt to discover a TCG Platform Certificate in TPM NV storage.

    The TCG Platform Certificate is stored at NV index 0x01C08000 by OEMs.
    It binds the TPM to a specific physical machine (make/model/serial).

    Returns a dict with OEM details if found, None otherwise.
    This is informational and does NOT affect the pass/fail count.
    """
    try:
        import ctypes

        tbs = ctypes.windll.tbs
    except (AttributeError, OSError):
        logger.debug("TBS API not available — skipping Platform Certificate probe")
        return None

    # Create TBS context for TPM 2.0
    tbs_ctx = ctypes.c_void_p()

    # TBS_CONTEXT_PARAMS2: version(4) + flags(4) = 8 bytes
    # version=2, includeTpm20=1 (bit 2 of flags)
    import struct

    params = (ctypes.c_ubyte * 8)(*struct.pack("<II", 2, 0x4))  # includeTpm20 = bit 2
    status = tbs.Tbsi_Context_Create(params, ctypes.byref(tbs_ctx))
    if status != 0:
        logger.debug("Tbsi_Context_Create failed: 0x%08X", status)
        return None

    try:
        # Step 1: Check if NV index exists and get data size
        data_size = _tpm2_nv_read_public(tbs_ctx, tbs, ctypes, _PLATFORM_CERT_NV_INDEX)
        if data_size is None or data_size == 0:
            logger.info(
                "Platform Certificate not found at TPM NV index 0x%08X (common on consumer/business PCs)",
                _PLATFORM_CERT_NV_INDEX,
            )
            return None

        logger.info(
            "Platform Certificate found at NV 0x%08X (%d bytes) — reading...",
            _PLATFORM_CERT_NV_INDEX,
            data_size,
        )

        # Step 2: Read the certificate data
        cert_data = _tpm2_nv_read(tbs_ctx, tbs, ctypes, _PLATFORM_CERT_NV_INDEX, data_size)
        if cert_data is None:
            logger.warning("Could not read Platform Certificate data from TPM NV")
            return None

        # Step 3: Try to parse as X.509 DER certificate
        result: dict[str, str] = {}
        try:
            cert = cx509.load_der_x509_certificate(cert_data)
            result["issuer"] = cert.issuer.rfc4514_string()
            result["subject"] = cert.subject.rfc4514_string()
            result["serial"] = format(cert.serial_number, "X")

            # Extract OEM details from subject
            for attr in cert.subject:
                if attr.oid == cx509.oid.NameOID.ORGANIZATION_NAME:
                    result["manufacturer"] = attr.value
                elif attr.oid == cx509.oid.NameOID.COMMON_NAME:
                    result["model"] = attr.value
                elif attr.oid == cx509.oid.NameOID.SERIAL_NUMBER:
                    result["serial_number"] = attr.value

            logger.info(
                "Platform Certificate: %s (signed by %s)",
                result.get("subject", "?"),
                result.get("issuer", "?"),
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Platform Certificate data is not a valid X.509 cert: %s", exc)
            result["raw_size"] = str(len(cert_data))

        return result if result else None

    finally:
        tbs.Tbsip_Context_Close(tbs_ctx)


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
    ek_cert_check, ek_pem, ek_details = _extract_ek_certificate()
    checks.append(ek_cert_check)
    if ek_pem:
        artifacts.append(
            AttestationArtifact(
                filename="ek_certificate.pem",
                content=ek_pem,
                description="TPM Endorsement Key certificate (manufacturer-signed)",
            )
        )
        if ek_details:
            artifacts.append(
                AttestationArtifact(
                    filename="ek_certificate_details.json",
                    content=json.dumps(ek_details, indent=2),
                    description="Parsed EK certificate details (issuer, serial, TCG attributes)",
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

    # Informational: Platform Certificate discovery (best-effort)
    platform_info = _check_platform_certificate()

    # ── Build human-readable verdict ────────────────────────────────
    # Checks group into two tiers:
    #   Tier 1 — TPM hardware (checks 1-4): Is there a genuine TPM?
    #   Tier 2 — Key residency (checks 5-7): Is the key provably in that TPM?
    #
    # A key is either on the TPM or it isn't — there's no "partial".
    # The summary should say exactly what was and wasn't confirmed.

    is_software = provider_info and provider_info.get("provider") == _MS_SOFTWARE_KSP

    # Build a check-name → passed lookup
    check_map = {chk.name: chk.passed for chk in checks}

    tpm_present = check_map.get("TPM status", False)
    ek_info_ok = check_map.get("EK information", False)
    ek_cert_ok = check_map.get("EK certificate extracted", False)
    ek_chain_ok = check_map.get("EK certificate chain verified", False)
    provider_ok = check_map.get("Key storage provider", False)
    claim_ok = check_map.get("NCryptCreateClaim attestation", False)
    export_ok = check_map.get("Key non-exportability", False)

    tpm_verified = tpm_present and ek_info_ok and ek_cert_ok and ek_chain_ok
    key_proven = provider_ok and claim_ok and export_ok

    if is_software:
        summary = (
            "The workload key is stored in software (--soft-key mode). "
            "Software keys cannot be attested to a TPM. "
            "Remove --soft-key to use hardware-bound keys."
        )
    elif tpm_verified and key_proven:
        summary = (
            "Cryptographically proven: your workload private key is bound to "
            "this TPM and cannot be extracted. The TPM's identity has been "
            "verified against the manufacturer's root certificate."
        )
    elif tpm_verified and provider_ok and not claim_ok:
        summary = (
            "Your device has a verified, genuine TPM and the workload key is "
            "stored in the TPM's key storage provider. However, the TPM could "
            "not produce a cryptographic attestation claim (NCryptCreateClaim "
            "failed). The key is likely on the TPM but this cannot be "
            "independently proven."
        )
    elif tpm_verified and not provider_ok:
        summary = (
            "Your device has a verified, genuine TPM but the workload key is "
            "not stored in the Platform Crypto Provider. The key may be in a "
            "software key store. Re-run setup without --soft-key to create a "
            "TPM-bound key."
        )
    elif tpm_present and not tpm_verified:
        summary = (
            "Your device has a TPM but its identity could not be fully verified. "
            "The EK certificate or manufacturer chain verification failed. "
            "The TPM may be genuine but we cannot cryptographically confirm it."
        )
    else:
        summary = (
            "No functional TPM was detected. Hardware attestation requires a "
            "TPM 2.0 that is present, enabled, and ready. Check your BIOS/UEFI "
            "settings to ensure the TPM is enabled."
        )

    return AttestationReport(
        platform="windows-cng",
        supported=True,
        hardware_type="CNG/TPM",
        artifacts=artifacts,
        checks=checks,
        summary=summary,
        platform_info=platform_info,
        ek_details=ek_details,
        tpm_info=tpm_info,
    )
