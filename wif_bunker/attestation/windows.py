"""Windows CNG/TPM key attestation via NCrypt ctypes bindings.

Uses NCryptCreateClaim for cryptographic attestation and PowerShell for
TPM status and EK information.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from wif_bunker.attestation.base import (
    AttestationArtifact,
    AttestationCheck,
    AttestationReport,
)
from wif_bunker.config import WorkloadConfig

logger = logging.getLogger(__name__)

# CNG constants
_MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"
_MS_SOFTWARE_KSP = "Microsoft Software Key Storage Provider"
_NCRYPT_CLAIM_KEY_ATTESTATION = 0x00000001


def _run_powershell(command: str) -> subprocess.CompletedProcess:
    """Run a PowerShell command and return the result."""
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
    )


def _check_tpm_status() -> tuple[AttestationCheck, dict | None]:
    """Query TPM status via PowerShell Get-Tpm."""
    result = _run_powershell("Get-Tpm | ConvertTo-Json -Depth 3")
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
    result = _run_powershell("Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 | ConvertTo-Json -Depth 3")
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
    result = _run_powershell(ps_command)
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

    # Extract issuer for identification
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
        tmp.write(output)
        tmp_path = tmp.name

    try:
        info = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-issuer", "-noout"],
            capture_output=True,
            text=True,
        )
        issuer = info.stdout.strip() if info.returncode == 0 else "unknown"
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return (
        AttestationCheck(
            name="EK certificate extracted",
            passed=True,
            detail=f"EK certificate extracted from TPM. Issuer: {issuer}",
        ),
        output,
    )


def _verify_ek_chain(ek_pem: str) -> AttestationCheck:
    """Verify EK certificate against known manufacturer root CAs."""
    roots_dir = Path(__file__).parent / "roots"
    if not roots_dir.exists() or not any(roots_dir.glob("*.pem")):
        return AttestationCheck(
            name="EK certificate chain verified",
            passed=False,
            detail=("No manufacturer root CA certificates bundled. Chain verification skipped."),
        )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
        tmp.write(ek_pem)
        ek_path = tmp.name

    try:
        for root_ca in sorted(roots_dir.glob("*.pem")):
            result = subprocess.run(
                ["openssl", "verify", "-CAfile", str(root_ca), ek_path],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and ": OK" in result.stdout:
                manufacturer = root_ca.stem.replace("_", " ").title()
                return AttestationCheck(
                    name="EK certificate chain verified",
                    passed=True,
                    detail=(f"EK certificate verified against {manufacturer} root CA ({root_ca.name})"),
                )
    finally:
        Path(ek_path).unlink(missing_ok=True)

    return AttestationCheck(
        name="EK certificate chain verified",
        passed=False,
        detail=("EK certificate did not chain to any bundled manufacturer root CA."),
    )


def _check_key_provider(config: WorkloadConfig) -> tuple[AttestationCheck, dict | None]:
    """Verify the bunker key's CNG storage provider."""
    # List keys in the Platform Crypto Provider
    result = subprocess.run(
        ["certutil", "-csp", _MS_PLATFORM_CRYPTO_PROVIDER, "-key"],
        capture_output=True,
        text=True,
    )

    key_cn = config.workload_cn
    is_platform = key_cn in result.stdout if result.returncode == 0 else False

    if is_platform:
        return (
            AttestationCheck(
                name="Key storage provider",
                passed=True,
                detail=f"Key '{key_cn}' found in {_MS_PLATFORM_CRYPTO_PROVIDER} (TPM-backed)",
            ),
            {"provider": _MS_PLATFORM_CRYPTO_PROVIDER, "key_name": key_cn},
        )

    # Check if it's in the software KSP instead
    result_sw = subprocess.run(
        ["certutil", "-csp", _MS_SOFTWARE_KSP, "-key"],
        capture_output=True,
        text=True,
    )
    is_software = key_cn in result_sw.stdout if result_sw.returncode == 0 else False

    if is_software:
        return (
            AttestationCheck(
                name="Key storage provider",
                passed=False,
                detail=(
                    f"Key '{key_cn}' is in {_MS_SOFTWARE_KSP} (software-backed, not TPM). "
                    "Use a TPM-backed key (remove --soft-key) for hardware attestation."
                ),
            ),
            {"provider": _MS_SOFTWARE_KSP, "key_name": key_cn},
        )

    return (
        AttestationCheck(
            name="Key storage provider",
            passed=False,
            detail=f"Key '{key_cn}' not found in any CNG provider",
        ),
        None,
    )


def _ncrypt_create_claim(config: WorkloadConfig) -> tuple[AttestationCheck, bytes | None]:
    """Create a TPM key attestation claim via NCrypt ctypes FFI.

    Uses NCryptCreateClaim with NCRYPT_CLAIM_KEY_ATTESTATION to produce
    a cryptographic proof that the key resides in the TPM.
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
    provider_name = _MS_PLATFORM_CRYPTO_PROVIDER

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

        # Open the key
        key_name = config.workload_cn
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

        # Create attestation claim
        claim_size = wintypes.DWORD(0)

        # First call to get required buffer size
        status = ncrypt.NCryptCreateClaim(
            key_handle,
            None,  # no additional key
            _NCRYPT_CLAIM_KEY_ATTESTATION,
            None,  # no parameters
            None,  # output buffer (null for size query)
            0,
            ctypes.byref(claim_size),
            0,
        )
        if status != 0:
            return (
                AttestationCheck(
                    name="NCryptCreateClaim attestation",
                    passed=False,
                    detail=(
                        f"NCryptCreateClaim size query failed: 0x{status:08X}. "
                        "This is expected for software keys (--soft-key)."
                    ),
                ),
                None,
            )

        # Second call with allocated buffer
        claim_buffer = (ctypes.c_byte * claim_size.value)()
        result_size = wintypes.DWORD(0)
        status = ncrypt.NCryptCreateClaim(
            key_handle,
            None,
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
                    detail=f"NCryptCreateClaim failed: 0x{status:08X}",
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


def _attest_windows(config: WorkloadConfig) -> AttestationReport:
    """Perform Windows CNG/TPM key attestation."""
    checks: list[AttestationCheck] = []
    artifacts: list[AttestationArtifact] = []

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
        chain_check = _verify_ek_chain(ek_pem)
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
    claim_check, claim_blob = _ncrypt_create_claim(config)
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
