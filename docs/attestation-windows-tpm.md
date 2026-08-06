# Windows TPM Attestation — Developer Guide

## Overview

Windows TPM key attestation proves that a workload private key was generated
inside — and is permanently bound to — a genuine TPM chip.  On Windows, the
**Microsoft Platform Crypto Provider** (PCP) manages keys stored in the TPM via
the CNG (Cryptography Next Generation) API.

## Architecture

```
┌─────────────────────────────────┐
│   wif_bunker attestation        │
│   (wif_bunker/attestation/      │
│    windows.py)                  │
├─────────────────────────────────┤
│   ctypes FFI to ncrypt.dll      │
│   (NCryptOpenStorageProvider,   │
│    NCryptOpenKey,               │
│    NCryptGetProperty)           │
├─────────────────────────────────┤
│   Microsoft Platform Crypto     │
│   Provider (PCP) — ncrypt.dll   │
├─────────────────────────────────┤
│   TPM 2.0 Hardware              │
│   (Nuvoton, Intel, AMD, etc.)   │
└─────────────────────────────────┘
```

## The Correct Attestation Approach: PCP Properties

### How It Works

The PCP provider stores TPM creation metadata when a key is first created.
This data is accessible via `NCryptGetProperty` on the key handle.  This is the
same approach used by **Google's `go-attestation` library**:
https://github.com/google/go-attestation/blob/master/attest/pcp_windows.go

### PCP Properties Used

| Property | What It Contains | Purpose |
|---|---|---|
| `PCP_KEY_CREATION_HASH` | TPM2B_DIGEST | Hash of TPM creation data — proves key was TPM-generated |
| `PCP_KEY_CREATION_SOFTWAREBINDING` | Software binding blob | Links key to the creating software context |
| `PCP_TPM2BNAME` | TPM 2.0 Name = Hash(public area) | Unique TPM identifier for the key object |

### Code Flow

```python
# 1. Open the Platform Crypto Provider
ncrypt.NCryptOpenStorageProvider(byref(provider_handle), "Microsoft Platform Crypto Provider", 0)

# 2. Open the workload key by name
ncrypt.NCryptOpenKey(provider_handle, byref(key_handle), key_name, 0, 0)

# 3. Read PCP properties (two-call pattern: get size, then read)
for prop_name in ["PCP_KEY_CREATION_HASH", "PCP_KEY_CREATION_SOFTWAREBINDING", "PCP_TPM2BNAME"]:
    ncrypt.NCryptGetProperty(key_handle, prop_name, None, 0, byref(prop_size), 0)  # size query
    ncrypt.NCryptGetProperty(key_handle, prop_name, buffer, prop_size, byref(result), 0)  # read
```

### Critical: ctypes argtypes

**You MUST declare argtypes for ALL ncrypt functions.**  Without argtypes,
ctypes defaults to `c_int` (32-bit) for return values and may truncate 64-bit
HANDLE arguments on 64-bit Windows.

```python
ncrypt.NCryptGetProperty.argtypes = [
    ctypes.c_void_p,  # hObject (HANDLE - 64-bit on x64!)
    wintypes.LPCWSTR,  # pszProperty
    ctypes.c_void_p,  # pbOutput
    wintypes.DWORD,  # cbOutput
    ctypes.POINTER(wintypes.DWORD),  # pcbResult
    wintypes.DWORD,  # dwFlags
]
ncrypt.NCryptGetProperty.restype = ctypes.c_long
```

Key handles on 64-bit Windows are values like `0x1E15C690CE0` (41 bits) — if
truncated to 32 bits they become garbage handles and the TPM reports
"key not loaded".


## Full Attestation Check List

The attestation report runs 7 checks:

1. **TPM Status** — PowerShell `Get-Tpm` to verify TPM is present and ready
2. **EK Information** — Read the Endorsement Key public key hash and manufacturer certs
3. **EK Certificate** — Extract the EK cert from TPM NV index via PowerShell
4. **EK Chain Verification** — Verify EK cert against `tpm-ca-certificates` bundle
5. **Key Storage Provider** — Confirm key is in PCP (not software KSP)
6. **PCP Key Attestation** — Read PCP creation properties (see above)
7. **Key Non-Exportability** — Verify key cannot be exported


## Dead Ends and Traps

### ❌ Dead End 1: NCryptCreateClaim with NCRYPT_CLAIM_AUTHORITY_ONLY (0x1)

**What we tried:**  Call `NCryptCreateClaim(hSubjectKey=workload_key,
hAuthorityKey=attestation_key, dwClaimType=0x1)`.

**Why it failed:**  `NCRYPT_CLAIM_AUTHORITY_ONLY` (0x1) is for **VBS
(Virtualization-Based Security)** attestation, not TPM PCP.  It expects a VBS
authority key, not a TPM Attestation Identity Key (AIK).

**Error seen:** `0x8029040F` (PCP_E_KEY_NOT_LOADED) — consistently, on every
TPM vendor.

**Why it's confusing:**  The name "AUTHORITY_ONLY" sounds like it should work for
TPM key attestation where an AIK certifies a subject key.  But it's a VBS-only
concept.

### ❌ Dead End 2: Creating an explicit Attestation Key (AK) with IDENTITY_KEY policy

**What we tried:**  Created a persistent RSA 2048 key named
`wif-bunker-attestation-key` with `PCP_KEY_USAGE_POLICY = 0x8` (IDENTITY_KEY),
then used it as `hAuthorityKey` in `NCryptCreateClaim`.

**Why it failed:**  Even with a correctly-configured AK, `NCryptCreateClaim`
with `dwClaimType=0x1` doesn't do TPM2_Certify.  The AK was irrelevant because
the claim type was wrong.

**Symptoms observed:**
- First attempt with existing AK: `0x8029040F`
- Fresh AK with IDENTITY_KEY: `0x8029040F`
- Without AK (hAuthorityKey=NULL): `0x80290416` (key usage policy invalid)

**Additional trap:** Setting `PCP_KEY_USAGE_POLICY = SIGNATURE_KEY (0x1)` on
the **workload** key reads back as `0x00010001` (the PCP driver prepends
`0x00010000` to whatever you set).  This created a "restricted" key template
that prevented even basic signing operations.

### ❌ Dead End 3: NCryptCreateClaim with NCRYPT_CLAIM_PLATFORM (0x10000)

**What we tried:**  `NCryptCreateClaim(hSubjectKey=workload_key,
hAuthorityKey=NULL, dwClaimType=0x10000)` with a PCR mask in the parameter list.

**Why it failed:**  `NCRYPT_CLAIM_PLATFORM` is for **boot/PCR attestation**
(TPM2_Quote over Platform Configuration Registers), not for key attestation.
It's the wrong operation entirely — it proves the boot state, not that a
specific key is TPM-bound.

**Error seen:** `0x80090027` (NTE_INVALID_PARAMETER).

### ❌ Dead End 4: 64-bit Handle Truncation Theory

**What we theorized:**  Without ctypes `argtypes`, 64-bit HANDLE values like
`0x1E15C690CE0` would be truncated to 32 bits, sending garbage handles to
`NCryptCreateClaim`.

**Reality:**  While declaring argtypes IS important (and we keep them), the
truncation theory was not the root cause.  The real problem was using the wrong
`dwClaimType`.  ctypes actually handles `c_void_p` arguments correctly even
without argtypes — it's the return value truncation that's more dangerous.

**Lesson:** Always declare argtypes anyway — it's defensive programming and
helps catch other marshalling bugs.


## Key Properties Reference

### PCP_KEY_USAGE_POLICY Values

The PCP driver adds `0x00010000` to whatever policy you set:

| You Set | TPM Reads Back | Meaning |
|---|---|---|
| Nothing | `0x00010001` | Default — unrestricted key |
| `0x1` (SIGNATURE_KEY) | `0x00010001` | Same as default! |
| `0x8` (IDENTITY_KEY) | `0x00010008` | Restricted signing key |

### NCrypt Error Codes

| Code | Name | Meaning |
|---|---|---|
| `0x8029040F` | PCP_E_KEY_NOT_LOADED | Key handle not recognized by TPM — wrong claim type or handle |
| `0x80290416` | PCP_E_BUFFER_LENGTH_MISMATCH | Key usage policy invalid (also seen as "no authority key") |
| `0x80090027` | NTE_INVALID_PARAMETER | Bad parameters — wrong claim type for the provider |
| `0x80090016` | NTE_BAD_KEYSET | Key not found (keyset does not exist) |
| `0x80280092` | TPM_E_SCHEME | TPM scheme mismatch — algorithm incompatibility |

### Tested TPM Vendors

| Vendor | Device | Result |
|---|---|---|
| Nuvoton (NTC) | Dell OptiPlex | ✅ Works with PCP properties |
| AMD | Surface Laptop 3 | ✅ Works with PCP properties |
| Intel | NUC (Linux) | N/A — uses tpm2-tools on Linux |


## PowerShell Commands Used

```powershell
# TPM Status
Get-Tpm | ConvertTo-Json -Depth 5

# EK Information (requires module import)
Import-Module Microsoft.PowerShell.Security; Import-Module PKI;
$ekPub = (Get-TpmEndorsementKeyInfo -Hash 'Sha256').PublicKeyHash;
$certs = @(Get-ChildItem Cert:\LocalMachine\YOURSTORE | ...);

# EK Certificate from NV Index
# (Reads from TPM NV 0x01C08000 — not present on all devices)
```


## File: wif_bunker/attestation/windows.py

### Key Functions

| Function | Purpose |
|---|---|
| `_check_tpm_status()` | PowerShell `Get-Tpm` — returns TPM present/ready/manufacturer |
| `_check_ek_info()` | PowerShell EK hash + manufacturer certs |
| `_extract_ek_certificate()` | PowerShell NV index read for EK cert |
| `_check_key_provider()` | `certutil -store -user` to find key in PCP |
| `_ncrypt_create_claim()` | The main attestation — reads PCP properties |
| `_check_exportability()` | `certutil -v -user -store` to verify non-exportable |
| `collect_attestation()` | Orchestrates all checks into `AttestationReport` |
