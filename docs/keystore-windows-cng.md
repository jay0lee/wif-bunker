# Windows CNG Keystore — Developer Guide

## Overview

On Windows, workload keys are stored in the **Microsoft Platform Crypto
Provider** (PCP), which binds them to the TPM.  Key creation, certificate
signing, and certificate import all go through the CNG (Cryptography Next
Generation) API, accessed via PowerShell `.NET` interop.

The critical invariant: **the private key never leaves the TPM**.  The PCP
provider generates the key inside the TPM and returns only a handle.  All
signing operations happen on-chip.


## Key Creation Flow

### Step 1: Generate a TPM-Bound Key Pair

**PowerShell / .NET API:**
```powershell
$cngKey = [System.Security.Cryptography.CngKey]::Create(
    [System.Security.Cryptography.CngAlgorithm]::ECDsaP256,
    $keyName,
    $keyParams
)
```

**Parameters that matter:**

| Parameter | Value | Why |
|---|---|---|
| Provider | `Microsoft Platform Crypto Provider` | Routes key generation to the TPM hardware |
| Algorithm | `ECDsaP256` / `ECDsaP384` / `RSA` | Must match the desired signing algorithm |
| Key name | `bunker-workload-<epoch>` | Unique name for the CNG key container |
| Export policy | `None` (0x0) | **Critical** — makes the key non-exportable |
| Key usage | `Signing` | Marks the key for digital signature operations |

**Platform behavior:**
- The PCP provider calls `TPM2_Create` internally
- The key is stored in the TPM's non-volatile storage
- Only a handle/reference is returned to userspace
- The key name must be unique — creating with a duplicate name fails

**CngKeyCreationParameters setup:**
```powershell
$keyParams = New-Object System.Security.Cryptography.CngKeyCreationParameters
$keyParams.Provider = New-Object System.Security.Cryptography.CngProvider(
    "Microsoft Platform Crypto Provider"
)
$keyParams.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
$keyParams.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
```

### Step 2: Export the Public Key

**API:**
```powershell
$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
$ecdsa.ImportParameters($cngKey.Export(...))
# or for the public key blob:
$pubKeyBytes = $cngKey.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
```

**Platform behavior:**
- Public key export always succeeds (only private export is blocked)
- The public key bytes are in CNG blob format, which includes a header
- For ECDSA P-256: the blob is 72 bytes (8-byte header + 32-byte X + 32-byte Y)
- For ECDSA P-384: 104 bytes (8-byte header + 48-byte X + 48-byte Y)

**CNG ECC Public Blob format:**
```
Offset  Size  Field
0       4     Magic ('ECK1' for P-256, 'ECK3' for P-384)
4       4     Key size in bytes (32 for P-256, 48 for P-384)
8       N     X coordinate (big-endian)
8+N     N     Y coordinate (big-endian)
```

### Step 3: Create an Ephemeral CA and Sign the Workload Certificate

This happens in Python (not CNG-specific):
1. Generate an ephemeral RSA CA key pair (in software)
2. Create a self-signed CA certificate
3. Create a CSR-like structure for the workload public key
4. Sign the workload certificate with the ephemeral CA
5. The ephemeral CA private key is discarded after signing

### Step 4: Import the Signed Certificate into the Windows Certificate Store

**PowerShell command:**
```powershell
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $certPath
)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    "My", "CurrentUser"
)
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
```

Wait — that only imports the certificate.  We must also **bind** the cert
to the existing CNG key:

**Binding the cert to the TPM key:**
```powershell
# The key association happens via matching the public key
# The cert's public key must match the CNG key's public key
$cert.PrivateKey = $cngKey  # .NET binds them
```

**Platform behavior:**
- The certificate is stored in `Cert:\CurrentUser\My`
- The private key remains in the TPM — the cert store only holds a reference
- The binding is by key name — if the CNG key is deleted, the cert becomes orphaned
- **Import must use `Import-PfxCertificate` or direct .NET store APIs** — `certutil -importcert` does NOT bind to the existing private key

### Step 5: Verify the Binding

**PowerShell verification:**
```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -like "*bunker-workload*"
}
$cert.HasPrivateKey  # Must be True
$cert.PrivateKey.Key.Provider.Provider  # Must be "Microsoft Platform Crypto Provider"
```


## Certificate Store Cleanup

### Stale Certificate Removal

Before creating a new workload identity, old `bunker-workload*` certs must
be cleaned from the CurrentUser store.

**PowerShell command:**
```powershell
Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -like "CN=bunker-workload*" } |
    Remove-Item -Force
```

**Critical platform behavior:**
- `Remove-Item` on a cert in `Cert:\` calls `CertDeleteCertificateFromStore`
- This deletes the **cert context** from the store
- It does NOT delete the underlying CNG key from the TPM
- To also delete the CNG key: use `certutil -delkey` or
  `[System.Security.Cryptography.CngKey]::Open($name).Delete()`

### CNG Key Cleanup

To delete orphaned TPM keys:
```powershell
# List all PCP keys
certutil -key -csp "Microsoft Platform Crypto Provider"

# Delete a specific key
certutil -delkey -csp "Microsoft Platform Crypto Provider" "bunker-workload-12345"
```


## Platform Quirks and Gotchas

### 1. CertFreeCertificateContext Bug

**Problem:** The Windows API `CertFreeCertificateContext` can accidentally
delete the cert from the store instead of just releasing the handle, if the
cert context was obtained via `CertEnumCertificatesInStore`.

**Impact:** Iterating over certs and freeing contexts can silently remove certs.

**Solution:** Don't call `CertFreeCertificateContext` on contexts from
`CertEnumCertificatesInStore`.  Let the enumeration handle cleanup.

### 2. PCP_KEY_USAGE_POLICY Prepending

**Behavior:** The PCP driver prepends `0x00010000` to whatever
`PCP_KEY_USAGE_POLICY` you set:

| You set | TPM reads back | Effect |
|---|---|---|
| Nothing | `0x00010001` | Default — signing + key exchange |
| `0x1` (SIGNATURE_KEY) | `0x00010001` | Same as default! |
| `0x8` (IDENTITY_KEY) | `0x00010008` | Restricted signing (for AKs only) |

**Lesson:** Don't set `PCP_KEY_USAGE_POLICY` on workload keys — the default
is correct.  Setting SIGNATURE_KEY explicitly does nothing useful and caused
confusion during debugging.

### 3. PowerShell Module Compatibility

PowerShell 7+ does NOT auto-load the `PKI` and `Microsoft.PowerShell.Security`
modules.  All PowerShell commands must be prefixed with:
```powershell
Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue;
Import-Module PKI -ErrorAction SilentlyContinue;
```

### 4. Software Fallback

If no TPM is available or the PCP provider fails, keys fall back to:
- **Provider:** `Microsoft Software Key Storage Provider`
- **Storage:** Software-only (DPAPI-protected file on disk)
- **Flag:** `--soft-key` CLI option

The software KSP uses the same CNG API but stores keys in
`%APPDATA%\Microsoft\Crypto\Keys\` instead of the TPM.

### 5. Algorithm Support by Provider

| Algorithm | Software KSP | PCP (TPM) |
|---|---|---|
| ECDSA P-256 | ✅ | ✅ |
| ECDSA P-384 | ✅ | ✅ (most TPMs) |
| RSA 2048 | ✅ | ✅ |
| RSA 4096 | ✅ | ⚠️ Some TPMs reject |
| Ed25519 | ❌ | ❌ |


## Error Codes Reference

| HRESULT | Name | Meaning |
|---|---|---|
| `0x80090016` | NTE_BAD_KEYSET | Key container not found |
| `0x80090020` | NTE_FAIL | General CNG failure |
| `0x80090027` | NTE_INVALID_PARAMETER | Bad parameter to CNG function |
| `0x80090029` | NTE_NOT_SUPPORTED | Operation not supported by provider |
| `0x8009002A` | NTE_PERM | Permission denied |
| `0x80092004` | CRYPT_E_NOT_FOUND | Certificate not found in store |


## File: wif_bunker/keystore/ncrypt.py

### Key Functions

| Function | Purpose |
|---|---|
| `generate_cert_ncrypt()` | Main entry: creates key, signs cert, imports to store |
| `_create_tpm_key()` | PowerShell: CngKey.Create in PCP provider |
| `_export_public_key()` | PowerShell: export CNG public key blob |
| `_create_ca_and_sign()` | Python: ephemeral CA + workload cert signing |
| `_import_cert_to_store()` | PowerShell: import cert and bind to CNG key |
| `_cleanup_stale_certs()` | PowerShell: remove old bunker-workload certs |
