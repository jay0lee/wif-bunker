# Linux TPM Attestation — Developer Guide

## Overview

Linux TPM key attestation uses **tpm2-tools** to interact directly with the
TPM 2.0 device at `/dev/tpmrm0`.  Unlike Windows (which uses the PCP
abstraction), Linux talks to the TPM via the Resource Manager using standard
TPM2 commands: `tpm2_createek`, `tpm2_createak`, `tpm2_certify`, etc.

## Architecture

```
┌─────────────────────────────────┐
│   wif_bunker attestation        │
│   (wif_bunker/attestation/      │
│    linux.py)                    │
├─────────────────────────────────┤
│   tpm2-tools CLI                │
│   (tpm2_createek, tpm2_readpub, │
│    tpm2_createak, tpm2_certify, │
│    tpm2_getekcertificate,       │
│    tpm2_makecredential,         │
│    tpm2_activatecredential,     │
│    tpm2_startauthsession,       │
│    tpm2_policysecret,           │
│    tpm2_createprimary,          │
│    tpm2_getcap,                 │
│    tpm2_nvread)                 │
├─────────────────────────────────┤
│   TPM2 Resource Manager         │
│   /dev/tpmrm0                   │
├─────────────────────────────────┤
│   TPM 2.0 Hardware              │
│   (Intel, AMD, etc.)            │
└─────────────────────────────────┘
```


## The Attestation Flow (6 Steps)

Entry point: `_attest_linux(config: WorkloadConfig)`.  All work is done in
a `tempfile.TemporaryDirectory`.

### Step 0: Prerequisites Check

```python
require_commands(
    "tpm2_createek", "tpm2_createak", "tpm2_certify", "tpm2_nvread", "tpm2_makecredential", "tpm2_activatecredential"
)
```

Also calls `_get_tpm_info(work_dir)` which runs `tpm2_getcap properties-fixed`
to extract manufacturer, firmware version, and family indicator.

### Step 1: Extract EK Certificate

**Function:** `_extract_ek_certificate()`

Tries multiple methods in order:

1. **NVRAM read** — `tpm2_nvread -C o <NV_INDEX> -o ek_cert.der`
   - RSA index: `0x01C00002`
   - ECC index: `0x01C0000A`
2. **Manufacturer provisioning** — `tpm2_getekcertificate -u ek_pub_native.tpm2 -o ek_cert_fetched.pem`

> **IMPORTANT: pyOpenSSL vs cryptography library**
>
> DER→PEM conversion uses `OpenSSL.crypto.load_certificate(FILETYPE_ASN1, ...)`
> from pyOpenSSL, NOT the `cryptography` library's Rust parser.  Real-world TPM
> EK certificates from Intel and Nuvoton have non-canonical DER encoding that
> the `cryptography` library rejects with `InvalidSetOrdering` errors.
> See: pyca/cryptography#7189

### Step 2: Verify EK Certificate Chain

**Function:** `verify_ek_chain()` (in `base.py`)

- Loads root CAs and intermediates from bundled `roots/` directory
  (sourced from [tpm-ca-certificates](https://github.com/loicsikidi/tpm-ca-certificates)),
  plus a `manually-managed/` directory
- Uses **pyOpenSSL's `X509StoreContext`** for chain verification

**AIA Chasing** — If verification fails with "unable to get local issuer
certificate":
1. Runs `openssl x509 -noout -text` to extract AIA extension URLs
2. Fetches the issuer cert via HTTP (`urllib.request`)
3. Adds it to intermediates and retries (up to 3 levels deep)

### Step 3: Create EK + AK

**Function:** `_create_ek_and_ak()`

```bash
# Create EK, export public key in TPM2B_PUBLIC and PEM formats
tpm2_createek -c ek.ctx -G rsa -u ek_pub.tpm2
tpm2_createek -c ek.ctx -G rsa -u ek_pub.pem -f pem

# Create AK bound to the EK in endorsement hierarchy
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -u ak_pub.pem -f pem -n ak.name
```

### Step 4: Credential Activation

**Function:** `_credential_activation()`

This proves the AK and EK live on the same TPM:

```bash
# 1. Generate random challenge
echo "<random_bytes_base64>" > challenge.txt

# 2. Encrypt challenge to EK, binding it to AK's name
tpm2_makecredential -u ek_pub.tpm2 -s challenge.txt -n <ak_name_hex> -o credential.secret

# 3. Create policy session for EK auth
tpm2_startauthsession --policy-session -S session.ctx
tpm2_policysecret -S session.ctx -c 0x4000000B   # TPM_RH_ENDORSEMENT

# 4. Decrypt on-TPM (only works if AK is on same TPM as EK)
tpm2_activatecredential -c ak.ctx -C ek.ctx -i credential.secret \
    -o decrypted_challenge.txt -P session:session.ctx

# 5. Compare decrypted output to original challenge
```

### Step 5: Key Certification (TPM2_Certify)

**Function:** `_certify_key()`

This is the **core attestation** — the AK signs proof that the workload key
exists inside the TPM:

```bash
# Create a primary key in owner hierarchy (parent of tpm2-pkcs11 keys)
tpm2_createprimary -C o -g sha256 -G rsa -c owner_primary.ctx

# AK certifies the workload key
tpm2_certify -c owner_primary.ctx -C ak.ctx -g sha256 \
    -o certify_attest.bin -s certify_signature.bin
```

> **Note:** The `-q` (qualifying-data/nonce) flag is intentionally omitted
> for compatibility with tpm2-tools ≤5.6.

**Outputs:**
- `certify_attest.bin` — TPM2B_ATTEST structure (signed by AK)
- `certify_signature.bin` — TPMT_SIGNATURE (AK's signature over the attest)

### Step 6: PKCS#11 Store Cross-Reference

**Function:** `_extract_workload_key_from_pkcs11()`

Searches for `tpm2_pkcs11.sqlite3` in standard locations and queries it:
- `$TPM2_PKCS11_STORE`, `~/.tpm2_pkcs11`, `/etc/tpm2_pkcs11`
- SQL: `SELECT id, label FROM tokens WHERE label LIKE '%bunker%'`
- Returns token metadata (store_path, token_id, token_label, object_count)


## Attestation Checks Summary

| # | Check | Tool | What It Proves |
|---|---|---|---|
| 1 | TPM Status | `tpm2_getcap` | TPM is present and functional |
| 2 | EK Info | `tpm2_createek` | EK exists and public key is readable |
| 3 | EK Certificate | `tpm2_getekcertificate` / NV read | EK cert from manufacturer |
| 4 | EK Chain | pyOpenSSL `X509StoreContext` | EK cert chains to known TPM CA |
| 5 | Credential Activation | `tpm2_makecredential` / `activatecredential` | AK + EK are on same physical TPM |
| 6 | Key Certification | `tpm2_certify` | **Cryptographic proof** key is in TPM |
| 7 | Non-Exportability | `tpm2_readpublic` attributes | fixedTPM + fixedParent set |


## Key Differences from Windows

| Aspect | Linux | Windows |
|---|---|---|
| TPM interface | `/dev/tpmrm0` via tpm2-tools | ncrypt.dll PCP provider |
| Key attestation method | `tpm2_certify` (TPM2_Certify) | `NCryptGetProperty("PCP_TPM2BNAME")` |
| AK requirement | Yes — AK signs the certification | No — PCP stores creation data internally |
| Credential activation | Explicit `makecredential`/`activatecredential` | Not needed (PCP handles internally) |
| EK cert retrieval | `tpm2_getekcertificate` or NV read | PowerShell Get-TpmEndorsementKeyInfo |
| Admin required | Access to `/dev/tpmrm0` (usually `tss` group) | Usually non-admin works |


## ASN.1 Compatibility (Critical)

This is a major recurring issue across both Linux and Windows.

**Problem:** Real-world TPM EK certificates from Intel and Nuvoton have
non-canonical DER encoding.  The `cryptography` library's Rust-based X.509
parser rejects them with errors like:
- `InvalidSetOrdering`
- Explicit `critical=FALSE` when it should be omitted

**Solution:** Use `pyOpenSSL` (`OpenSSL.crypto`) for DER↔PEM conversion and
chain verification.  pyOpenSSL uses the C OpenSSL library which is more lenient.

**Reference:** pyca/cryptography#7189 — maintainers explicitly refuse to add
leniency for non-standard certificates.


## Error Handling Notes

### Common tpm2-tools Errors

| Error | Meaning | Fix |
|---|---|---|
| `command not found` | tpm2-tools not installed | `apt install tpm2-tools` |
| `Could not open /dev/tpmrm0` | No TPM or no permissions | Add user to `tss` group |
| `TPM2_RC_COMMAND_CODE` | Command not supported | Firmware too old |
| `TPM2_RC_NV_UNINITIALIZED` | NV index empty | Use `tpm2_getekcertificate` fallback |

### Graceful Degradation

Each step checks if the previous step succeeded before proceeding:
- If AK creation fails → credential activation and key certification are skipped
- If EK cert extraction fails → chain verification is skipped
- The final summary has 6 distinct messages based on which combination passed/failed

### Software TPM (swtpm)

The CI uses `swtpm` (software TPM simulator):
- swtpm generates self-signed EK certs NOT in the `tpm-ca-certificates` bundle
- Key certification may succeed but chain verification will fail
- Summary messages specifically account for this scenario


## File: wif_bunker/attestation/linux.py

### Key Functions

| Function | Purpose |
|---|---|
| `_run_tpm2()` | Helper: runs tpm2-tools commands via `subprocess.run()` |
| `_get_tpm_info()` | `tpm2_getcap properties-fixed` — manufacturer/firmware |
| `_extract_ek_certificate()` | NV read or `tpm2_getekcertificate` — EK cert |
| `_create_ek_and_ak()` | `tpm2_createek` + `tpm2_createak` — key hierarchy |
| `_credential_activation()` | `tpm2_makecredential`/`activatecredential` — TPM identity |
| `_certify_key()` | `tpm2_certify` — core attestation proof |
| `_extract_workload_key_from_pkcs11()` | SQLite query of tpm2-pkcs11 store |
| `_attest_linux()` | Orchestrates all checks into `AttestationReport` |


## File: wif_bunker/attestation/base.py

### Shared Data Model

| Class | Purpose |
|---|---|
| `AttestationArtifact` | filename, content (str/bytes), description, is_binary |
| `AttestationCheck` | name, passed (bool), detail (str) |
| `AttestationReport` | platform, supported, hardware_type, artifacts, checks, summary |

### Shared Functions

| Function | Purpose |
|---|---|
| `verify_ek_chain()` | pyOpenSSL X509StoreContext chain verification + AIA chasing |
| `_parse_tcg_attributes()` | Extract manufacturer/model/version from EK cert SAN |
| `_decode_manufacturer_id()` | Map 32-bit TCG vendor IDs to human names (17 manufacturers) |
| `parse_ek_details()` | Two-tier parsing: `cryptography.x509` → pyOpenSSL fallback |
