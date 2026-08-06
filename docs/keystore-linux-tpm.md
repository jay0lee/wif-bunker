# Linux TPM Keystore — Developer Guide

## Overview

On Linux, workload keys are stored in the TPM via the **tpm2-pkcs11** PKCS#11
middleware.  Key creation goes through `tpm2_ptool`, signing uses GnuTLS
`certtool` with PKCS#11 URIs, and the resulting cert is imported back into the
PKCS#11 token.


## Key Creation Flow

### Step 1: Check Hardware Capability

**Command:**
```bash
tpm2_testparms ecc256:ecdsa     # or rsa2048:rsassa
```

- Returns exit code 0 if the TPM supports the algorithm
- Returns non-zero if unsupported
- **Gotcha:** Many firmware TPMs (Intel PTT, AMD fTPM) only support P-256.
  P-384 and RSA-4096 may be rejected.

### Step 2: Environment Setup

```bash
export TPM2_PKCS11_STORE=~/.tpm2_pkcs11
```

**This is mandatory.** Without it, operations fall back to `/etc/tpm2_pkcs11`
which requires root.

### Step 3: Cleanup Old Tokens (CRITICAL)

This step has multiple gotchas. Must be done carefully.

```bash
# 1. Remove the logical PKCS#11 token from the SQLite DB
tpm2_ptool rmtoken --label=bunker-wif

# 2. Find physical TPM NV handles belonging to this token
tpm2_ptool listprimaries

# 3. Evict each handle from TPM NV storage
tpm2_evictcontrol -c 0x81000001
```

**Why all three steps:**

| Step | What it does | What it does NOT do |
|---|---|---|
| `rmtoken` | Deletes the DB entry | ❌ Does NOT evict NV handles from TPM |
| `listprimaries` | Finds which NV handles belong to the token | — |
| `evictcontrol` | Frees TPM NV storage | ❌ Does NOT touch the DB |

> **⚠️ CRITICAL: "No Space Left" Bug**
>
> If you only call `rmtoken` without `evictcontrol`, the TPM NV storage fills
> up after 2-3 key creations.  Error: `TPM_RC_NV_SPACE` (`0x14b`).
>
> Recovery: `tpm2_getcap handles-persistent` to list all handles, then
> `tpm2_evictcontrol -c <handle>` for each.

> **⚠️ CRITICAL: Do NOT `rm -rf ~/.tpm2_pkcs11`**
>
> The Python `tpm2_ptool` tool may recreate the SQLite database with a different
> schema version than the system C library (`libtpm2_pkcs11.so`) expects.
> This causes mysterious `CKR_OPERATION_NOT_INITIALIZED` errors.  Always use
> `rmtoken` instead.

> **⚠️ CRITICAL: Eviction Safety**
>
> Only evict handles that belong to your token (found via `listprimaries`).
> Arbitrarily evicting all persistent handles will break the host's Secure Boot,
> LUKS disk encryption, or VPN keys.

### Step 4: Create Token and Key

```bash
# Initialize the PKCS#11 SQLite database
tpm2_ptool init

# Create a logical token
tpm2_ptool addtoken --pid=1 --sopin=<pin> --userpin=<pin> --label=bunker-wif

# Generate the TPM key
tpm2_ptool addkey --algorithm=ecc256:ecdsa --label=bunker-wif \
    --key-label=<cn> --userpin=<pin>
```

**`addkey` returns a `CKA_ID`** (e.g., `CKA_ID '31323334'`).  This ID is
essential — it links the key to its certificate in the PKCS#11 store.

### Step 5: Sign Certificate via PKCS#11

```bash
export GNUTLS_PIN=<pin>
certtool --generate-self-signed \
    --load-privkey "pkcs11:token=bunker-wif;object=<cn>;type=private;pin-value=<pin>" \
    --outfile workload.pem \
    --template certtool.cfg
```

**The PKCS#11 URI must be exact:**
- `token=` must match `--label` from `addtoken`
- `object=` must match `--key-label` from `addkey`
- `pin-value=` provides authentication without interactive prompt
- `GNUTLS_PIN` environment variable prevents `certtool` from hanging

### Step 6: Import Signed Certificate

```bash
echo "<pin>" | tpm2_ptool addcert --label=bunker-wif \
    --key-id=<CKA_ID> workload.pem
```

The `--key-id` must be the `CKA_ID` returned from `addkey`.
The PIN is read from stdin.


## Algorithm Mapping

| Config Name | tpm2-tools Algorithm | Notes |
|---|---|---|
| `es256` | `ecc256:ecdsa` | Most widely supported |
| `es384` | `ecc384:ecdsa` | Some firmware TPMs reject |
| `rsa2048` | `rsa2048:rsassa` | Universally supported |
| `rsa4096` | `rsa4096:rsassa` | Many TPMs reject |


## Platform Quirks and Gotchas

### 1. Ubuntu `tpm2_ptool` Wrapper Bug

On newer Ubuntu (26.04+), the `/usr/bin/tpm2_ptool` wrapper is broken due to
an `easy_install` entry-point version mismatch.

**Detection:** Run `tpm2_ptool --help` — if it fails, fall back to:
```bash
python3 -m tpm2_pkcs11.tpm2_ptool
```

### 2. Permission Requirements

The user must have R/W access to `/dev/tpmrm0`:
```bash
sudo usermod -aG tss <username>
# Log out and back in
```

### 3. TCTI Configuration

If the Resource Manager isn't at the default path, set:
```bash
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
# or for swtpm:
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
```

### 4. PKCS#11 Library Paths

For mTLS via ECP, the PKCS#11 `.so` library must be found:

| Library | Common Paths |
|---|---|
| `libtpm2_pkcs11.so` | `/usr/lib/x86_64-linux-gnu/pkcs11/`, `/usr/lib/pkcs11/` |


## Error Reference

| Error | Meaning | Fix |
|---|---|---|
| `Could not load tcti` | TPM resource manager not found | Check `/dev/tpmrm0`, set `TPM2TOOLS_TCTI` |
| `insufficient space` / `0x14b` | TPM NV storage full | Evict old handles with `tpm2_evictcontrol` |
| `timed out` | Resource Manager frozen | Reboot or restart `tpm2-abrmd` |
| `CKR_OPERATION_NOT_INITIALIZED` | SQLite schema mismatch | Don't `rm -rf` the DB — use `rmtoken` |
| `CKA_ID not found` | Key-cert binding mismatch | Ensure `addcert --key-id` matches `addkey` output |
