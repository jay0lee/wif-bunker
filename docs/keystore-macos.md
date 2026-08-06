# macOS Keystore — Developer Guide

## Overview

On macOS, workload keys are generated inside the **Secure Enclave** via
Apple's **CryptoTokenKit (CTK)** framework, accessed through the `sc_auth`
command-line tool.  The private key never leaves the Secure Enclave hardware.

**Requires macOS 15+ (Sequoia)** — `sc_auth` CTK identity creation is not
available on older macOS versions.


## Key Creation Flow

### Step 1: Clean Up Stale Identities

**Commands:**
```bash
# Find existing bunker CTK identities
sc_auth identities

# Delete stale CTK identity by SHA-1 hash
sc_auth delete-ctk-identity -h <sha1_hash>

# Also clean login keychain
security find-certificate -c bunker-workload -a -Z ~/Library/Keychains/login.keychain-db
security delete-certificate -Z <sha1> ~/Library/Keychains/login.keychain-db
```

**Why both CTK and Keychain cleanup:**
- `sc_auth delete-ctk-identity` removes the CTK identity (Secure Enclave key reference)
- `security delete-certificate` removes the certificate from the login keychain
- Without both, orphaned SE keys or orphaned certs accumulate

### Step 2: Generate Secure Enclave Key Pair

**Command:**
```bash
sc_auth create-ctk-identity -l <cn> -N <cn> -k <algo> -t none
```

**Parameters:**

| Flag | Value | Purpose |
|---|---|---|
| `-l` | `bunker-workload-<epoch>` | Label for the identity |
| `-N` | `bunker-workload-<epoch>` | Common Name for the throwaway self-signed cert |
| `-k` | `p-256-ne` or `p-384-ne` | Algorithm (`-ne` = native enclave) |
| `-t` | `none` | Token type (none = use default SE token) |

**Platform behavior:**
- The Secure Enclave generates the key pair internally
- A throwaway self-signed certificate is created and bound to the key
- The private key is non-exportable — it never leaves the hardware
- This may trigger a macOS authorization prompt (Touch ID / password)

**Error `-25293` (`errSecAuthFailed`):**
This means either:
- Running in a VM without Secure Enclave pass-through
- User denied the authorization prompt
- Secure Enclave is not available on this hardware

### Step 3: Wait for CTK Registration

After `create-ctk-identity`, the CTK subsystem takes time to register
the new identity.  **You must poll `sc_auth identities`** until the new
identity appears.

```bash
# Poll up to 10 times, 1 second apart
sc_auth identities | grep <cn>
```

This delay is especially noticeable on ARM64 macOS CI runners.

### Step 4: Generate CSR

**Command:**
```bash
sc_auth create-ctk-csr -h <sha1_hash> -N <cn> -f <basename>
```

**Gotcha:** `sc_auth` automatically appends `.csr` to the filename argument.
If you pass `-f /tmp/workload`, the output file is `/tmp/workload.csr`.

**Platform behavior:**
- The CSR is signed by the Secure Enclave private key
- The CSR is output in PEM format
- The public key in the CSR matches the SE-generated key

### Step 5: Sign Certificate with Ephemeral CA

This step happens in Python (not macOS-specific):
1. Generate an ephemeral RSA CA key pair (in software)
2. Create a self-signed CA certificate
3. Sign the workload certificate using the CSR's public key
4. The ephemeral CA private key is discarded after signing

### Step 6: Import CA-Signed Certificate

**Command:**
```bash
sc_auth import-ctk-certificate -f <cert_path>
```

**Platform behavior:**
- Replaces the throwaway self-signed cert with the CA-signed workload cert
- The certificate is bound to the Secure Enclave private key
- The cert appears in "My Certificates" in Keychain Access


## Algorithm Support

The Secure Enclave only supports ECC curves.  **No RSA support.**

| Config Name | sc_auth Algorithm | Notes |
|---|---|---|
| `es256` | `p-256-ne` | Universally supported on SE hardware |
| `es384` | `p-384-ne` | Supported on Apple Silicon |
| `rsa2048` | ❌ | Not supported by Secure Enclave |
| `rsa4096` | ❌ | Not supported by Secure Enclave |


## Platform Quirks and Gotchas

### 1. macOS 15+ Requirement

`sc_auth create-ctk-identity` requires macOS 15 (Sequoia) or later.
On older versions, the command doesn't exist or doesn't support CTK
identity creation.

### 2. CSR Filename Appending

`sc_auth create-ctk-csr -f <basename>` silently appends `.csr` to the
output filename.  Pass the basename without extension and read
`<basename>.csr` afterward.

### 3. CTK Registration Delay

After `create-ctk-identity`, the identity may not appear in
`sc_auth identities` for several seconds.  Poll with a 1-second sleep,
up to 10 retries.

### 4. VM Limitations

Virtual machines without Secure Enclave pass-through will fail with
error `-25293` (`errSecAuthFailed`).  This is a hardware limitation —
the Secure Enclave must be physically present.

### 5. Authorization Prompts

Key generation may trigger macOS Touch ID or password prompts.
In non-interactive environments (CI/CD), this will hang or fail.

### 6. No Attestation

See [docs/attestation-macos.md](attestation-macos.md) — Apple does not
expose APIs for third-party key attestation from the Secure Enclave.
The key is hardware-bound but you cannot prove it to a remote verifier.
