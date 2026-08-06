# TPM PKCS#11 Operations on Linux: Reference Guide

This document serves as a reference for developers performing PKCS#11 TPM key operations on Linux systems. It focuses on the architectural concepts, practical implementation details, required libraries, and prominently features common pitfalls and "dead ends" to avoid.

## 1. Architecture

The Linux TPM stack is layered, translating hardware operations into high-level PKCS#11 API calls.

*   **Hardware/Kernel**: The physical or emulated TPM hardware is exposed via the kernel at `/dev/tpmrm0` (TPM Resource Manager).
*   **TSS Layer**: The `tpm2-tss` library provides the TCG Software Stack (TSS) implementation.
*   **PKCS#11 Bridge**: `libtpm2_pkcs11.so` bridges the standard PKCS#11 API to the TSS layer.
*   **Concepts Mapping**:
    *   **Tokens** map to TPM **Primary Keys**.
    *   **Objects** map to TPM **Child Keys** derived from those primary keys.

## 2. How to Do Things

### PKCS#11 Library Discovery

`libtpm2_pkcs11.so` is the crucial shared library bridging the PKCS#11 standard and the TPM.
Discovery mechanisms include:
*   Environment Variable: `TPM2_PKCS11_MODULE`
*   `p11-kit` configuration.
*   Well-known paths which vary by distribution:
    *   **Debian/Ubuntu**: `/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so`
    *   **Fedora/RHEL**: `/usr/lib64/pkcs11/libtpm2_pkcs11.so`
    *   **Arch Linux**: `/usr/lib/pkcs11/libtpm2_pkcs11.so`

### Token Management

*   **Initialization**: Use `C_InitToken` to initialize a slot and create a token.
*   **Identification**: Tokens are identified by their string label.
*   **Storage**: The `TPM2_PKCS11_STORE` environment variable defines the directory for the SQLite database holding token metadata.

### Key Generation

Keys generated via this interface are created persistently (`CKA_TOKEN=True`).

*   **Elliptic Curve (EC)**: Use mechanism `CKM_EC_KEY_PAIR_GEN`. Provide `CKA_EC_PARAMS` containing the ASN.1 OID for the target curve.
*   **RSA**: Use mechanism `CKM_RSA_PKCS_KEY_PAIR_GEN`. Provide `CKA_MODULUS_BITS` (e.g., 2048).

### Public Key Extraction

Extracting public key material requires parsing PKCS#11 attributes.

*   **EC Keys** (`CKA_EC_POINT`): Returns a DER-encoded OCTET STRING that wraps the uncompressed point.
    *   *P-256*: Outer DER `04 41`, followed by `04` `<32 bytes X>` `<32 bytes Y>`.
    *   *P-384*: Outer DER `04 61`, followed by `04` `<48 bytes X>` `<48 bytes Y>`.
*   **RSA Keys**: Extract `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`.

### Certificate Import

To import a certificate and link it to a key pair:
*   Use `C_CreateObject` with class `CKO_CERTIFICATE` and type `CKC_X_509`.
*   Pass the DER-encoded certificate as `CKA_VALUE`.
*   **Crucial**: The `CKA_ID` of the certificate object must exactly match the `CKA_ID` of the associated key pair.

### Algorithm Probing

To determine what cryptographic algorithms the underlying TPM supports:
*   Call `C_GetMechanismList` on the initialized slot.
*   `CKM_ECDSA` indicates Elliptic Curve support.
*   `CKM_RSA_PKCS` indicates RSA support.

## 3. Python Libraries

### `python-pkcs11` (pip)

*   A pure Python wrapper for PKCS#11. Works with any compliant `.so` library.
*   Load the module: `pkcs11.lib('/path/to/libtpm2_pkcs11.so')`.
*   Ideal for session management, key generation, and reading attributes.

### `tpm2-pytss` (pip)

*   *Requires `libtss2-dev` system packages.*
*   Direct Python bindings for the TPM2 TSS (ESAPI/FAPI).
*   Operates at a lower level than PKCS#11, issuing raw TPM commands.
*   **Necessary for attestation operations**, such as `Certify` and credential activation.

## 4. Dead Ends — What Didn't Work

> [!WARNING]
> The following approaches were attempted but failed or proved unreliable. Avoid using these methods for programmatic interaction.

### `tpm2_ptool` Python Entry-Point Broken (Ubuntu 24.04+)
*   **Issue**: The Ubuntu/Debian package installs `tpm2_ptool` via `setuptools` `entry_points`. On newer distributions, version mismatches break this wrapper.
*   **Workaround**: Running `python3 -m tpm2_pkcs11.tpm2_ptool` circumvents the entry-point issue, but leads directly to the SQLite schema mismatch problem below.

### SQLite Schema Mismatch (`tpm2_ptool` vs `libtpm2_pkcs11.so`)
*   **Issue**: `tpm2_ptool` (Python) and `libtpm2_pkcs11.so` (C) have conflicting definitions of the SQLite database schema. If you use `tpm2_ptool` to create the store, the C library will fail to read it, throwing `CKR_OPERATION_NOT_INITIALIZED` or "no such table: schema".
*   **Solution**: **Never use `tpm2_ptool` for initialization.** Let the C library create the database automatically when it is first used.
*   **Best Practice**: Use `python-pkcs11` to call `C_InitToken`, which delegates the DB creation safely to the C library.

### `certtool` + PKCS#11 URIs (GnuTLS)
*   **Issue**: Attempting to generate self-signed certs using `certtool --generate-self-signed --load-privkey 'pkcs11:token=...;object=...;type=private;pin-value=...'` is extremely fragile. The URI syntax must be exact, and `GNUTLS_PIN` must be set to avoid interactive prompts.
*   **Solution**: Replaced this entirely by extracting the public key via PKCS#11 attributes directly in Python and generating the certificate programmatically.

### `pkcs11-tool` / `p11tool`
*   **Issue**: Commands like `pkcs11-tool --module /path/to/libtpm2_pkcs11.so -T` are useful for ad-hoc debugging but are poor choices for programmatic access. Parsing standard output is brittle.
*   **Solution**: Replaced by using `python-pkcs11` to perform slot and mechanism queries directly in code.

## 5. Permission Requirements

*   The user executing the application must have read/write access to `/dev/tpmrm0`.
*   Typically, this requires adding the user to the `tss` group: `sudo usermod -aG tss <username>`
*   When using a software TPM (e.g., `swtpm` on port 2321), set the environment variable: `TPM2TOOLS_TCTI=mssim:host=127.0.0.1,port=2321`.

## 6. Error Reference

| Error Code | Meaning | Resolution |
| :--- | :--- | :--- |
| `CKR_DEVICE_ERROR` | TPM is not responding. | Check permissions and availability of `/dev/tpmrm0`. |
| `CKR_PIN_INCORRECT` | The provided Token PIN is wrong. | Re-initialize the token with the correct PIN. |
| `CKR_TOKEN_NOT_RECOGNIZED` | SQLite store is corrupted. | Wipe the store directory (`~/.tpm2_pkcs11` or `$TPM2_PKCS11_STORE`). |
| `CKR_OPERATION_NOT_INITIALIZED` | SQLite schema mismatch. | DB was likely created by the wrong tool (e.g., `tpm2_ptool`). Wipe it and let the C library recreate it. |
| `TPM_RC_NV_SPACE` (`0x14b`) | TPM Non-Volatile storage is full. | Evict old persistent handles using `tpm2_evictcontrol`. |
