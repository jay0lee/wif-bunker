# hardmTLS — Hardware-Backed mTLS Signing Library

## Problem Statement

Google's ECP (Enterprise Certificate Proxy) is a closed-source Go binary
suite that handles mTLS signing for ADC. It's broken or fragile on every
platform, requires distributing 3 separate binaries, and its Go runtime
causes PKCS#11 session conflicts. WIF Bunker is **blocked** on ECP.

**Decision:** Full replacement. No ECP fallback. No fork. No Python interim.
Ship a single Rust shared library that replaces everything.

## Design Goal

> [!IMPORTANT]
> hardmTLS should **simplify** how WIF Bunker configures ADC, not just
> match ECP's complexity. Today, WIF Bunker must locate 3 ECP binaries,
> generate a `certificate_config.json` with platform-specific `cert_configs`
> AND `libs` paths, handle subprocess isolation for Go runtime PKCS#11
> conflicts, and work around `NCRYPT_SILENT_FLAG`. hardmTLS eliminates
> all of this.

---

## Architecture

```
BEFORE (ECP — 3 closed-source Go/C++ binaries per platform):

  google-auth ──→ libecp.{dll,so,dylib}     ──→ GetCertPemForPython()
              ──→ tls_offload.{dll,so,dylib} ──→ ConfigureSslContext()
                    ├─ Windows: NCrypt + NCRYPT_SILENT_FLAG (breaks Smart Card KSP)
                    ├─ Linux:   PKCS#11 via Go runtime (session conflicts)
                    └─ macOS:   Keychain (fragile, undocumented)

AFTER (hardmTLS — 1 open-source Rust library):

  google-auth ──→ hardmtls.{dll,so,dylib}
                    ├─ pkcs11.rs:      Linux TPM, YubiKey on all platforms
                    ├─ win_ncrypt.rs:  Windows TPM
                    └─ mac_se.rs:      macOS Secure Enclave + Keychain
```

Both `libs.ecp_client` and `libs.tls_offload` in `certificate_config.json`
point to the same `hardmtls` binary. Downstream apps (`gcloud`, `terraform`,
any Google SDK) load it transparently via google-auth. Zero changes required
in downstream consumers.

---

## Signing Backends

### `pkcs11.rs` — Cross-Platform PKCS#11

Unlike ECP, which only uses PKCS#11 on Linux, hardmTLS uses PKCS#11
**wherever a PKCS#11 module exists**:

| Platform | Keystore | PKCS#11 Module |
|---|---|---|
| Linux | TPM | `libtpm2_pkcs11.so` |
| Linux | YubiKey | `libykcs11.so` / `opensc-pkcs11.so` |
| Windows | YubiKey | `libykcs11.dll` (bypasses NCrypt entirely) |
| macOS | YubiKey | `libykcs11.dylib` |

PKCS#11 signing is the **primary backend**. It covers 4 of 6
platform+keystore combinations and is the fix for the Windows YubiKey
blocker (`libykcs11.dll` talks directly to YubiKey via PC/SC, completely
bypassing NCrypt/CNG and the Smart Card KSP).

### `win_ncrypt.rs` — Windows TPM Only

NCrypt/CNG via the TPM Key Storage Provider. This is the one path where
ECP already works — hardmTLS replicates it without `NCRYPT_SILENT_FLAG`
for Smart Card providers (future-proofing).

| Platform | Keystore | NCrypt Provider |
|---|---|---|
| Windows | TPM | Microsoft Platform Crypto Provider |

### `mac_se.rs` — macOS Secure Enclave + Keychain

Apple's Security.framework for hardware-backed keys on MacBooks.
PKCS#11 cannot access SE or Keychain keys — this backend is required.

| Platform | Keystore | API |
|---|---|---|
| macOS | Secure Enclave | `SecKeyCreateSignature()` (P-256 only) |
| macOS | Keychain | `SecItemCopyMatching()` + `SecKeyCreateSignature()` |

---

## Full Coverage Matrix

| Platform | Keystore | Backend | All P0 |
|---|---|---|---|
| Linux | TPM | `pkcs11.rs` | ✅ |
| Linux | YubiKey | `pkcs11.rs` | ✅ |
| Windows | TPM | `win_ncrypt.rs` | ✅ |
| Windows | YubiKey | `pkcs11.rs` | ✅ |
| macOS | YubiKey | `pkcs11.rs` | ✅ |
| macOS | SE/Keychain | `mac_se.rs` | ✅ |

---

## C API (Drop-in Compatible with google-auth)

hardmTLS exports the exact functions that `google-auth`'s
`_custom_tls_signer.py` expects. One binary serves as both
`libecp` and `tls_offload`.

```c
// === tls_offload interface ===

// Wire signing into the TLS handshake.
// sign_func: callback created by google-auth (wraps SignForPython)
// cert:      PEM-encoded client certificate
// ctx:       raw OpenSSL SSL_CTX* from Python's ssl module
int ConfigureSslContext(
    int (*sign_func)(unsigned char *sig, size_t *sig_len,
                     const unsigned char *tbs, size_t tbs_len),
    const char *cert,
    void *ctx  /* SSL_CTX* */
);

// === libecp interface ===

// Retrieve client certificate PEM.
// Call with cert_holder=NULL to get required buffer size.
int GetCertPemForPython(
    const char *config_path,
    char *cert_holder,
    int cert_holder_len
);

// Sign data using the hardware-backed private key.
int SignForPython(
    const char *config_path,
    const unsigned char *input, int input_len,
    unsigned char *output, int output_len
);
```

### Internal dispatch:

```
ConfigureSslContext() / SignForPython()
  → parse certificate_config.json
  → select backend:
      "pkcs11" in cert_configs       → pkcs11.rs
      "windows_store" in cert_configs → win_ncrypt.rs
      "macos_keychain" in cert_configs → mac_se.rs
  → sign / configure accordingly
```

---

## OpenSSL Linking (Not BoringSSL)

> [!IMPORTANT]
> hardmTLS **must dynamically link against OpenSSL**, not BoringSSL.

The `SSL_CTX*` pointer passed to `ConfigureSslContext` comes from
Python's `ssl` module, which links against OpenSSL. Calling BoringSSL
functions on an OpenSSL `SSL_CTX*` would segfault — the struct layouts
are incompatible.

Our OpenSSL usage is minimal and targets stable public API:

| Function | Purpose | Stability |
|---|---|---|
| `SSL_CTX_use_certificate_chain()` | Load client cert into context | Stable since 1.0 |
| `EVP_PKEY` + custom `EVP_PKEY_METHOD` | Proxy signing to our backends | Stable in 1.1.x, 3.x has provider alternative |
| `SSL_CTX_use_PrivateKey()` | Attach custom key to context | Stable since 1.0 |

Rust crate: `openssl-sys` (raw FFI bindings, dynamically links against
system OpenSSL — the same one Python uses, avoiding version mismatch).

---

## How hardmTLS Simplifies WIF Bunker

### What goes away:

| Current ECP complexity | With hardmTLS |
|---|---|
| `get_ecp.py` — download 3 binaries per platform | Bundle 1 library |
| `_find_ecp_binaries()` — search multiple directories | Single known path |
| `_add_ecp_to_path()` — PATH manipulation for DLL loading | Not needed |
| `ecp_get_cert_pem()` — ctypes call to Go library | Direct PEM read from disk, or ctypes to Rust |
| `_ecp_get_cert_subprocess()` — subprocess isolation for Go PKCS#11 | Not needed (no Go runtime) |
| `_find_system_python()` — find Python for subprocess hack | Not needed |
| `precache_yubikey_pin_ncrypt()` — NCrypt PIN pre-caching attempt | Not needed (PKCS#11 handles PIN) |
| Platform-specific `cert_configs` branching (windows_store vs pkcs11 vs macos_keychain) | Still needed, but dispatch moves into hardmTLS |

### Simplified `certificate_config.json`:

```json
{
  "version": 1,
  "cert_configs": {
    "pkcs11": {
      "module": "/usr/lib/libykcs11.so",
      "slot": "0",
      "label": "X.509 Certificate for PIV Authentication",
      "user_pin": "pin_from_config"
    }
  },
  "libs": {
    "ecp_client": "/path/to/hardmtls.so",
    "tls_offload": "/path/to/hardmtls.so"
  }
}
```

### Simplified `cert.py`:

```python
def build_certificate_config(config, cert_bundle):
    """Build certificate_config.json — simplified with hardmTLS."""
    # Platform-specific cert_configs (same as before, but now
    # pkcs11 is used on ALL platforms for YubiKey)
    cert_configs = _build_cert_configs(config, cert_bundle)

    # Single library path — no more hunting for 3 binaries
    hardmtls_lib = _find_hardmtls_lib()

    return {
        "version": 1,
        "cert_configs": {**cert_configs, "workload": {"cert_path": str(cert_path)}},
        "libs": {
            "ecp_client": str(hardmtls_lib),
            "tls_offload": str(hardmtls_lib),
        },
    }
```

---

## Project Structure

```
hardmtls-native/
├── Cargo.toml
├── src/
│   ├── lib.rs              # C API exports (ConfigureSslContext, Get/SignForPython)
│   ├── config.rs           # certificate_config.json parser
│   ├── dispatch.rs         # Backend selection from cert_configs
│   ├── ssl_ctx.rs          # OpenSSL SSL_CTX manipulation (cert + custom key)
│   ├── backends/
│   │   ├── mod.rs          # Backend trait
│   │   ├── pkcs11.rs       # PKCS#11 signing (all platforms)
│   │   ├── win_ncrypt.rs   # Windows NCrypt/CNG (Windows TPM)
│   │   └── mac_se.rs       # macOS Security.framework (SE + Keychain)
│   └── error.rs
├── tests/
│   ├── test_pkcs11.rs
│   ├── test_config.rs
│   └── integration/
├── build/
│   ├── ci-linux.sh
│   ├── ci-macos.sh
│   └── ci-windows.ps1
└── README.md
```

---

## Changes to WIF Bunker

#### [MODIFY] `wif_bunker/cert.py`

- Replace `_find_ecp_binaries()` with `_find_hardmtls_lib()` (find 1 binary)
- Remove `_add_ecp_to_path()`, `ecp_get_cert_pem()`,
  `_ecp_get_cert_inprocess()`, `_ecp_get_cert_subprocess()`,
  `_find_system_python()`
- `build_certificate_config()`: both `libs` entries point to hardmTLS
- YubiKey on Windows now uses `pkcs11` config (not `windows_store`)

#### [MODIFY] `wif_bunker/cli.py`

- Step 6: find hardmTLS library (1 file, not 3)
- Step 7a: cert verification reads PEM from disk (no ECP ctypes call)
- Step 7: ADC verification unchanged — google-auth loads hardmTLS
  via `configure_mtls_offload_channel` as before
- Remove `precache_yubikey_pin_ncrypt` call

#### [MODIFY] `wif_bunker/modes.py`

- Remove ECP cert retrieval stage (stage 3)
- ADC test stage: unchanged (google-auth handles it)

#### [DELETE] `get_ecp.py`

Replaced by hardmTLS binary distribution.

---

## Level of Effort

### Phase 1: Core Library (all backends)
**LoE: 14-21 days** | Priority: **P0**

| Task | Est |
|---|---|
| Rust project scaffold, CI matrix (Linux/macOS/Windows) | 1-2 days |
| `config.rs` — `certificate_config.json` parser | 0.5 day |
| `dispatch.rs` — backend selection from cert_configs | 0.5 day |
| `ssl_ctx.rs` — `ConfigureSslContext` (OpenSSL `SSL_CTX` + custom `EVP_PKEY`) | 2-3 days |
| `lib.rs` — C API exports (`ConfigureSslContext`, `GetCertPemForPython`, `SignForPython`) | 1 day |
| `backends/pkcs11.rs` — PKCS#11 signing (cross-platform) | 2-3 days |
| `backends/win_ncrypt.rs` — Windows NCrypt/CNG (TPM KSP) | 1-2 days |
| `backends/mac_se.rs` — macOS Security.framework (SE + Keychain) | 2-3 days |
| Cross-platform builds (.dll, .so, .dylib) | 1-2 days |
| Integration tests (hardmTLS ↔ google-auth ↔ real keystores) | 2-3 days |

### Phase 2: WIF Bunker Integration + Cleanup
**LoE: 3-5 days** | Priority: **P0**

| Task | Est |
|---|---|
| Update `cert.py` — simplify config generation, remove ECP code | 1 day |
| Update `cli.py` — remove ECP discovery, simplify step 6/7/7a | 0.5 day |
| Update `modes.py` — remove ECP cert retrieval | 0.5 day |
| Delete `get_ecp.py` | 0.5 day |
| Binary distribution (bundle with wif-bunker, update PyInstaller spec) | 0.5-1 day |
| Update docs, wiki, error messages | 0.5-1 day |
| End-to-end testing: all 6 platform+keystore combos | 1-2 days |

### Phase 3: Downstream Validation
**LoE: 1-2 days** | Priority: **P1**

| Task | Est |
|---|---|
| Test `gcloud projects list` with hardmTLS on all platforms | 0.5 day |
| Test `terraform plan` with hardmTLS | 0.5 day |
| Document any downstream quirks | 0.5 day |

### Ongoing Maintenance
**~0.5 day/month**

| Task | Frequency |
|---|---|
| Cross-platform CI builds | Per release |
| PKCS#11 module compat (new TPM/YubiKey drivers) | As needed |
| OpenSSL API compat | Yearly |
| Apple Security.framework changes | Yearly (WWDC) |

---

## Total LoE

| Phase | Effort | Priority |
|---|---|---|
| Phase 1: Core Rust library | 14-21 days | P0 |
| Phase 2: WIF Bunker integration | 3-5 days | P0 |
| Phase 3: Downstream validation | 1-2 days | P1 |
| **Total** | **18-28 days** | |

---

## Risks

> [!WARNING]
> **OpenSSL version compatibility.** We dynamically link against the
> system OpenSSL via `openssl-sys`. Must test against OpenSSL 1.1.x
> (older Linux distros), 3.0.x, 3.1.x, 3.2.x. The `EVP_PKEY` custom
> key method may differ between 1.1.x (ENGINE-based) and 3.x
> (provider-based). Mitigation: runtime version detection.

> [!WARNING]
> **google-auth internal API.** `_custom_tls_signer.py` is underscore-
> prefixed. The `ConfigureSslContext(SignFunc, char*, void*)` C API
> has been stable since 2022 and serves enterprise ECP customers.
> Breaking changes unlikely but possible. Mitigation: CI test against
> latest google-auth.

> [!CAUTION]
> **Code signing.** macOS `.dylib` requires notarization for Gatekeeper.
> Windows `.dll` needs Authenticode signing. Both add build complexity.

> [!NOTE]
> **Secure Enclave P-256 limitation.** macOS SE only supports P-256
> (NIST) keys. This is fine for our default `es256` algorithm but
> means `es384`/RSA are not available on macOS SE. Keychain supports
> all algorithms.

## Verification Plan

### Automated Tests

```bash
# Rust unit + integration tests
cargo test
cargo test --target x86_64-pc-windows-msvc    # Windows cross-compile
cargo test --target aarch64-apple-darwin       # macOS ARM

# Python integration
pytest tests/test_hardmtls_integration.py
```

### Manual Verification Matrix

| Platform | Keystore | Backend | WIF Bunker | Downstream |
|---|---|---|---|---|
| Linux | TPM | `pkcs11.rs` | `python3 -m wif_bunker` | `gcloud projects list` |
| Linux | YubiKey | `pkcs11.rs` | `--use-yubikey` | `gcloud projects list` |
| Windows | TPM | `win_ncrypt.rs` | `python3 -m wif_bunker` | `gcloud projects list` |
| Windows | YubiKey | `pkcs11.rs` | `--use-yubikey` | `gcloud projects list` |
| macOS | YubiKey | `pkcs11.rs` | `--use-yubikey` | `gcloud projects list` |
| macOS | SE | `mac_se.rs` | `python3 -m wif_bunker` | `gcloud projects list` |
