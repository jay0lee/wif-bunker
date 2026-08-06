# YubiKey Keystore — Developer Guide

## Overview

YubiKey keys are generated on-device via the **PIV (Personal Identity
Verification)** smart card applet.  The private key is created inside the
YubiKey's secure element and **never leaves the hardware**.  All operations
use the `yubikit` Python library which communicates over PC/SC (CCID).


## Key Creation Flow

### Step 1: Device Discovery

**API:**
```python
from ykman.device import list_all_devices

devices = list_all_devices()
```

- Returns list of `(device, info)` tuples
- `info` contains: `serial`, `version` (major, minor, patch), `form_factor`
- If multiple YubiKeys connected, the user must specify `--yubikey-serial`

**Prerequisite:** On Linux, `pcscd` must be running:
```bash
sudo systemctl start pcscd
```

### Step 2: Security Initialization (First Use)

On first use, the YubiKey has factory-default credentials.  These MUST be
changed before generating keys.

**Factory defaults:**

| Credential | Default Value |
|---|---|
| PIN | `123456` |
| PUK | `12345678` |
| Management Key | `010203040506070801020304050607080102030405060708` (24-byte TDES) |

**Initialization sequence:**

```python
from yubikit.piv import PivSession, MANAGEMENT_KEY_TYPE, DEFAULT_MANAGEMENT_KEY

piv = PivSession(conn)

# 1. Authenticate with factory default management key
piv.authenticate(MANAGEMENT_KEY_TYPE.TDES, DEFAULT_MANAGEMENT_KEY)

# 2. Change PIN (max 8 characters)
new_pin = generate_random_pin(8)
piv.change_pin("123456", new_pin)

# 3. Change PUK (max 8 characters)
new_puk = generate_random_puk(8)
piv.change_puk("12345678", new_puk)

# 4. Set new management key (24 bytes, TDES)
new_mgm = os.urandom(24)
piv.set_management_key(MANAGEMENT_KEY_TYPE.TDES, new_mgm)

# 5. Re-authenticate with new management key
piv.authenticate(MANAGEMENT_KEY_TYPE.TDES, new_mgm)
```

**Credential storage:** Saved to a local JSON file with `chmod 0o600`:
- Linux/macOS: `~/.config/wif-bunker/yubikey_<serial>.json`
- Windows: `%LOCALAPPDATA%\wif-bunker\yubikey_<serial>.json`

### Step 3: Generate Key On-Device

**API:**
```python
from yubikit.piv import SLOT, KEY_TYPE, PIN_POLICY, TOUCH_POLICY

piv.authenticate(mgm_key)
piv.verify_pin(pin)

pub_key = piv.generate_key(
    slot=SLOT.AUTHENTICATION,  # 0x9A
    key_type=KEY_TYPE.ECCP256,  # Algorithm
    pin_policy=PIN_POLICY.ONCE,  # PIN required once per session
    touch_policy=TOUCH_POLICY.DEFAULT,  # No touch required
)
```

**Platform behavior:**
- The private key is generated inside the secure element
- Only the public key is returned
- The private key **cannot** be exported — ever
- The key replaces any existing key in the slot (no warning)

**Export the public key:**
```python
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

pub_pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
```

### Step 4: Sign and Import Certificate

After signing the workload certificate (with an ephemeral CA), import it
into the same PIV slot:

```python
from cryptography.x509 import load_pem_x509_certificate

cert = load_pem_x509_certificate(cert_pem_bytes)
piv.put_certificate(SLOT.AUTHENTICATION, cert)
```

**Platform behavior:**
- The certificate is stored in the PIV slot alongside the private key
- The cert's public key must match the generated private key
- `put_certificate` requires prior management key authentication


## PIV Slot Map

| Slot ID | Enum | Purpose | Typical Use |
|---|---|---|---|
| `0x9A` | `SLOT.AUTHENTICATION` | PIV Authentication | **Default for workload keys** |
| `0x9C` | `SLOT.SIGNATURE` | Digital Signature | Document signing |
| `0x9D` | `SLOT.KEY_MANAGEMENT` | Key Management | Key exchange/encryption |
| `0x9E` | `SLOT.CARD_AUTH` | Card Authentication | Physical access |
| `0xF9` | `SLOT.ATTESTATION` | Attestation | **Read-only, factory-set** |


## Algorithm Support by Firmware

| Algorithm | KEY_TYPE | Min Firmware | Notes |
|---|---|---|---|
| ECDSA P-256 | `ECCP256` | 4.3.0 | Universally supported |
| ECDSA P-384 | `ECCP384` | 4.3.0 | Widely supported |
| RSA 2048 | `RSA2048` | 4.3.0 | Universally supported |
| RSA 4096 | `RSA4096` | **5.7.0** | Requires YubiKey 5.7+ |


## PIN and Touch Policies

These are set at key generation time and **cannot be changed** without
regenerating the key.

### PIN Policies

| Policy | Value | Behavior |
|---|---|---|
| `PIN_POLICY.NEVER` | 1 | PIN never required |
| `PIN_POLICY.ONCE` | 2 | PIN required once per session (**default**) |
| `PIN_POLICY.ALWAYS` | 3 | PIN required for every operation |

### Touch Policies

| Policy | Value | Behavior |
|---|---|---|
| `TOUCH_POLICY.NEVER` | 1 | No touch required |
| `TOUCH_POLICY.ALWAYS` | 2 | Touch required for every operation |
| `TOUCH_POLICY.CACHED` | 3 | Touch required, cached for 15 seconds |




## Platform-Specific mTLS Signing

### Linux and macOS: PKCS#11 (Working)

On Linux and macOS, ECP's `tls_offload` library uses a **PKCS#11 module**
(`libykcs11.so` / `libykcs11.dylib`) to sign during the mTLS handshake.
The PIN is provided programmatically via the `user_pin` field in
`certificate_config.json`:

```json
{
  "cert_configs": {
    "pkcs11": {
      "module": "/usr/lib/x86_64-linux-gnu/libykcs11.so",
      "slot": "0x00",
      "label": "X.509 Certificate for PIV Authentication",
      "user_pin": "<pin_from_config>"
    }
  }
}
```

This works because:
1. The PKCS#11 API accepts the PIN inline via `C_Login()`
2. No OS-level UI is required
3. The signing happens entirely within the PKCS#11 module → YubiKey

### Windows: NCrypt / Smart Card KSP (Blocked)

On Windows, ECP's `tls_offload.dll` exclusively uses the **NCrypt** (CNG)
API for signing.  It does **not** use PKCS#11 on Windows, regardless of
what is specified in `certificate_config.json`.

The intended workflow for YubiKey on Windows is:

```
certificate_config.json
  → windows_store (issuer match)
    → tls_offload.dll
      → NCryptSignHash()
        → Smart Card KSP
          → YubiKey Smart Card Minidriver
            → YubiKey PIV applet
```

**This workflow does not work.**  The root cause is `NTE_SILENT_CONTEXT`
(`0x80090022`), a fundamental incompatibility between ECP and the
Windows Smart Card Key Storage Provider.

#### Why It Fails: NCRYPT_SILENT_FLAG

`tls_offload.dll` opens the NCrypt key handle with `NCRYPT_SILENT_FLAG`,
which tells the cryptographic provider that **no UI is allowed**.  This
is a reasonable design choice for a TLS handshake — blocking for a dialog
in the middle of a network operation is unacceptable.

However, the **Smart Card KSP always requires UI capability**, even when
no actual UI is needed (e.g., `PIN_POLICY.NEVER`).  When it detects
`NCRYPT_SILENT_FLAG`, it returns `NTE_SILENT_CONTEXT` without attempting
the operation.

The TPM KSP does **not** have this limitation — it supports fully silent
signing because TPM operations never require user interaction.

Debug output confirming the failure:
```
tls_offload.cpp: ConfigureSslContext is successful....
before calling key->Sign, sig len: 72
the key is ecdsa key
failed to sign hash: NCryptSignHash: failed to get signature: 0x80090022
```

Note that `ConfigureSslContext` succeeds (cert discovery works), but
`NCryptSignHash` fails at signing time.


## Windows YubiKey Investigation Log

The following approaches were systematically investigated and documented
for future reference.

### Approach 1: windows_store + PIN_POLICY.ONCE

**Hypothesis:** Use the Windows Certificate Store with `PIN_POLICY.ONCE`.
The YubiKey Smart Card Minidriver propagates PIV certificates into
`Cert:\CurrentUser\My`, making them visible to ECP's `windows_store`
config.

**What worked:**
- Key generation via `yubikit` (CCID) ✅
- Certificate import into PIV slot 9A ✅
- Writing CHUID/CCC objects (required for minidriver discovery) ✅
- Certificate visibility in Windows store after re-insertion ✅
- NCrypt key discovery (key appears as `ECDsaCng` with
  `Microsoft Smart Card Key Storage Provider`) ✅
- Interactive signing via PowerShell (entering PIN in dialog) ✅

**What failed:**
- `tls_offload.dll` signing → `NTE_SILENT_CONTEXT` (`0x80090022`)
- The Smart Card PIN dialog cannot be displayed because
  `tls_offload.dll` uses `NCRYPT_SILENT_FLAG`

### Approach 2: windows_store + PIN_POLICY.NEVER

**Hypothesis:** If no PIN is required, the Smart Card KSP might not
need to display UI, and `NCRYPT_SILENT_FLAG` might work.

**Result:** Same `0x80090022` error.  The Smart Card KSP returns
`NTE_SILENT_CONTEXT` regardless of PIN policy — it's a blanket
restriction on silent mode, not conditional on whether a PIN is
actually needed.

### Approach 3: NCrypt PIN Pre-Caching

**Hypothesis:** Open the NCrypt key handle before the mTLS handshake,
set the PIN via `NCryptSetProperty("SmartCardPin", pin)`, and the
PIN will be cached for subsequent operations.

**Implementation:**
```python
ncrypt.NCryptOpenStorageProvider(h_provider, "Microsoft Smart Card Key Storage Provider", 0)
ncrypt.NCryptOpenKey(h_provider, h_key, key_container_name, 0, 0)
ncrypt.NCryptSetProperty(h_key, "SmartCardPin", pin_bytes, len(pin_bytes), 0)
```

**Result:** `NCryptSetProperty` returned `0x80100011`
(`SCARD_E_READER_UNAVAILABLE`).  Even if this succeeded, NCrypt PIN
caching is **per-handle** — `tls_offload.dll` opens its own handle
internally, so a PIN set on our handle would not be visible to it.

### Approach 4: PKCS#11 on Windows

**Hypothesis:** Use the `pkcs11` config format in
`certificate_config.json` with `libykcs11.dll` on Windows, same as
Linux/macOS.

**Result:** ECP's `tls_offload.dll` on Windows does **not** use
PKCS#11 for signing.  The `pkcs11` config section is only used by
`libecp.dll` for certificate retrieval.  Signing always goes through
NCrypt regardless of config format.  Confirmed by debug output showing
`NCryptSignHash` calls even with PKCS#11 config.

### Approach 5: Windows Smart Card Minidriver Prerequisites

Before the signing investigation, significant work was needed just to
get the YubiKey certificate visible in the Windows Certificate Store.

**CHUID and CCC objects:**  The Windows Smart Card Minidriver requires
valid CHUID (Card Holder Unique Identifier) and CCC (Card Capability
Container) PIV data objects to recognize the card.  Without these,
the minidriver ignores the card entirely — no certificates appear in
the store.

```python
piv.put_object(OBJECT_ID.CHUID, chuid_bytes)
piv.put_object(OBJECT_ID.CAPABILITY, ccc_bytes)
```

CHUID must contain a valid GUID and expiry date.  CCC must contain a
valid Card Identifier.  New values must be written each time a key is
regenerated (changing the CHUID forces the minidriver to re-read the
card contents).

**Re-insertion requirement:**  After writing new PIV objects, the
YubiKey must be physically removed and re-inserted for the minidriver
to discover the new certificate.  `certutil -pulse` alone is not
sufficient — the minidriver needs a card insertion event.


## Summary: YubiKey mTLS by Platform

| Platform | Signing Method | PIN Handling | Status |
|---|---|---|---|
| **Linux** | PKCS#11 (`libykcs11.so`) | `user_pin` in config | ✅ Working |
| **macOS** | PKCS#11 (`libykcs11.dylib`) | `user_pin` in config | ✅ Working |
| **Windows** | NCrypt (Smart Card KSP) | Not automatable | ❌ Blocked by `NTE_SILENT_CONTEXT` |

### Possible Future Solutions for Windows

1. **Google ECP update:** If `tls_offload.dll` adds PKCS#11 support on
   Windows (or removes `NCRYPT_SILENT_FLAG` for smart card providers),
   YubiKey signing would work immediately.

2. **Custom TLS signer:** Bypass `tls_offload.dll` entirely and
   implement mTLS signing in Python using the `cryptography` library
   with direct PKCS#11 calls via `python-pkcs11` or `PyKCS11`.

3. **certreq-based key generation:** Generate the key through
   `certreq.exe` (Windows CNG) instead of `yubikit` (CCID).  Keys
   created through the CNG enrollment path may have different NCrypt
   properties that allow silent signing.  This is unverified.


## Platform Quirks and Gotchas

### 1. Linux Requires pcscd

The PC/SC Smart Card Daemon must be running:
```bash
sudo systemctl start pcscd
sudo systemctl enable pcscd
```

Without it, `list_all_devices()` returns an empty list.

### 2. PIN Length Limit

PIV PINs have a **maximum length of 8 characters**.  Longer PINs are silently
truncated by some firmware versions.

### 3. Slot Overwrites Without Warning

`piv.generate_key()` silently replaces any existing key in the slot.
There is no confirmation prompt or backup mechanism.  The old key is
permanently destroyed.

### 4. Management Key Authentication Scope

`piv.authenticate()` must be called before:
- `generate_key()`
- `put_certificate()`
- `change_pin()`, `change_puk()`, `set_management_key()`

The authentication is valid for the duration of the `PivSession`.

### 5. Imported vs Generated Keys

Keys that are **imported** (via `piv.put_key()`) cannot be attested.
Only keys created via `piv.generate_key()` produce valid attestation
certificates.  This is a fundamental YubiKey limitation.

### 6. PKCS#11 Label Mismatch

The CKA_LABEL for slot 9A differs between PKCS#11 providers:

| Provider | CKA_LABEL for slot 9A |
|---|---|
| OpenSC (`opensc-pkcs11.so`) | `Certificate for PIV Authentication` |
| Yubico (`libykcs11.so/dll`) | `X.509 Certificate for PIV Authentication` |

Both must be checked when locating the key.

