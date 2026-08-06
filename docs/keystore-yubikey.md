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
    slot=SLOT.AUTHENTICATION,      # 0x9A
    key_type=KEY_TYPE.ECCP256,     # Algorithm
    pin_policy=PIN_POLICY.ONCE,    # PIN required once per session
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


## PKCS#11 for mTLS

For mTLS signing via ECP (External Credential Provider), the PKCS#11 library
must be located:

### Library Search Order

1. `YKCS11_MODULE` environment variable
2. Platform-specific default paths:

| Platform | Libraries Checked |
|---|---|
| Linux | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`, `/usr/lib/x86_64-linux-gnu/libykcs11.so`, etc. |
| macOS | `/usr/local/lib/libykcs11.dylib`, Homebrew paths |
| Windows | `C:\Program Files\Yubico\*\libykcs11.dll` |

### PKCS#11 Label Mismatch

The CKA_LABEL for slot 9A differs between PKCS#11 providers:

| Provider | CKA_LABEL for slot 9A |
|---|---|
| OpenSC (`opensc-pkcs11.so`) | `Certificate for PIV Authentication` |
| Yubico (`libykcs11.so/dll`) | `X.509 Certificate for PIV Authentication` |

Both must be checked when locating the key.


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
