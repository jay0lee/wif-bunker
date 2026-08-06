# Linux TPM Keystore — Developer Guide

## Overview

On Linux, workload keys are stored in the TPM via the **tpm2-pkcs11** PKCS#11
middleware.  The `python-pkcs11` library (pip-installed) talks directly to
`libtpm2_pkcs11.so` via the standard PKCS#11 C API.  No CLI tools (tpm2_ptool,
certtool, etc.) are used — all operations happen through library calls.


## Architecture

```
wif-bunker (Python)
    └── python-pkcs11 (pip)
            └── libtpm2_pkcs11.so (system)
                    └── TPM 2.0 hardware
```

**System requirement:** `libtpm2_pkcs11.so` must be installed.  This is the
PKCS#11 shared library that bridges PKCS#11 operations to the TPM hardware.

**Discovery order** for the `.so` path:
1. `TPM2_PKCS11_MODULE` environment variable (user override)
2. `p11-kit list-modules` output (desktop Linux standard)
3. Well-known paths: Debian/Ubuntu, Fedora/RHEL, Arch Linux


## Key Creation Flow

### Step 1: Check Hardware Capability

The TPM's supported algorithms are queried via PKCS#11 slot mechanisms:

```python
import pkcs11

lib = pkcs11.lib("/path/to/libtpm2_pkcs11.so")
slot = lib.get_slots()[0]
mechs = slot.get_mechanisms()
# Mechanism.ECDSA → es256/es384
# Mechanism.RSA_PKCS → rsa2048/rsa3072/rsa4096
```

**Gotcha:** Many firmware TPMs (Intel PTT, AMD fTPM) only support P-256.
P-384 and RSA-4096 may be rejected.

### Step 2: Environment Setup

```bash
export TPM2_PKCS11_STORE=~/.tpm2_pkcs11
```

**This is mandatory.** Without it, operations fall back to `/etc/tpm2_pkcs11`
which requires root.

### Step 3: Cleanup Old Objects (SAFE)

The code only destroys objects in our token (`bunker-wif`), never
wipes the store or evicts unknown persistent handles.

```python
token = lib.get_token(token_label="bunker-wif")
with token.open(user_pin=pin, rw=True) as session:
    for obj in session.get_objects():
        obj.destroy()
```

> **⚠️ CRITICAL: TPM Citizenship**
>
> In production, other applications (disk encryption, Secure Boot, VPN keys)
> may have their own tokens and persistent handles.  **Never** wipe the store
> directory or evict handles you don't own.  Only destroy objects with our label.

### Step 4: Token Init and Key Generation

```python
# Find or create our token
token = lib.get_token(token_label="bunker-wif")
# or: slot.init_token(pin, "bunker-wif")

with token.open(user_pin=pin, rw=True) as session:
    # Generate key pair — stays in TPM, never exportable
    pub, priv = session.generate_keypair(
        KeyType.EC,
        mechanism=Mechanism.EC_KEY_PAIR_GEN,
        store=True,
        label=workload_cn,
        attrs={Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
    )
```

### Step 5: Extract Public Key and Sign Certificate

The public key is extracted via PKCS#11 attributes, then used with
`cryptography` to create a CA-signed workload certificate:

```python
# Extract EC point from PKCS#11
ec_point = pub[Attribute.EC_POINT]
# Convert to cryptography public key
crypto_pub = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), raw_point)
# Serialize as PEM and pass to _create_ca_and_sign()
pub_pem = crypto_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
```

### Step 6: Import Signed Certificate

```python
# Convert PEM → DER
workload_der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)

session.create_object(
    {
        Attribute.CLASS: ObjectClass.CERTIFICATE,
        Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
        Attribute.LABEL: workload_cn,
        Attribute.VALUE: workload_der,
        Attribute.TOKEN: True,
        Attribute.ID: pub[Attribute.ID],  # Links cert to key
    }
)
```


## Algorithm Mapping

| Config Name | PKCS#11 Key Type | PKCS#11 Mechanism | Notes |
|---|---|---|---|
| `es256` | EC (secp256r1) | `CKM_ECDSA` | Most widely supported |
| `es384` | EC (secp384r1) | `CKM_ECDSA` | Some firmware TPMs reject |
| `rsa2048` | RSA 2048-bit | `CKM_RSA_PKCS` | Universally supported |
| `rsa3072` | RSA 3072-bit | `CKM_RSA_PKCS` | Most TPMs support |
| `rsa4096` | RSA 4096-bit | `CKM_RSA_PKCS` | Many TPMs reject |


## Platform Quirks and Gotchas

### 1. Permission Requirements

The user must have R/W access to `/dev/tpmrm0`:
```bash
sudo usermod -aG tss <username>
# Log out and back in
```

### 2. TCTI Configuration

If the Resource Manager isn't at the default path, set:
```bash
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
# or for swtpm:
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
```

### 3. PKCS#11 Library Path Override

If `libtpm2_pkcs11.so` is in a non-standard location:
```bash
export TPM2_PKCS11_MODULE=/path/to/libtpm2_pkcs11.so
```

### 4. EC Point DER Encoding

`libtpm2_pkcs11.so` returns `EC_POINT` as a DER-encoded `OCTET STRING`
wrapping the uncompressed point.  The outer DER wrapper (2 bytes) must be
stripped before passing to `cryptography`:
```
DER: 04 41 04 <32 bytes x> <32 bytes y>   (P-256)
DER: 04 61 04 <48 bytes x> <48 bytes y>   (P-384)
```


## Error Reference

| Error | Meaning | Fix |
|---|---|---|
| `CKR_DEVICE_ERROR` | TPM not responding | Check `/dev/tpmrm0`, set `TPM2TOOLS_TCTI` |
| `CKR_PIN_INCORRECT` | Token PIN mismatch | `rm -rf ~/.tpm2_pkcs11 && wif-bunker --cert-only` |
| `CKR_TOKEN_NOT_RECOGNIZED` | Store corruption | `rm -rf ~/.tpm2_pkcs11 && wif-bunker --cert-only` |
| `No available PKCS#11 slot` | All slots occupied | Check store integrity |
| `Could not find libtpm2_pkcs11.so` | Library not installed | Install `libtpm2-pkcs11-1` or set `TPM2_PKCS11_MODULE` |
