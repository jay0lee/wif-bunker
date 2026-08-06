# Attestation Architecture — Cross-Platform Overview

## What Is Attestation?

Attestation cryptographically proves that a workload private key:
1. Was **generated inside** a hardware security device (TPM or YubiKey)
2. Is **permanently bound** to that device (non-exportable)
3. The device is **genuine hardware** (not emulated)

## Platform Matrix

| Platform | Hardware | Attestation Method | Trust Root |
|---|---|---|---|
| **Windows** | TPM 2.0 | PCP Properties via `NCryptGetProperty` | TPM EK Certificate → Manufacturer Root CA |
| **Linux** | TPM 2.0 | `tpm2_certify` via tpm2-tools | TPM EK Certificate → Manufacturer Root CA |
| **macOS** | Secure Enclave | ❌ **Not possible** — [see why](attestation-macos.md) | N/A |
| **Any** | YubiKey | `piv.attest_key()` via yubikit | F9 Cert → Yubico Root CA |


## Common Trust Chain

All platforms follow the same trust model:

```
┌──────────────────────┐
│  Manufacturer Root   │  (bundled in wif-bunker)
│  CA Certificate      │  - TPM: tpm-ca-certificates
│                      │  - YubiKey: Yubico PIV Root CA
├──────────────────────┤
│  Device Identity     │  (provisioned at factory)
│  Certificate         │  - TPM: Endorsement Key (EK) cert
│                      │  - YubiKey: F9 Attestation cert
├──────────────────────┤
│  Key Residency       │  (generated at attestation time)
│  Proof               │  - TPM: PCP props / tpm2_certify
│                      │  - YubiKey: attest_key() cert
├──────────────────────┤
│  Workload Key        │  (the key we're proving is safe)
│                      │
└──────────────────────┘
```


## Shared Code (base.py)

### Data Model

```python
@dataclass
class AttestationArtifact:
    filename: str           # e.g., "ek_certificate.pem"
    content: str | bytes    # PEM text or binary blob
    description: str        # Human-readable explanation
    is_binary: bool = False # True for binary artifacts

@dataclass
class AttestationCheck:
    name: str               # e.g., "TPM status"
    passed: bool            # True if check succeeded
    detail: str             # Detailed explanation

@dataclass
class AttestationReport:
    platform: str           # "windows-cng", "linux-tpm2", "yubikey"
    supported: bool         # Can this platform do attestation?
    hardware_type: str      # "CNG/TPM", "TPM2", "YubiKey"
    artifacts: list         # Files to write to disk
    checks: list            # Individual check results
    summary: str            # Overall verdict message
    # Optional enrichment:
    platform_info: dict     # OEM platform certificate details
    ek_details: dict        # Parsed EK certificate details
    tpm_info: dict          # TPM/device info dictionary
    workload_cn: str        # Workload certificate CN
```

### Shared Functions

| Function | Used By | Purpose |
|---|---|---|
| `verify_ek_chain()` | Windows, Linux | pyOpenSSL chain verification + AIA chasing |
| `parse_ek_details()` | Windows, Linux | Two-tier EK cert parsing |
| `_parse_tcg_attributes()` | Windows, Linux | TCG OID extraction from EK cert SAN |
| `_decode_manufacturer_id()` | Windows, Linux | 32-bit vendor ID → human name |


## EK Certificate Chain Verification

### Why pyOpenSSL (Not cryptography library)

Real-world TPM EK certificates have non-standard ASN.1 encoding:
- Intel: `InvalidSetOrdering` in issuer/subject RDN sequences
- Nuvoton: Explicit `critical=FALSE` where DER requires omission

The `cryptography` library's Rust parser is strict and rejects these.
pyOpenSSL uses C OpenSSL which tolerates the encoding quirks.

**Reference:** pyca/cryptography#7189

### AIA Chasing

When verification fails with "unable to get local issuer certificate":
1. Parse AIA extension from the failing certificate
2. Fetch intermediate CA cert via HTTP from the AIA URL
3. Add to intermediates and retry (up to 3 levels)

This handles manufacturers who don't include their intermediate CAs in
the `tpm-ca-certificates` bundle.

### Root CA Bundle

The bundle is sourced from https://github.com/loicsikidi/tpm-ca-certificates
and includes roots for: Intel, AMD, Infineon, Nuvoton, STMicroelectronics,
Broadcom, Atmel, Winbond, NationZ, Qualcomm, Samsung, and more.

There is also a `manually-managed/` directory for roots not yet in the
upstream bundle (we filed a PR for Intel).


## File Organization

```
wif_bunker/attestation/
├── __init__.py          # Platform dispatcher
├── base.py              # Shared dataclasses, EK chain verification
├── windows.py           # Windows CNG/PCP attestation (ctypes to ncrypt.dll)
├── linux.py             # Linux tpm2-tools attestation
├── yubikey.py           # YubiKey PIV attestation
└── roots/               # Bundled root CA certificates
    ├── roots/           # TPM manufacturer root CAs
    ├── intermediates/   # TPM manufacturer intermediate CAs
    ├── manually-managed/# Manually added CAs (e.g., Intel)
    └── yubico/          # Yubico PIV Root CA + intermediates
```


## Testing

### Unit Tests

```bash
pytest tests/test_windows_attestation.py  # Windows-specific (mocked ncrypt)
pytest tests/test_yubikey.py              # YubiKey-specific (mocked yubikit)
pytest tests/                             # All tests
```

### Real Hardware Testing

| Hardware | Command |
|---|---|
| Windows TPM | `python3 -m wif_bunker --cert-only --output-dir test1 && python3 -m wif_bunker --attest --cert-file test1/workload_cert.pem` |
| Linux TPM | Same commands (uses tpm2-tools automatically) |
| YubiKey | `python3 -m wif_bunker --cert-only --yubikey && python3 -m wif_bunker --attest --cert-file <cert>` |

### CI with Software TPM

Uses `swtpm` (software TPM simulator).  EK chain verification will fail
(swtpm uses self-signed certs), but key certification should succeed.


## Debugging Checklist

### Windows TPM Not Working?

1. Is the TPM present? → `Get-Tpm` in PowerShell
2. Is the key in PCP? → Check `certutil -store -user My` output
3. Are PCP properties available? → Run with `-v` logging, check for
   "PCP property ... not available" messages
4. Are ctypes argtypes declared? → Check `NCryptGetProperty.argtypes`
5. See [Windows TPM Guide](attestation-windows-tpm.md) for dead ends

### Linux TPM Not Working?

1. Is `/dev/tpmrm0` accessible? → Check group membership (`tss` group)
2. Are tpm2-tools installed? → `which tpm2_getcap`
3. Is the EK cert present? → `tpm2_nvread 0x01C00002`
4. Check tpm2-tools version compatibility (some flags differ between versions)

### YubiKey Not Working?

1. Is the YubiKey connected? → `ykman list`
2. Is firmware ≥ 4.3.0? → `ykman info`
3. Was the key **generated** (not imported)? → `attest_key()` will fail for imported keys
4. Is the right slot being used? → Default is `9a` (AUTHENTICATION)
