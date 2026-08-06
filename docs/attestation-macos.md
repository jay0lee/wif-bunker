# macOS Attestation — Developer Guide

## Overview

**Attestation is not possible on macOS.**  Apple's Secure Enclave does not
expose the APIs needed for third-party key attestation.

## Why Attestation Cannot Work on macOS

### No TPM

Macs do not have a TPM (Trusted Platform Module).  The Secure Enclave
Processor (SEP) serves a similar purpose but has a fundamentally different
architecture and API surface.

### Secure Enclave Limitations

Apple's Secure Enclave:
- **No Endorsement Key (EK) equivalent** — There is no manufacturer-signed
  certificate proving the Secure Enclave is genuine Apple hardware
- **No attestation API** — There is no equivalent of `tpm2_certify`,
  `NCryptGetProperty(PCP_TPM2BNAME)`, or `piv.attest_key()`
- **No public key extraction for attestation** — The SEP does not allow
  reading its root-of-trust public key to build a verification chain

### Apple's App Attest (Not Applicable)

Apple does provide [App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
via the DeviceCheck framework, but it:
- Only works for **iOS/iPadOS/macOS apps distributed via the App Store**
- Proves the *app binary* is genuine, not that a *key* is hardware-bound
- Requires an Apple Developer account and App Store distribution
- Is not usable from Python or command-line tools
- Is not designed for enterprise workload identity

### Apple's Managed Device Attestation (Not Applicable)

Apple also provides [Managed Device Attestation](https://support.apple.com/guide/deployment/managed-device-attestation-dep28afbde6a/web)
for MDM-enrolled devices, but it:
- Requires device enrollment in an MDM solution
- Is an MDM-to-Apple-server protocol, not a local API
- Cannot be invoked by third-party applications
- Proves device identity to the MDM server, not key residency

### References

- Apple Secure Enclave overview:
  https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web
- Apple App Attest:
  https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity
- Apple Managed Device Attestation:
  https://support.apple.com/guide/deployment/managed-device-attestation-dep28afbde6a/web


## What macOS CAN Do

While attestation is impossible, macOS **can** generate hardware-bound keys
in the Secure Enclave:

- Keys are generated via the Security framework (`SecKeyCreateRandomKey`)
- Keys are non-exportable — they never leave the Secure Enclave
- Keys can sign data via `SecKeyCreateSignature`
- But there is **no way to prove** to a third party that the key is in
  the Secure Enclave rather than in software

This means macOS workload keys are "trust me, it's hardware-backed" rather
than "here's cryptographic proof it's hardware-backed."


## Current Implementation Status

There is **no macOS attestation module**.  The attestation dispatcher
(`wif_bunker/attestation/__init__.py`) does not have a macOS path.
If `--attest` is invoked on macOS, it should report that attestation
is not supported on this platform.
