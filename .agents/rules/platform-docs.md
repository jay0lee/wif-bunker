# Platform & Hardware Reference Docs

The `docs/` directory contains wiki articles that document the technical details of working with specific platforms and hardware (TPM, YubiKey, macOS Secure Enclave, Windows CNG, etc.).

## When to Reference

- **Before** implementing or debugging any platform-specific code (attestation, key generation, credential activation, certificate handling), read the relevant `docs/` article.
- **Before** guessing at API signatures, type constructors, or protocol flows for TPM, PKCS#11, CNG, or similar hardware interfaces, check the docs first.
- These docs capture hard-won knowledge from real hardware testing — don't re-discover what's already documented.

## What the Docs Contain

- Technical steps to perform operations (e.g., TPM credential activation flow, EK certificate retrieval methods, policy session setup)
- Platform-specific API details, gotchas, and dead ends
- Comparisons between CLI and library approaches
- Error references and fixes

## What the Docs Do NOT Contain

- WIF Bunker or hardmTLS-specific implementation details (code structure, function names, module layout)
- These implementation details change frequently and belong in the code itself

## Updating the Docs

When new platform/hardware knowledge is gained through debugging or testing (e.g., Intel PTT NV restrictions, tpm2-pytss API quirks), update the relevant `docs/` article with the findings so future work benefits.
