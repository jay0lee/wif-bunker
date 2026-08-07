# TPM State Management — CI vs Production

WIF Bunker must be a good citizen on production TPMs. It should NOT perform TPM initialization, handle eviction, or clear state — those are the responsibility of the system administrator or CI setup steps.

## The Contract

WIF Bunker expects an **already-initialized** PKCS#11 store with a primary object (pid=1). It only creates its own token, generates keys, and imports certificates. If the store isn't ready, fail with a clear error and setup instructions — don't try to fix it.

## State Matrix

| State / Step | CI-softtpm | CI-hardtpm (NUC8) | Healthy prod TPM |
|---|---|---|---|
| **TPM hardware** | Fresh swtpm each run | Persistent Intel PTT | Running kernel device |
| **Stale state?** | None (ephemeral) | Keys/handles from prior runs | None expected |
| **Step 1: TPM accessible** | Start swtpm + abrmd | Already running via `/dev/tpmrm0` | Already running |
| **Step 2: Health check** | N/A (fresh) | DA lockout check + auto-clear | N/A |
| **Step 3: Evict stale handles** | N/A (fresh) | `tpm2_evictcontrol` all persistent | N/A |
| **Step 4: Wipe PKCS#11 store** | N/A (doesn't exist) | `rm -rf ~/.tpm2_pkcs11` | N/A |
| **Step 5: Create store dir** | `mkdir -p ~/.tpm2_pkcs11` | `mkdir -p ~/.tpm2_pkcs11` | Done at install time |
| **Step 6: Init primary object** | `tpm2_ptool init` | `tpm2_ptool init` | Done at install time |
| **Step 7: Set env vars** | `TPM2_PKCS11_STORE`, TCTI vars | `TPM2_PKCS11_STORE` | Set in profile/systemd |
| **Resulting state** | Store with pid=1, no tokens | Store with pid=1, no tokens | Store with pid=1, no tokens |
| **WIF Bunker then does** | `addtoken` → gen key → import cert | Same | Same |

## Key Principles

- **CI setup steps** are responsible for getting the TPM into a sane state (steps 1–7 above)
- **WIF Bunker** only manages its own token (`bunker-wif`), keys, and certificates
- **Never run `tpm2_ptool init`** from WIF Bunker — it creates persistent handles and could interfere with other TPM applications (e.g., disk encryption, system integrity)
- **Never evict handles** from WIF Bunker — other applications may depend on them
- **Never clear DA lockout** from WIF Bunker — this is an admin operation
- The CI-softtpm and CI-hardtpm setup steps must produce an **identical resulting state** so WIF Bunker code paths are the same
