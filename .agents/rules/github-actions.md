# GitHub Actions Workflow Rules

## Paths and Variables

- **NEVER** use hard-coded paths like `/tmp`, `/home`, or `/usr` in workflow steps.
- **ALWAYS** use GitHub Actions runner variables:
  - `$RUNNER_TEMP` — temporary directory for the current job
  - `$GITHUB_WORKSPACE` — the workspace/checkout directory
  - `$HOME` — only for user-specific config (e.g., `$HOME/.tpm2_pkcs11`)
- Quote all variable expansions in paths: `"$RUNNER_TEMP/file"` not `$RUNNER_TEMP/file`.

## TPM (Hardware TPM NUC8)

- **NEVER** clear or undefine NV indices — EK certificates and firmware-provisioned data live there and require platform auth (locked after boot) to restore.
- Intel PTT does not store EK certs in NV RAM; they are fetched at runtime via `tpm2_getekcertificate` from Intel's Endorsement Provisioning Service.
- The CI TPM reset should only: evict persistent handles, wipe the PKCS#11 SQLite store, and re-initialize with `tpm2_ptool init`.
- Do not suppress stderr from TPM commands (`2>/dev/null`) — surface errors so they can be diagnosed.

## Error Handling

- Do not use `|| true` to mask failures. If a command can legitimately fail, use an `if` block with clear messaging.
- Do not suppress stderr unless there is a specific, documented reason.
