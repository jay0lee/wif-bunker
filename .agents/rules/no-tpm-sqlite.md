# TPM2 PKCS#11 SQLite — Do Not Touch

Never directly read, write, check existence of, or delete the `tpm2_pkcs11.sqlite3` database files from application code. Doing so leads to database corruption, stale references, or bad assumptions about internal schema.

## Allowed Interactions

| Layer | Tool | Use case |
|---|---|---|
| TPM operations | `tpm2-pytss` ESAPI | Keys, sessions, certify, activate_credential |
| PKCS#11 store management | `tpm2_ptool` CLI | `init`, `addtoken`, `rmtoken` |
| PKCS#11 token querying | `python-pkcs11` library | Finding tokens, keys, certificates |
| EK cert fetch | `tpm2_getekcertificate` CLI | Manufacturer provisioning service |

## Forbidden

- `Path(..., "tpm2_pkcs11.sqlite3").exists()` — don't check for the file
- `db_path.unlink()` — don't delete the file
- `sqlite3.connect(...)` on the store — don't query it directly
- Any direct file operations on the PKCS#11 store directory contents

## Exception

Forensic / debugging only (e.g., `sqlite3` CLI to inspect state during incident investigation). Never from application code, never to modify.
