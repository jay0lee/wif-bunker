# WIF Bunker

**Pure-Python, Hardware-Backed OIDC Workload Identity Federation for Google Cloud**

> [!WARNING]
> **Beta Software** — WIF Bunker is under active development and has not yet been proven in production environments. It is suitable for development, testing, and non-critical workloads. Bug reports and field testing feedback are welcome via [Issues](https://github.com/jay0lee/wif-bunker/issues).

WIF Bunker binds a **pre-existing non-exportable hardware key** (TPM 2.0, Apple Secure Enclave, YubiKey PIV, PKCS#11 HSM, or FIDO2 security key) to Google Cloud [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) using **Static-JWKS OIDC** — no external Identity Provider, no mTLS, no Rust native libraries, and no exportable service account JSON keys on disk.

Its built-in localhost token-caching agent (`wif-bunker agent`) signs **once per hour** with your hardware key and serves cached Google OAuth2 access tokens to **100% stock ADC clients** (Python, Go, Node, Java, Terraform, GAM, `gcloud`) over `127.0.0.1` — even across hundreds of parallel workers or Domain-Wide Delegation loops.

> **Looking for the legacy X.509 mTLS / ECP engine?** The `hardmTLS` Rust library has been preserved in its own standalone repository at **[jay0lee/hardmtls](https://github.com/jay0lee/hardmtls)**.

## Why WIF Bunker v2?

| | Service Account JSON Keys | WIF Bunker v2 (Static-JWKS OIDC) |
|---|---|---|
| **Private key location** | Exportable JSON file on disk | Non-exportable hardware key (TPM, SE, YubiKey, PKCS#11, FIDO2) |
| **External IdP required?** | No | **No** — public JWK uploaded directly to GCP WIF provider |
| **Client SDK compatibility** | Stock ADC | **100% stock ADC** (plain HTTPS / localhost HTTP, zero custom patches) |
| **Performance (e.g. GAM DwD)** | Fast | **1 hardware sign/hour** across all local processes via `wif-bunker agent` |
| **Binary / TLS stack** | Pure Python | **100% Pure Python** — no shared OpenSSL / mTLS constraints |
| **Hardware Attestation** | None | Optional read-only `wif-bunker attest` (TPM 2.0 & YubiKey PIV) |

## Supported Hardware Signers

WIF Bunker delegates all hardware signing to the pluggable signers in **[jay0lee/dpop-signers](https://github.com/jay0lee/dpop-signers)** and does **not** provision or overwrite keys. Provision a key once using the instructions for your hardware:

| `--signer` | Hardware | Provisioning Guide |
|---|---|---|
| `linux-tpm` | Linux TPM 2.0 persistent handle (e.g. `0x81000001`) | [dpop-signers/linux-tpm](https://github.com/jay0lee/dpop-signers/tree/main/linux-tpm) |
| `windows-certstore` | Windows Certificate Store / TPM 2.0 CNG (PCP) | [dpop-signers/windows-certstore](https://github.com/jay0lee/dpop-signers/tree/main/windows-certstore) |
| `macos-secureenclave` | Apple Silicon Secure Enclave (`sc_auth` CTK / Keychain) | [dpop-signers/macos-secureenclave](https://github.com/jay0lee/dpop-signers/tree/main/macos-secureenclave) |
| `yubikey` | YubiKey 5 PIV slot (`9c`, `9a`, `9d`, `9e`) | [dpop-signers/yubikey](https://github.com/jay0lee/dpop-signers/tree/main/yubikey) |
| `pkcs11` | Any PKCS#11 HSM / smart card via RFC 7512 URI | [dpop-signers/pkcs11](https://github.com/jay0lee/dpop-signers/tree/main/pkcs11) |
| `fido2-previewsign` | FIDO2 / CTAP 2.3 `previewSign` authenticator | [dpop-signers/fido2-previewsign](https://github.com/jay0lee/dpop-signers/tree/main/fido2-previewsign) |
| `software` | Pre-existing PEM private key (CI / local dev only) | ES256 or RS256 PEM file |

> **Supported OIDC algorithms:** GCP Static-JWKS OIDC WIF supports **`ES256`** (ECDSA P-256, recommended) and **`RS256`** (RSA 2048+).

## Installation

### Pre-built releases (Linux / macOS)

```bash
bash <(curl -s -S -L https://raw.githubusercontent.com/jay0lee/wif-bunker/main/packaging/install.sh)
```

### Windows

Download and run `wif-bunker-VERSION-windows-x86_64-setup.exe` (or `wif-bunker-VERSION-windows-arm64-setup.exe` for Windows on ARM) from [Releases](https://github.com/jay0lee/wif-bunker/releases).

### From source (Python 3.10+)

```bash
# On Linux, install system libs for tpm2-pytss / pyscard first:
# sudo apt install libpcsclite-dev libtss2-dev swig pkg-config

pip install git+https://github.com/jay0lee/wif-bunker.git
```

## Quick Start

### 1. Provision a hardware key (once)

Follow the short guide for your hardware in [jay0lee/dpop-signers](https://github.com/jay0lee/dpop-signers) (for example, a persistent ES256 handle `0x81000001` in Linux TPM 2.0, a PIV key in YubiKey slot `9c`, a Windows Cert Store TPM key, or a macOS Secure Enclave CTK identity).

### 2. Bind your key to GCP Static-JWKS OIDC WIF

```bash
# Example: Linux TPM 2.0 handle 0x81000001
wif-bunker setup \
  --signer linux-tpm --tpm-handle 0x81000001 \
  --create-project my-wif-project --gcp-folder 123456789

# Example: YubiKey PIV slot 9c
wif-bunker setup \
  --signer yubikey --yubikey-slot 9c \
  --use-project my-wif-project

# Example: Windows Cert Store (TPM CNG)
wif-bunker setup \
  --signer windows-certstore --windows-subject "WIF Bunker" \
  --use-project my-wif-project

# Example: macOS Secure Enclave
wif-bunker setup \
  --signer macos-secureenclave --macos-label "WIF Bunker" \
  --use-project my-wif-project
```

This creates the GCP WIF pool, uploads your key's public JWK as a Static-JWKS OIDC provider (no external IdP is ever contacted by Google), configures IAM bindings (Service Account impersonation by default, or `--no-service-account` for direct WIF), writes `bunker.json` (`0600`), and verifies the full exchange end-to-end.

To rotate keys in place without creating or soft-deleting providers, reuse the same pool, provider, and subject:

```bash
wif-bunker setup \
  --signer linux-tpm --tpm-handle 0x81000001 \
  --use-project my-wif-project \
  --use-pool bunker-wif-pool \
  --use-provider my-oidc-provider \
  --use-service-account bunker-wif-sa@my-wif-project.iam.gserviceaccount.com \
  --subject my-host
```

### 3. Run in Agent Mode (Recommended — 1 Hardware Sign / Hour)

```bash
wif-bunker agent --config bunker.json
```

The agent binds `127.0.0.1:<ephemeral-port>` (or a fixed `--port` for systemd/launchd/Windows Service), creates a `0600` per-session shared secret, writes `adc.json`, and caches minted Google access tokens **in RAM only**.

Then point any stock ADC application at `adc.json`:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/adc.json
```

```python
import google.auth

credentials, project = google.auth.default()
# Uses stock google-auth — zero custom patches, zero mTLS!
```

### Alternative: Daemon-less Executable ADC Mode

If you prefer no long-running agent process (or work in locked-down Windows AV/EDR environments where local HTTP ports are restricted), pass `--write-executable-adc` during `setup`:

```bash
wif-bunker setup \
  --signer yubikey --yubikey-slot 9c \
  --use-project my-wif-project \
  --write-executable-adc \
  --executable-cache-file ~/.cache/wif-bunker-jwt.json
```

Then enable Google's Pluggable Auth executable credential source in your client environment:

```bash
export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/adc.json
```

Stock Google ADC libraries will automatically invoke `wif-bunker sign-jwt` whenever the cached OIDC JWT expires (defaults to **1 hour**, customizable via `--jwt-lifetime`, so even daemon-less mode only signs with your hardware key once per hour).

## CLI Reference

| Command | Description |
|---|---|
| `wif-bunker setup` | Bind a pre-existing hardware key to a GCP Static-JWKS OIDC WIF Provider and write `bunker.json` |
| `wif-bunker agent` | Run the foreground localhost token-caching agent (`POST /v1/token`, `GET /health`) |
| `wif-bunker sign-jwt` | Mint a signed OIDC JWT and print Google Pluggable Auth v1 JSON to stdout |
| `wif-bunker status` | Inspect `bunker.json`, probe running agent `/health`, and test live OIDC STS → GCP API |
| `wif-bunker attest` | Run read-only hardware attestation (`tpm2_certify` / Windows PCP / YubiKey PIV `f9`) |
| `wif-bunker versions` | Print version info, installed `dpop-signers` backends, environment variables, and system info |

Run `wif-bunker <command> --help` for full options on each subcommand.

## Security Model

- **Zero key material on disk:** Private keys remain inside your hardware module; `bunker.json` contains only public JWK metadata, GCP resource names, and the hardware locator.
- **No external IdP:** Uploading static `jwksJson` on the GCP OIDC provider instructs Google STS to validate signatures locally against your pinned public key without making outbound calls to `issuerUri`.
- **RAM-only token caching:** `wif-bunker agent` keeps Google access tokens strictly in memory. Its localhost `/v1/token` endpoint validates a per-session 256-bit secret (`0600` file, preferably in `$XDG_RUNTIME_DIR`) using constant-time `hmac.compare_digest`.
- **Read-only attestation:** `wif-bunker attest` verifies TPM 2.0 EK chains / `TPM2_Certify` / Windows PCP creation properties / YubiKey PIV `f9` chains against bundled manufacturer root CAs without modifying keys.
- **Build provenance:** Release binaries are signed, notarized (macOS), code-signed (Windows), and include SLSA build provenance attestations (`gh attestation verify`).

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
