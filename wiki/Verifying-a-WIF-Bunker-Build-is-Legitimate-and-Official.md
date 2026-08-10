# Verifying a WIF Bunker Build is Legitimate and Official

WIF Bunker releases are built entirely through GitHub Actions, which means every single binary can be traced back to the exact source code commit and workflow run that produced it. In addition, all macOS and Windows binaries are code-signed by the project maintainer.

This page explains how to verify that a WIF Bunker binary you downloaded is:
- **Unmodified** — the file matches the official release exactly
- **Signed** — the binary was signed by the WIF Bunker developer (macOS, Windows)
- **Traceable** — it was built by this repository's CI pipeline, not by a third party

---

### Table of Contents

- [1. SHA-256 Checksums](#1-sha-256-checksums)
- [2. GitHub Attestation (Build Provenance)](#2-github-attestation-build-provenance)
- [3. macOS Code Signing & Notarization](#3-macos-code-signing--notarization)
  - [Verify Code Signature](#verify-code-signature)
  - [Verify Notarization](#verify-notarization)
- [4. Windows Code Signing](#4-windows-code-signing)
  - [Verify via GUI](#verify-via-gui)
  - [Verify via Command Line](#verify-via-command-line-powershell)
  - [Certificate Details](#certificate-details)
- [5. Linux Binaries](#5-linux-binaries)
- [Summary](#summary)
- [Build Transparency](#build-transparency)

---

## 1. SHA-256 Checksums

Every release includes a `SHA256SUMS.txt` file containing the SHA-256 hash of every artifact.

### Linux / macOS

```bash
# Download both the artifact and checksums file from the release
sha256sum -c SHA256SUMS.txt
```

### Windows (PowerShell)

```powershell
# Verify a specific file
(Get-FileHash .\wif-bunker-*-setup.exe -Algorithm SHA256).Hash
# Compare with the hash in SHA256SUMS.txt
```

If the hashes match, the file has not been tampered with since it was uploaded to GitHub.

## 2. GitHub Attestation (Build Provenance)

WIF Bunker uses [GitHub's artifact attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) to create a cryptographic, tamper-proof record proving each artifact was built by this repository's GitHub Actions workflow. This is the strongest verification available — it proves the binary was built from a specific commit by a specific workflow, signed by GitHub's own certificate authority (Sigstore).

### Verify with GitHub CLI

```bash
# Verify any release artifact
gh attestation verify wif-bunker-*.tar.gz -R jay0lee/wif-bunker

# Verify the Windows installer
gh attestation verify wif-bunker-*-setup.exe -R jay0lee/wif-bunker

# Verify the checksums file itself
gh attestation verify SHA256SUMS.txt -R jay0lee/wif-bunker
```

A successful verification looks like:
```
✓ Verification succeeded!

sha256:abc123... was attested by a]
Repo:       jay0lee/wif-bunker
Workflow:   .github/workflows/release.yml
```

This confirms:
- The artifact was built by the `release.yml` workflow in `jay0lee/wif-bunker`
- It was not modified after being built
- The attestation was signed by GitHub's Sigstore instance

### Requirements

- [GitHub CLI](https://cli.github.com/) (`gh`) version 2.49.0 or later
- You must be authenticated: `gh auth login`

## 3. macOS Code Signing & Notarization

All macOS binaries are:
1. **Code-signed** with an Apple Developer ID certificate (identity: `Jay Lee`)
2. **Notarized** by Apple — submitted to Apple's notary service, which scans for malware and issues a notarization ticket

### Verify Code Signature

```bash
# Check the code signature
codesign --verify --deep --strict --verbose=2 wif-bunker/wif-bunker

# Display signing details
codesign --display --verbose=4 wif-bunker/wif-bunker
```

You should see:
```
Authority=Developer ID Application: Jay Lee
Authority=Developer ID Certification Authority
Authority=Apple Root CA
```

### Verify Notarization

```bash
# Check notarization status (requires internet)
spctl --assess --verbose=2 --type execute wif-bunker/wif-bunker
```

A notarized binary will show:
```
wif-bunker/wif-bunker: accepted
source=Notarized Developer ID
```

### What This Means

- **Code signing** proves the binary was signed by the WIF Bunker developer's Apple certificate and hasn't been modified since signing
- **Notarization** proves Apple has scanned the binary and hasn't found any known malware
- macOS Gatekeeper automatically checks both of these when you first run the binary

## 4. Windows Code Signing

All Windows binaries (`wif-bunker.exe` and the InnoSetup installer) are code-signed with an EV (Extended Validation) code signing certificate issued by **Certum**.

### Verify via GUI

1. Right-click the `.exe` file → **Properties**
2. Click the **Digital Signatures** tab
3. Select the signature and click **Details**
4. You should see:
   - **Name:** Jay Lee
   - **Timestamp:** A valid RFC 3161 timestamp from `http://time.certum.pl`
   - **Status:** "This digital signature is OK"

### Verify via Command Line (PowerShell)

```powershell
# Quick verification
& 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' verify /pa /v .\wif-bunker.exe
```

Or without the Windows SDK:
```powershell
# Using PowerShell's Get-AuthenticodeSignature
Get-AuthenticodeSignature .\wif-bunker.exe | Format-List
```

You should see:
```
SignerCertificate : [Subject]   CN=Jay Lee, ...
                    [Issuer]    CN=Certum Code Signing 2021 CA, ...
Status            : Valid
StatusMessage     : Signature verified.
```

### Certificate Details

| Field | Value |
|---|---|
| Subject | Jay Lee |
| Issuer | Certum Code Signing 2021 CA |
| SHA-1 Thumbprint | `3B11D9340A45CF078FF7FD984F1C3E30DA82FD05` |
| Timestamp Authority | `http://time.certum.pl` |

### What This Means

- The binary was signed with a certificate that required identity verification by the Certificate Authority (Certum)
- The timestamp proves the binary was signed while the certificate was valid
- Windows SmartScreen will recognize the signed binary and not show "Unknown publisher" warnings

## 5. Linux Binaries

Linux binaries (`.tar.gz` archives) are not code-signed in the traditional sense because Linux doesn't have a universal code signing infrastructure like macOS or Windows. Instead, Linux builds are verified through:

1. **SHA-256 checksums** — verify the file wasn't tampered with
2. **GitHub attestation** — cryptographic proof the binary was built by this repo's CI

Both of these methods are described above.

## Summary

| Platform | Checksum | Attestation | Code Signing | Notarization |
|---|---|---|---|---|
| **Linux** | ✅ SHA-256 | ✅ Sigstore | — | — |
| **macOS** | ✅ SHA-256 | ✅ Sigstore | ✅ Developer ID | ✅ Apple Notary |
| **Windows** | ✅ SHA-256 | ✅ Sigstore | ✅ Certum EV | — |

## Build Transparency

Every WIF Bunker release is built by the [`release.yml`](https://github.com/jay0lee/wif-bunker/blob/main/.github/workflows/release.yml) workflow, which:

- Runs on GitHub-hosted runners (no self-hosted build infrastructure)
- Compiles Python and OpenSSL from source (via cached daily builds from [`build-python-ssl.yml`](https://github.com/jay0lee/wif-bunker/blob/main/.github/workflows/build-python-ssl.yml))
- Passes [integration tests](https://github.com/jay0lee/wif-bunker/blob/main/.github/workflows/integration-test.yml) against real GCP infrastructure before publishing
- Generates a [Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom) in SPDX format for each platform
- Attests every artifact with GitHub's Sigstore-backed attestation
- Creates immutable release tags

You can inspect the full build log for any release by clicking the workflow run link in the release notes.
