#!/usr/bin/env python3
"""Build a patched ECP from source for hardware-backed key support.

Patches enterprise-certificate-proxy to use SecCertificateCopyData instead
of SecItemExport in keychain.go.  SecItemExport silently fails for Secure
Enclave / CryptoTokenKit identities, causing ECP to skip them.

Remove this script once the upstream fix lands in ECP.

Usage (requires Go 1.21+):
    python patches/build_patched_ecp.py [--output-dir DIR]
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ECP_REPO = "https://github.com/googleapis/enterprise-certificate-proxy.git"
ECP_TAG = "v0.3.19"

# The old certRefToX509 uses SecItemExport which fails for SE keys.
OLD_CERT_REF_TO_X509 = '''\
func certRefToX509(certRef C.SecCertificateRef) (*x509.Certificate, error) {
\t// Export the PEM-encoded certificate to a CFDataRef.
\tvar certPEMData C.CFDataRef
\tif errno := C.SecItemExport(C.CFTypeRef(certRef), C.kSecFormatUnknown, C.kSecItemPemArmour, nil, &certPEMData); errno != 0 {
\t\treturn nil, keychainError(errno)
\t}
\tdefer C.CFRelease(C.CFTypeRef(certPEMData))
\tcertPEM := cfDataToBytes(certPEMData)

\t// This part based on crypto/tls.
\tvar certDERBlock *pem.Block
\tfor {
\t\tcertDERBlock, certPEM = pem.Decode(certPEM)
\t\tif certDERBlock == nil {
\t\t\treturn nil, fmt.Errorf("failed to parse certificate PEM data")
\t\t}
\t\tif certDERBlock.Type == "CERTIFICATE" {
\t\t\t// found it
\t\t\tbreak
\t\t}
\t}

\t// Check the certificate is OK by the x509 library, and obtain the
\t// public key algorithm (which I assume is the same as the private key
\t// algorithm). This also filters out certs missing critical extensions.
\txc, err := x509.ParseCertificate(certDERBlock.Bytes)'''

# Replacement uses SecCertificateCopyData which works for all cert types.
NEW_CERT_REF_TO_X509 = '''\
func certRefToX509(certRef C.SecCertificateRef) (*x509.Certificate, error) {
\t// Patched: use SecCertificateCopyData instead of SecItemExport.
\t// SecItemExport fails silently for Secure Enclave / CryptoTokenKit
\t// identities, causing hardware-backed keys to be skipped.
\tcertDERData := C.SecCertificateCopyData(certRef)
\tif certDERData == 0 {
\t\treturn nil, fmt.Errorf("SecCertificateCopyData returned nil")
\t}
\tdefer C.CFRelease(C.CFTypeRef(certDERData))

\txc, err := x509.ParseCertificate(cfDataToBytes(certDERData))'''


def run(cmd, cwd=None):
    print(f"  $ {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=cwd)


def main():
    parser = argparse.ArgumentParser(description="Build patched ECP binaries")
    parser.add_argument(
        "--output-dir", default=os.path.expanduser("~/.config/bunker-ecp"),
        help="Directory to place built ECP binaries (default: ~/.config/bunker-ecp)",
    )
    args = parser.parse_args()

    if sys.platform != "darwin":
        print("ECP patching is only needed on macOS (Secure Enclave support).")
        print("Skipping.")
        return

    # Check for Go
    if not shutil.which("go"):
        print("ERROR: Go is required to build ECP. Install from https://go.dev/dl/")
        sys.exit(1)

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ecp-build-") as tmpdir:
        repo_dir = os.path.join(tmpdir, "ecp")

        # Clone
        print(f"\n1. Cloning ECP {ECP_TAG}...")
        run(["git", "clone", "--depth=1", "--branch", ECP_TAG, ECP_REPO, repo_dir])

        # Patch keychain.go
        print("\n2. Patching keychain.go (SecItemExport → SecCertificateCopyData)...")
        keychain_path = os.path.join(
            repo_dir, "internal", "signer", "darwin", "keychain", "keychain.go",
        )
        with open(keychain_path, "r") as f:
            content = f.read()

        if OLD_CERT_REF_TO_X509 not in content:
            print("  WARNING: Could not find target text in keychain.go.")
            print("  The upstream code may have changed. Trying to continue...")
        else:
            content = content.replace(OLD_CERT_REF_TO_X509, NEW_CERT_REF_TO_X509, 1)
            with open(keychain_path, "w") as f:
                f.write(content)
            print("  OK: Patched certRefToX509")

        # Remove unused 'pem' import (no longer needed after patch)
        # The import is used elsewhere so we leave it.

        # Build the C-shared signer library (ecp_client)
        print("\n3. Building ECP C-shared library (ecp_client)...")
        arch = "arm64" if platform.machine() == "arm64" else "amd64"
        cshared_dir = os.path.join(repo_dir, "cshared")
        signer_output = os.path.join(output_dir, "libecp.dylib")
        run(
            [
                "go", "build",
                "-buildmode=c-shared",
                f"-o={signer_output}",
                ".",
            ],
            cwd=cshared_dir,
        )
        print(f"  Built: {signer_output}")

        # Build the macOS signer binary
        print("\n4. Building ECP macOS signer binary...")
        darwin_signer_dir = os.path.join(repo_dir, "internal", "signer", "darwin")
        signer_bin_output = os.path.join(output_dir, "ecp")
        run(
            [
                "go", "build",
                f"-o={signer_bin_output}",
                ".",
            ],
            cwd=darwin_signer_dir,
        )
        print(f"  Built: {signer_bin_output}")

        # Download the TLS offload library from the GitHub release.
        # The offload library is a separate binary (provides ConfigureSslContext)
        # that does NOT need patching — only the signer library does.
        print("\n5. Downloading TLS offload library from GitHub release...")
        import io
        import json
        import tarfile
        import urllib.request

        release_url = f"https://api.github.com/repos/googleapis/enterprise-certificate-proxy/releases/tags/{ECP_TAG}"
        with urllib.request.urlopen(release_url) as resp:
            release = json.loads(resp.read())

        arch_str = "arm64" if platform.machine() == "arm64" else "amd64"
        offload_output = os.path.join(output_dir, "libtls_offload.dylib")
        offload_asset = None
        for asset in release["assets"]:
            if "tls_offload" in asset["name"] and "darwin" in asset["name"] and arch_str in asset["name"]:
                offload_asset = asset
                break

        if offload_asset:
            print(f"  Downloading {offload_asset['name']}...")
            with urllib.request.urlopen(offload_asset["browser_download_url"]) as dl:
                with tarfile.open(fileobj=io.BytesIO(dl.read()), mode="r:gz") as tf:
                    tf.extractall(output_dir)
            # Rename to expected name if needed
            for f in os.listdir(output_dir):
                if "tls_offload" in f and f.endswith(".dylib"):
                    src = os.path.join(output_dir, f)
                    if src != offload_output:
                        shutil.move(src, offload_output)
            print(f"  Downloaded: {offload_output}")
        else:
            print("  WARNING: Could not find TLS offload asset in release.")
            print(f"  Available: {[a['name'] for a in release['assets']]}")

    print(f"\n✅ Patched ECP binaries installed to: {output_dir}")
    print("Files:")
    for f in sorted(os.listdir(output_dir)):
        fpath = os.path.join(output_dir, f)
        size = os.path.getsize(fpath) // 1024
        print(f"  {f} ({size} KB)")


if __name__ == "__main__":
    main()
