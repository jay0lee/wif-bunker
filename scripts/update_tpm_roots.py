#!/usr/bin/env python3
"""Fetch and verify TPM EK root/intermediate CA certificates from upstream.

Downloads the latest tpm-ca-certificates bundle using the upstream `tpmtb`
CLI (https://github.com/loicsikidi/tpm-ca-certificates), which performs
Sigstore signature and SLSA provenance verification, then splits the bundle
into individual per-vendor PEM files for transparency.

Prerequisites:
    tpmtb - install via: go install github.com/loicsikidi/tpm-ca-certificates/cmd/tpmtb@latest
            or download from: https://github.com/loicsikidi/tpm-ca-certificates/releases

Usage:
    python scripts/update_tpm_roots.py

The script will:
  1. Run `tpmtb bundle download` to fetch and cryptographically verify
     the latest bundle (Cosign integrity + SLSA provenance)
  2. Split the verified PEMs into individual per-vendor files under
     wif_bunker/attestation/roots/{roots,intermediates}/
  3. Print a summary of what changed
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Output directories (relative to repo root)
REPO_ROOT = Path(__file__).resolve().parent.parent
CERTS_DIR = REPO_ROOT / "wif_bunker" / "attestation" / "roots"
ROOTS_DIR = CERTS_DIR / "roots"
INTERMEDIATES_DIR = CERTS_DIR / "intermediates"


def _require_command(name: str, install_hint: str) -> None:
    """Verify a command is available on PATH."""
    if shutil.which(name) is None:
        print(f"ERROR: '{name}' not found on PATH.", file=sys.stderr)
        print(f"Install: {install_hint}", file=sys.stderr)
        sys.exit(1)


def _sanitize(name: str) -> str:
    """Convert a certificate subject to a safe filename."""
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name.lower()[:120]


def _get_subject_label(cert_pem: str) -> str:
    """Extract O + CN from a PEM certificate via openssl."""
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "utf8,sep_comma_plus_space"],
        input=cert_pem,
        capture_output=True,
        text=True,
    )
    subject = result.stdout.strip().removeprefix("subject=").strip()
    parts = []
    m = re.search(r"O\s*=\s*([^,]+)", subject)
    if m:
        parts.append(m.group(1).strip())
    m = re.search(r"CN\s*=\s*([^,]+)", subject)
    if m:
        parts.append(m.group(1).strip())
    return "_".join(parts) if parts else subject or "unknown"


def _split_bundle(pem_path: Path, out_dir: Path) -> int:
    """Split a PEM bundle into individual files. Returns count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    pem_text = pem_path.read_text(encoding="utf-8")
    certs = re.findall(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        pem_text,
        re.DOTALL,
    )
    seen: dict[str, int] = {}
    for cert_pem in certs:
        label = _sanitize(_get_subject_label(cert_pem))
        if label in seen:
            seen[label] += 1
            label = f"{label}_{seen[label]}"
        else:
            seen[label] = 1
        (out_dir / f"{label}.pem").write_text(cert_pem + "\n", encoding="utf-8")
    return len(certs)


def _download_and_verify(work_dir: Path) -> str:
    """Download and verify the latest bundle via tpmtb. Returns the release tag."""
    # List available releases to show the latest tag
    list_result = subprocess.run(
        ["tpmtb", "bundle", "list", "--output", "json"],
        capture_output=True,
        text=True,
    )
    if list_result.returncode == 0:
        try:
            releases = json.loads(list_result.stdout)
            tag = releases[0] if releases else "unknown"
        except (json.JSONDecodeError, IndexError):
            tag = "unknown"
    else:
        tag = "unknown"

    # Download and verify (Cosign + SLSA provenance)
    print("  Running: tpmtb bundle download (with Sigstore verification)...")
    result = subprocess.run(
        ["tpmtb", "bundle", "download"],
        cwd=work_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: tpmtb bundle download failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Print verification output
    for line in result.stderr.splitlines():
        if line.strip():
            print(f"  {line.strip()}")

    return tag


def main() -> None:
    _require_command(
        "tpmtb",
        (
            "go install github.com/loicsikidi/tpm-ca-certificates/cmd/tpmtb@latest\n"
            "         or: https://github.com/loicsikidi/tpm-ca-certificates/releases"
        ),
    )
    _require_command("openssl", "Install openssl for your platform")

    # Count existing files
    old_roots = len(list(ROOTS_DIR.glob("*.pem"))) if ROOTS_DIR.exists() else 0
    old_intermediates = len(list(INTERMEDIATES_DIR.glob("*.pem"))) if INTERMEDIATES_DIR.exists() else 0

    print("Fetching latest TPM EK root certificates...")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        tag = _download_and_verify(work)

        roots_pem = work / "tpm-ca-certificates.pem"
        intermediates_pem = work / "tpm-intermediate-ca-certificates.pem"

        if not roots_pem.exists():
            print("ERROR: tpmtb did not produce tpm-ca-certificates.pem", file=sys.stderr)
            sys.exit(1)

        # Clear and repopulate
        if ROOTS_DIR.exists():
            shutil.rmtree(ROOTS_DIR)
        if INTERMEDIATES_DIR.exists():
            shutil.rmtree(INTERMEDIATES_DIR)

        n_roots = _split_bundle(roots_pem, ROOTS_DIR)
        print(f"  Wrote {n_roots} root CAs to {ROOTS_DIR.relative_to(REPO_ROOT)}/")

        if intermediates_pem.exists():
            n_intermediates = _split_bundle(intermediates_pem, INTERMEDIATES_DIR)
            print(f"  Wrote {n_intermediates} intermediate CAs to {INTERMEDIATES_DIR.relative_to(REPO_ROOT)}/")
        else:
            n_intermediates = 0
            print("  No intermediates bundle in this release.")

    # Summary
    print()
    print(f"Source:  https://github.com/loicsikidi/tpm-ca-certificates (bundle: {tag})")
    print("Verify:  Sigstore integrity + SLSA provenance (via tpmtb)")
    print(f"Root CAs:         {old_roots} -> {n_roots}")
    print(f"Intermediate CAs: {old_intermediates} -> {n_intermediates}")
    print()
    print("Review changes with:  git diff --stat")
    print("Commit with:          git add -A && git commit -m 'chore: update TPM EK root CAs'")


if __name__ == "__main__":
    main()
