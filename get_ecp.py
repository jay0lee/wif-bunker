#!/usr/bin/env python3
"""Download ECP (Enterprise Certificate Proxy) binaries for the current platform.

This script downloads the correct ECP binaries from the
jay0lee/enterprise-certificate-proxy GitHub releases. It is used by:
  - CI workflows (before running integration tests)
  - Developers (after cloning the repo)
  - Build workflows (before PyInstaller bundles everything)

Usage:
    python get_ecp.py                    # Install to default location
    python get_ecp.py --output ecp/      # Install to specific directory
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import zipfile
import argparse
import platform
from pathlib import Path

import requests

_ECP_GITHUB_REPO = "jay0lee/enterprise-certificate-proxy"


def get_ecp_platform_info() -> tuple[str, str, str, str]:
    """Returns (github_os, arch, lib_ext, archive_ext) for the current platform."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine

    if sys.platform == "win32":
        return "windows", arch, ".dll", ".zip"
    elif sys.platform == "darwin":
        return "darwin", arch, ".dylib", ".tar.gz"
    else:
        return "linux", arch, ".so", ".tar.gz"


def get_ecp_binary_names() -> tuple[str, str, str]:
    """Returns (ecp_binary, libecp, tls_offload) filenames for the current platform."""
    _, _, lib_ext, _ = get_ecp_platform_info()
    exe_ext = ".exe" if sys.platform == "win32" else ""
    ecp_bin = f"ecp{exe_ext}"
    libecp = f"libecp{lib_ext}"
    # Windows uses "tls_offload.dll"; Linux/macOS use "libtls_offload.*"
    tls_offload = f"tls_offload{lib_ext}" if sys.platform == "win32" else f"libtls_offload{lib_ext}"
    return ecp_bin, libecp, tls_offload


def get_default_ecp_dir() -> Path:
    """Returns the default persistent directory for ECP binaries."""
    if sys.platform == "win32":
        local_app_data = os.environ.get(
            "LOCALAPPDATA", str(Path.home() / "AppData" / "Local"),
        )
        return Path(local_app_data) / "Google" / "ECP"
    else:
        return Path.home() / ".config" / "bunker-ecp"


def download_ecp(output_dir: Path) -> None:
    """Downloads ECP binaries from the forked GitHub release into output_dir."""
    github_os, arch, lib_ext, archive_ext = get_ecp_platform_info()

    # Use GITHUB_TOKEN if available (CI runners share IPs and hit the
    # 60 req/hr unauthenticated rate limit quickly).
    gh_headers = {}
    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if gh_token:
        gh_headers["Authorization"] = f"token {gh_token}"

    # Fetch latest release from the fork.
    api_url = f"https://api.github.com/repos/{_ECP_GITHUB_REPO}/releases/latest"
    print(f"Fetching ECP release from {_ECP_GITHUB_REPO}...")
    resp = requests.get(api_url, headers=gh_headers, timeout=30)
    resp.raise_for_status()
    release = resp.json()
    tag = release["tag_name"]

    # Find the two assets we need:
    #   ecp_*_{os}_{arch}.tar.gz           — ecp binary + libecp
    #   ecp_*_{os}_{arch}_tls_offload.*    — libtls_offload
    assets = release.get("assets", [])
    target_os_arch = f"{github_os}_{arch}"

    signer_asset = None
    offload_asset = None
    for a in assets:
        name = a["name"]
        if target_os_arch not in name:
            continue
        if "tls_offload" in name:
            offload_asset = a
        else:
            signer_asset = a

    if not signer_asset or not offload_asset:
        available = [a["name"] for a in assets]
        raise FileNotFoundError(
            f"ECP release {tag} missing assets for {target_os_arch}.\n"
            f"Available: {available}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    # Download and extract both archives.
    for asset in (signer_asset, offload_asset):
        print(f"Downloading {asset['name']}...")
        dl = requests.get(
            asset["browser_download_url"], headers=gh_headers, timeout=120,
        )
        dl.raise_for_status()

        if asset["name"].endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
                for member in zf.namelist():
                    basename = Path(member).name
                    if not basename:
                        continue
                    with zf.open(member) as src:
                        (output_dir / basename).write_bytes(src.read())
        else:
            with tarfile.open(fileobj=io.BytesIO(dl.content), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    src = tf.extractfile(member)
                    if src:
                        (output_dir / Path(member.name).name).write_bytes(src.read())

    # Make binaries executable on Unix.
    if sys.platform != "win32":
        for f in output_dir.iterdir():
            if f.is_file():
                f.chmod(f.stat().st_mode | 0o755)

    print(f"ECP {tag} installed to {output_dir}")

    # Verify all expected files are present.
    ecp_bin, libecp, tls_offload = get_ecp_binary_names()
    for name in (ecp_bin, libecp, tls_offload):
        if not (output_dir / name).exists():
            actual = [f.name for f in output_dir.iterdir()]
            raise FileNotFoundError(
                f"Expected {name} not found after download. "
                f"Actual files: {actual}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Download ECP binaries for the current platform.",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output directory (default: platform-specific location)",
    )
    args = parser.parse_args()

    output_dir = args.output or get_default_ecp_dir()
    github_os, arch, _, _ = get_ecp_platform_info()
    print(f"Platform: {github_os}/{arch}")

    # Check if already installed.
    ecp_bin, libecp, tls_offload = get_ecp_binary_names()
    if all((output_dir / n).exists() for n in (ecp_bin, libecp, tls_offload)):
        print(f"ECP binaries already present in {output_dir}")
        return

    download_ecp(output_dir)


if __name__ == "__main__":
    main()
