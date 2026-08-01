#!/usr/bin/env python3
"""Temporary patches for google-auth to support hardware-backed keys.

These patches modify the installed google-auth library files to support
X.509 WIF with hardware-backed keys (TPM/Secure Enclave) where no
extractable private key file exists.

Remove this script once these upstream PRs land:
  - google-auth: allow missing key_path in workload cert config
  - ECP: support macOS Secure Enclave / CryptoTokenKit keys

Usage:
    python patches/patch_google_auth.py
"""

import importlib
import os
import sys


def find_package_file(*module_parts):
    """Locate an installed package file by module path."""
    mod = importlib.import_module(".".join(module_parts[:-1]))
    pkg_dir = os.path.dirname(mod.__file__)
    return os.path.join(pkg_dir, module_parts[-1] + ".py")


def patch_file(filepath, original, replacement, description):
    """Replace exact text in a file. Fails loudly if original not found."""
    with open(filepath, "r") as f:
        content = f.read()

    if replacement in content:
        print(f"  SKIP (already patched): {description}")
        return

    if original not in content:
        print(f"  FAIL: Could not find target text for: {description}")
        print(f"        File: {filepath}")
        sys.exit(1)

    content = content.replace(original, replacement, 1)
    with open(filepath, "w") as f:
        f.write(content)
    print(f"  OK:   {description}")


def main():
    print("Patching google-auth for hardware-backed key support...\n")

    # ── Patch 1: _mtls_helper.py ──────────────────────────────────────────
    # Allow missing key_path (hardware-backed keys have no extractable key).
    mtls_helper = find_package_file(
        "google", "auth", "transport", "_mtls_helper",
    )
    patch_file(
        mtls_helper,
        # Original: raises error if key_path missing
        '    if "key_path" not in workload:\n'
        "        raise exceptions.ClientCertError(\n"
        "            'Certificate config file {} is in an invalid format, "
        'a "key_path" is expected in the workload cert config\'.format(\n'
        "                absolute_path\n"
        "            )\n"
        "        )\n"
        '    key_path = workload["key_path"]',
        # Patched: key_path is optional, defaults to None
        '    key_path = workload.get("key_path")  # None for hardware-backed keys',
        "Allow missing key_path in _mtls_helper._get_workload_cert_and_key_paths",
    )

    # ── Patch 2: external_account.py ──────────────────────────────────────
    # Skip cert= injection when key_path is None. When key_path is None,
    # passing cert=(cert_path, None) causes urllib3 to try reading a private
    # key from the cert PEM. The mTLS adapter handles signing via ECP instead.
    external_account = find_package_file(
        "google", "auth", "external_account",
    )
    patch_file(
        external_account,
        # Original: always injects cert= when mTLS required
        "        if self._mtls_required():\n"
        "            request = functools.partial(\n"
        "                request, cert=self._get_mtls_cert_and_key_paths()\n"
        "            )",
        # Patched: skip injection if key_path is None (hardware-backed)
        "        if self._mtls_required():\n"
        "            _cert_path, _key_path = self._get_mtls_cert_and_key_paths()\n"
        "            if _key_path is not None:\n"
        "                request = functools.partial(\n"
        "                    request, cert=(_cert_path, _key_path)\n"
        "                )",
        "Skip cert= injection when key_path is None in external_account.refresh",
    )

    # ── Patch 3: _custom_tls_signer.py ────────────────────────────────────
    # When GetCertPemForPython returns 0 (can't access keychain/TPM),
    # fall back to reading the cert from the PEM file in the config.
    custom_tls_signer = find_package_file(
        "google", "auth", "transport", "_custom_tls_signer",
    )
    patch_file(
        custom_tls_signer,
        # Original: raises immediately if cert_len == 0
        '    if cert_len == 0:\n'
        '        raise exceptions.MutualTLSChannelError("failed to get certificate")',
        # Patched: fall back to reading cert from config file
        "    if cert_len == 0:\n"
        "        # Fallback: read cert from the cert_path in the config file.\n"
        "        try:\n"
        "            import json as _json\n"
        "            with open(config_file_path, 'r') as _f:\n"
        "                _cfg = _json.load(_f)\n"
        "            _cert_path = _cfg.get('cert_configs', {}).get('workload', {}).get('cert_path')\n"
        "            if _cert_path:\n"
        "                with open(_cert_path, 'rb') as _cf:\n"
        "                    return _cf.read()\n"
        "        except Exception:\n"
        "            pass\n"
        '        raise exceptions.MutualTLSChannelError("failed to get certificate")',
        "Fallback cert reading in _custom_tls_signer.get_cert",
    )

    print("\nAll patches applied successfully.")


if __name__ == "__main__":
    main()
