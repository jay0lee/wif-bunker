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
import re
import sys


def find_package_file(*module_parts):
    """Locate an installed package file by module path."""
    mod = importlib.import_module(".".join(module_parts[:-1]))
    pkg_dir = os.path.dirname(mod.__file__)
    return os.path.join(pkg_dir, module_parts[-1] + ".py")


def patch_file_regex(filepath, pattern, replacement, description):
    """Replace a regex pattern in a file. Fails loudly if pattern not found."""
    with open(filepath, "r") as f:
        content = f.read()

    # Check if already patched
    marker = f"PATCHED: {description}"
    if marker in content:
        print(f"  SKIP (already patched): {description}")
        return

    new_content, count = re.subn(pattern, replacement, content, count=1, flags=re.DOTALL)
    if count == 0:
        print(f"  FAIL: Could not find target pattern for: {description}")
        print(f"        File: {filepath}")
        print(f"        Pattern: {pattern[:120]}...")
        sys.exit(1)

    with open(filepath, "w") as f:
        f.write(new_content)
    print(f"  OK:   {description}")


def main():
    print("Patching google-auth for hardware-backed key support...\n")

    # ── Patch 1: _mtls_helper.py ──────────────────────────────────────────
    # Allow missing key_path (hardware-backed keys have no extractable key).
    # The original code raises ClientCertError if "key_path" not in workload.
    # We replace the entire key_path check block with a .get() call.
    mtls_helper = find_package_file(
        "google", "auth", "transport", "_mtls_helper",
    )
    patch_file_regex(
        mtls_helper,
        # Match the combined cert_path/key_path check and both assignments.
        # Actual code:
        #   if "cert_path" not in workload or "key_path" not in workload:
        #       raise exceptions.ClientCertError(...)
        #   cert_path = workload["cert_path"]
        #   key_path = workload["key_path"]
        r'([ \t]+)if "cert_path" not in workload or "key_path" not in workload:.*?'
        r'cert_path = workload\["cert_path"\]\s*\n'
        r'\s+key_path = workload\["key_path"\]',
        # Replace: require cert_path but allow key_path to be missing.
        r'\1if "cert_path" not in workload:\n'
        r'\1    raise exceptions.ClientCertError(\n'
        r"\1        'Workload certificate configuration is missing"
        r''' \"cert_path\" in {}'.format(\n'''
        r'\1            absolute_path\n'
        r'\1        )\n'
        r'\1    )\n'
        r'\1# PATCHED: Allow missing key_path\n'
        r'\1cert_path = workload["cert_path"]\n'
        r'\1key_path = workload.get("key_path")  # None for hardware-backed keys',
        "Allow missing key_path",
    )

    # ── Patch 2: external_account.py ──────────────────────────────────────
    # Skip cert= injection when key_path is None. When key_path is None,
    # passing cert=(cert_path, None) causes urllib3 to try reading a private
    # key from the cert PEM. The mTLS adapter handles signing via ECP instead.
    external_account = find_package_file(
        "google", "auth", "external_account",
    )
    patch_file_regex(
        external_account,
        # Match the mTLS cert injection block.
        r'([ \t]+)if self\._mtls_required\(\):\s*\n'
        r'\s+request = functools\.partial\(\s*\n'
        r'\s+request, cert=self\._get_mtls_cert_and_key_paths\(\)\s*\n'
        r'\s+\)',
        # Replace: only inject cert= if key_path is not None.
        r'\1# PATCHED: Skip cert= injection when key_path is None\n'
        r'\1if self._mtls_required():\n'
        r'\1    _cert_path, _key_path = self._get_mtls_cert_and_key_paths()\n'
        r'\1    if _key_path is not None:\n'
        r'\1        request = functools.partial(\n'
        r'\1            request, cert=(_cert_path, _key_path)\n'
        r'\1        )',
        "Skip cert= injection when key_path is None",
    )

    # ── Patch 3: _custom_tls_signer.py ────────────────────────────────────
    # When GetCertPemForPython returns 0 (can't access keychain/TPM),
    # fall back to reading the cert from the PEM file in the config.
    custom_tls_signer = find_package_file(
        "google", "auth", "transport", "_custom_tls_signer",
    )
    patch_file_regex(
        custom_tls_signer,
        # Match: if cert_len == 0: raise MutualTLSChannelError(...)
        r'([ \t]+)if cert_len == 0:\s*\n'
        r'\s+raise exceptions\.MutualTLSChannelError\("failed to get certificate"\)',
        # Replace: try reading from cert_path in config, then raise if that also fails.
        r'\1# PATCHED: Fallback cert reading in _custom_tls_signer.get_cert\n'
        r'\1if cert_len == 0:\n'
        r'\1    # Fallback: read cert from the cert_path in the config file.\n'
        r'\1    try:\n'
        r'\1        import json as _json\n'
        r"\1        with open(config_file_path, 'r') as _f:\n"
        r'\1            _cfg = _json.load(_f)\n'
        r"\1        _cert_path = _cfg.get('cert_configs', {}).get('workload', {}).get('cert_path')\n"
        r'\1        if _cert_path:\n'
        r"\1            with open(_cert_path, 'rb') as _cf:\n"
        r'\1                return _cf.read()\n'
        r'\1    except Exception:\n'
        r'\1        pass\n'
        r'\1    raise exceptions.MutualTLSChannelError("failed to get certificate")',
        "Fallback cert reading in _custom_tls_signer.get_cert",
    )

    print("\nAll patches applied successfully.")


if __name__ == "__main__":
    main()
