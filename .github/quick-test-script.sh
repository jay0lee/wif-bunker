#!/usr/bin/env bash
# Quick Test Script — edit this file, commit & push to run on the
# runner specified in .github/quick-test-config.json
#
# Environment available:
#   - wif-bunker installed in venv (if install_wif_bunker=true)
#   - TPM reset to clean state (if setup_tpm=true, hardware-tpm only)
#   - TPM2_PKCS11_STORE set to $HOME/.tpm2_pkcs11 (on TPM runners)
#   - GCP auth via WIF (GOOGLE_APPLICATION_CREDENTIALS set)
#   - ECP binaries downloaded to ./ecp/ (if install_wif_bunker=true)
#
# The "Environment dump" and "Post-run diagnostics" steps run
# automatically before/after this script — no need to add them here.

set -euo pipefail

echo "=== Quick Test: Hardware TPM ECP/PKCS#11 Debug ==="

# 1. Generate a workload key+cert
python -m wif_bunker --cert-only --output-dir test1
echo ""

# 2. Check what wif-bunker created
echo "=== Files created ==="
ls -la test1/
echo ""

# 3. Show the adc.json to verify PKCS#11 URI
echo "=== adc.json ==="
cat test1/adc.json
echo ""

# 4. Check PKCS#11 store state
echo "=== PKCS#11 store ==="
ls -la "$HOME/.tpm2_pkcs11/"
echo ""

# 5. Verify PKCS#11 tokens visible
echo "=== PKCS#11 tokens ==="
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so -T 2>&1 || true
echo ""

# 6. Try ECP directly to reproduce the CKR_GENERAL_ERROR
echo "=== Testing ECP ==="
if [ -d "ecp" ]; then
  export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/test1/adc.json"
  ./ecp/ecp 2>&1 || echo "(ECP exited with rc=$?)"
else
  echo "ECP not found — skipping"
fi
