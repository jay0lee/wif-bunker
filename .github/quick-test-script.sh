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

set -uo pipefail  # no -e: we want to see ALL output even if something fails
RC=0

echo "=== Quick Test: Hardware TPM ECP/PKCS#11 Debug ==="
echo ""

# 1. Generate a workload key+cert
echo "--- Step 1: Generate workload key+cert ---"
python -m wif_bunker --cert-only --output-dir test1 || { echo "FAIL: cert generation"; RC=1; }
echo ""

# 2. Check what wif-bunker created
echo "--- Step 2: Files created ---"
ls -la test1/ 2>/dev/null || echo "(test1/ not found)"
echo ""

# 3. Check PKCS#11 store state
echo "--- Step 3: PKCS#11 store ---"
echo "TPM2_PKCS11_STORE=$TPM2_PKCS11_STORE"
ls -la "$HOME/.tpm2_pkcs11/" 2>/dev/null || echo "(store not found)"
echo ""

# 4. Verify PKCS#11 tokens visible to pkcs11-tool
echo "--- Step 4: PKCS#11 tokens (via pkcs11-tool) ---"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so -T 2>&1 || true
echo ""

# 5. Verify PKCS#11 tokens visible to p11tool
echo "--- Step 5: PKCS#11 tokens (via p11tool) ---"
p11tool --provider=/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so --list-tokens 2>&1 || true
echo ""

# 6. Check what the PKCS#11 URI looks like in cert_config
echo "--- Step 6: cert_config.json (PKCS#11 URI) ---"
if [ -f test1/cert_config.json ]; then
  cat test1/cert_config.json
else
  echo "(no cert_config.json — checking for ecp_meta.json)"
  cat test1/ecp_meta.json 2>/dev/null || echo "(no ecp_meta.json either)"
fi
echo ""

# 7. Try ECP directly
echo "--- Step 7: Testing ECP ---"
if [ -d "ecp" ]; then
  echo "ECP binary found at ./ecp/"
  ls -la ecp/
  echo ""

  # Create a minimal adc.json pointing to cert_config
  if [ -f test1/cert_config.json ]; then
    echo "Creating adc.json pointing to cert_config.json..."
    cat > test_adc.json <<ADCEOF
{
  "type": "external_account",
  "credential_source": {
    "certificate": {
      "use_default_provider": false,
      "certificate_config_location": "$(pwd)/test1/cert_config.json"
    }
  }
}
ADCEOF
    echo "adc.json contents:"
    cat test_adc.json
    echo ""

    echo "Running ECP with GOOGLE_APPLICATION_CREDENTIALS=test_adc.json..."
    GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/test_adc.json" ./ecp/ecp 2>&1 || echo "(ECP exited with rc=$?)"
  else
    echo "No cert_config.json to point ECP at — skipping ECP test"
  fi
else
  echo "ECP not found in ./ecp/ — skipping"
  echo "Contents of current dir:"
  ls -la
fi
echo ""

echo "--- Step 8: TPM persistent handles ---"
tpm2_getcap handles-persistent 2>/dev/null || echo "(none)"

exit $RC
