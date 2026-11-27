#!/usr/bin/env bash
# Quick Test Script — edit this file, commit & push to run on the
# runner specified in .github/quick-test-config.json
#
# Environment available:
#   - wif-bunker installed in .venv (if install_wif_bunker=true)
#   - TPM reset to clean state (if setup_tpm=true, hardware-tpm only)
#   - GCP auth via WIF (GOOGLE_APPLICATION_CREDENTIALS set)
#
# The "Environment dump" and "Post-run diagnostics" steps run
# automatically before/after this script — no need to add them here.

set -uo pipefail  # no -e: we want to see ALL output even if something fails
RC=0

echo "=== Quick Test: WIF Bunker v2 (Pure-Python OIDC WIF) ==="
echo ""

echo "--- Step 1: wif-bunker versions ---"
wif-bunker versions || { echo "FAIL: wif-bunker versions"; RC=1; }
echo ""

echo "--- Step 2: TPM persistent handles ---"
if command -v tpm2_getcap &>/dev/null; then
  tpm2_getcap handles-persistent 2>&1 || true
else
  echo "(tpm2_getcap not installed on this runner)"
fi

exit $RC
