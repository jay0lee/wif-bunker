"""Minimal ADC test for hardware-backed X.509 Workload Identity Federation.

Prerequisites:
  - google-auth patched for hardware-backed keys (no key_path)
  - Environment variables set:
      GOOGLE_APPLICATION_CREDENTIALS=path/to/adc.json
      GOOGLE_API_USE_CLIENT_CERTIFICATE=true
      GOOGLE_API_CERTIFICATE_CONFIG=path/to/certificate_config.json
"""
import os, google.auth, requests
from google.auth.transport.requests import Request, _MutualTlsOffloadAdapter

# Verify env vars
for var in ["GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_API_USE_CLIENT_CERTIFICATE", "GOOGLE_API_CERTIFICATE_CONFIG"]:
    print(f"  {var}={os.environ.get(var, 'NOT SET')}")

# Set up mTLS session with ECP adapter
session = requests.Session()
session.mount("https://", _MutualTlsOffloadAdapter(os.environ["GOOGLE_API_CERTIFICATE_CONFIG"]))
mtls_request = Request(session=session)

# Load and refresh ADC
creds, _ = google.auth.default(
    scopes=[
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
    request=mtls_request,
)
creds.refresh(mtls_request)

# Verify this is actually an X.509 WIF credential, not GHA OIDC
cred_type = type(creds).__name__
print(f"\nCredential type: {cred_type}")
if "ExternalAccount" not in cred_type and "Impersonated" not in cred_type:
    print(f"ERROR: Expected ExternalAccountCredentials but got {cred_type}")
    print("This may be using GHA's OIDC credentials instead of X.509 WIF!")
    exit(1)
print(f"  ✓ Confirmed X.509 WIF credential (not GHA OIDC)")

# Token info — shows the authenticated identity
info = session.get(
    f"https://oauth2.googleapis.com/tokeninfo?access_token={creds.token}",
).json()
email = info.get("email", "unknown")
print(f"\nAuthenticated as: {email}")
print(f"  Scope:   {info.get('scope', '')}")
print(f"  Expires: {info.get('expires_in', '?')}s")

# If EXPECTED_SA_EMAIL is set, assert the identity matches
expected = os.environ.get("EXPECTED_SA_EMAIL")
if expected:
    if email == expected:
        print(f"  ✓ Identity matches expected SA: {expected}")
    else:
        print(f"  ✗ MISMATCH! Expected {expected}, got {email}")
        exit(1)

# List projects
resp = session.get(
    "https://cloudresourcemanager.googleapis.com/v1/projects",
    headers={"Authorization": f"Bearer {creds.token}"},
)
print(f"\nAccessible projects:")
for p in resp.json().get("projects", []):
    print(f"  {p['projectId']}  {p.get('name', '')}")
