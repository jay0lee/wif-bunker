"""Minimal ADC test — proves Application Default Credentials work.

Uses the '403 trick' to discover the federated principal identity:
requesting a non-existent project returns a 403 whose error message
contains the exact principal string.
"""

import re

import google.auth
import google.auth.transport.requests

# Load and use ADC
creds, project = google.auth.default(
    scopes=["https://www.googleapis.com/auth/cloud-platform"],
)
authed_session = google.auth.transport.requests.AuthorizedSession(creds)

# Print what we know about the credentials
cred_type = type(creds)
print(f"Credential type: {cred_type.__module__}.{cred_type.__name__}")
sa_email = getattr(creds, "service_account_email", None)
if sa_email:
    print(f"Service account: {sa_email}")

# ── "Who am I?" via the 403 trick ──
# Request a project that doesn't exist. GCP's IAM evaluation returns a
# 403 whose error message leaks the exact principal string, e.g.:
#   "Permission denied: Principal principal://iam.googleapis.com/projects/
#    123/locations/global/workloadIdentityPools/pool/subject/..."
print("\n--- Identity Check (403 trick) ---")
resp = authed_session.get(
    "https://cloudresourcemanager.googleapis.com/v1/projects/wif-bunker-identity-check-00000",
)
if resp.status_code == 403:
    error_msg = resp.json().get("error", {}).get("message", "")
    # Extract the principal:// URI from the error message
    match = re.search(r"principal://\S+", error_msg)
    if match:
        principal = match.group(0).rstrip(".")
        print(f"Authenticated as: {principal}")

        # Parse out the useful parts
        parts = re.match(
            r"principal://iam\.googleapis\.com/projects/(?P<project_number>[^/]+)"
            r"/locations/(?P<location>[^/]+)"
            r"/workloadIdentityPools/(?P<pool>[^/]+)"
            r"/subject/(?P<subject>.+)",
            principal,
        )
        if parts:
            print(f"  Project number:  {parts.group('project_number')}")
            print(f"  WIF Pool:        {parts.group('pool')}")
            print(f"  Subject:         {parts.group('subject')}")
    else:
        print(f"403 but could not parse principal from: {error_msg}")
elif resp.status_code == 404:
    print("Got 404 (not 403) — identity has broad project access, cannot extract principal.")
    print("This typically means you're using a service account, not WIF.")
else:
    print(f"Unexpected status {resp.status_code}: {resp.text[:200]}")
