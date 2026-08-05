"""Minimal ADC test — proves Application Default Credentials work.

Authenticates via ADC, makes a real API call to the target project,
and introspects the access token to discover the federated principal.
"""

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
if project:
    print(f"Project: {project}")

# ── Verify ADC works: call the target project ──
if project:
    print("\n--- API Verification ---")
    resp = authed_session.get(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}",
    )
    if resp.ok:
        proj_info = resp.json()
        print(f"Project name:   {proj_info.get('name')}")
        print(f"Project number: {proj_info.get('projectNumber')}")
        print(f"Lifecycle:      {proj_info.get('lifecycleState')}")
    else:
        print(f"API call failed: {resp.status_code} {resp.text[:200]}")

# ── Introspect the access token for identity info ──
print("\n--- Identity ---")
# Ensure we have a fresh token
creds.refresh(google.auth.transport.requests.Request())
token = creds.token

# Use Google's tokeninfo endpoint to discover the principal
token_resp = authed_session.get(
    f"https://oauth2.googleapis.com/tokeninfo?access_token={token}",
)
if token_resp.ok:
    info = token_resp.json()
    # WIF tokens have 'sub' (subject) and may have 'email'
    if info.get("email"):
        print(f"Email:   {info['email']}")
    if info.get("sub"):
        print(f"Subject: {info['sub']}")
    if info.get("azp"):
        print(f"Azp:     {info['azp']}")
    if info.get("scope"):
        print(f"Scopes:  {info['scope']}")
    exp = info.get("expires_in")
    if exp:
        print(f"Expires: {exp}s")
else:
    print(f"Token introspection failed: {token_resp.status_code}")
