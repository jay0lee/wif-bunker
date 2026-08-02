"""Minimal ADC test — proves Application Default Credentials work."""
import google.auth
import google.auth.transport.requests
from google.auth.external_account import Credentials as ExternalAccountCredentials

# Load ADC — google-auth auto-creates mTLS transport for hw-backed keys
creds, project = google.auth.default(
    scopes=["https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/userinfo.email"],
)
authed_session = google.auth.transport.requests.AuthorizedSession(creds)
print(f"Credential type: {type(creds).__name__}")

# Identity check — bare WIF principals (no SA impersonation) can't call tokeninfo;
# all other credential types (user, service account, SA-impersonated WIF) can.
is_bare_wif = (isinstance(creds, ExternalAccountCredentials)
               and creds.service_account_email is None)
if is_bare_wif:
    print(f"Authenticated as: WIF principal (no SA impersonation)")
    print(f"  Token present: {bool(creds.token)}")
else:
    resp = authed_session.get(
        f"https://oauth2.googleapis.com/tokeninfo?access_token={creds.token}",
    )
    info = resp.json()
    print(f"Authenticated as: {info.get('email', 'unknown')}")
    print(f"  Scope:   {info.get('scope', '')}")
    print(f"  Expires: {info.get('expires_in', '?')}s")

# Smoke test: list accessible projects
resp = authed_session.get(
    "https://cloudresourcemanager.googleapis.com/v1/projects",
)
projects = resp.json().get("projects", [])
print(f"\nAccessible projects ({len(projects)}):")
for p in projects:
    print(f"  {p['projectId']}  {p.get('name', '')}")
