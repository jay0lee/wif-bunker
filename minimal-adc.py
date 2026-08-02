"""Minimal ADC test — proves Application Default Credentials work."""
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

# Smoke test: list accessible projects
resp = authed_session.get(
    "https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState%3AACTIVE&pageSize=5",
)
projects = resp.json().get("projects", [])
print(f"\nAccessible projects ({len(projects)}):")
for p in projects:
    print(f"  {p['projectId']}  {p.get('name', '')}")
