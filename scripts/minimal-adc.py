"""Minimal ADC test — proves Application Default Credentials work.

Authenticates via ADC, makes a real API call to the target project,
and introspects the access token to discover the federated principal.
"""

import sys

import google.auth
import google.auth.exceptions
import google.auth.transport.requests
import requests.exceptions


def main() -> int:
    # Load ADC
    try:
        creds, project = google.auth.default(
            scopes=[
                "https://www.googleapis.com/auth/cloud-platform",
                "email",
            ],
        )
    except google.auth.exceptions.DefaultCredentialsError as exc:
        print(
            f"❌ No Google credentials found: {exc}\n"
            "   Run `gcloud auth application-default login` or set "
            "GOOGLE_APPLICATION_CREDENTIALS.",
            file=sys.stderr,
        )
        return 1

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
        try:
            resp = authed_session.get(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}",
            )
        except google.auth.exceptions.OAuthError as exc:
            print(
                f"❌ WIF token exchange failed — the pool or provider may "
                f"not exist, may be disabled, or may have been deleted.\n"
                f"   {exc}",
                file=sys.stderr,
            )
            return 1
        except google.auth.exceptions.RefreshError as exc:
            print(
                f"❌ Credential refresh failed: {exc}",
                file=sys.stderr,
            )
            return 1
        except google.auth.exceptions.TransportError as exc:
            print(
                f"❌ Network/mTLS transport error: {exc}",
                file=sys.stderr,
            )
            return 1
        except requests.exceptions.ConnectionError as exc:
            print(
                f"❌ Connection error: {exc}",
                file=sys.stderr,
            )
            return 1

        if resp.ok:
            proj_info = resp.json()
            print(f"Project name:   {proj_info.get('name')}")
            print(f"Project number: {proj_info.get('projectNumber')}")
            print(f"Lifecycle:      {proj_info.get('lifecycleState')}")
        else:
            print(f"API call failed: {resp.status_code} {resp.text[:200]}")

    # ── Introspect the access token for identity info ──
    print("\n--- Identity ---")
    try:
        creds.refresh(google.auth.transport.requests.Request())
    except google.auth.exceptions.OAuthError as exc:
        print(
            f"❌ WIF token exchange failed during refresh — the pool or "
            f"provider may not exist, may be disabled, or may have been "
            f"deleted.\n   {exc}",
            file=sys.stderr,
        )
        return 1
    except google.auth.exceptions.RefreshError as exc:
        print(f"❌ Credential refresh failed: {exc}", file=sys.stderr)
        return 1
    except google.auth.exceptions.TransportError as exc:
        print(f"❌ Network error during token refresh: {exc}", file=sys.stderr)
        return 1

    token = creds.token

    # Use Google's tokeninfo endpoint to discover the principal
    try:
        token_resp = authed_session.get(
            f"https://oauth2.googleapis.com/tokeninfo?access_token={token}",
        )
    except requests.exceptions.RequestException as exc:
        print(f"Token introspection request failed: {exc}", file=sys.stderr)
        return 1

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
