"""Minimal ADC test — proves Application Default Credentials work.

Authenticates via ADC, makes a real API call to the target project,
and introspects the access token to discover the federated principal.

Retries transient errors (RefreshError, TransportError, ConnectionError)
with exponential backoff.  Permanent errors (DefaultCredentialsError,
OAuthError) fail immediately.
"""

import argparse
import re
import sys
import time

import google.auth
import google.auth.exceptions
import google.auth.transport.requests
import requests.exceptions

# Retry config
MAX_RETRIES = 6
INITIAL_BACKOFF = 5  # seconds

# Whether to redact tokens in output (set via --no-redact flag)
_REDACT = True


def redact_token_value(text: str) -> str:
    """Replace access-token values in JSON-like text and URLs with ***REDACTED***."""
    # JSON pattern: "access_token": "<value>"
    text = re.sub(
        r'("access_token"\s*:\s*)"[^"]+"',
        r'\1"***REDACTED***"',
        text,
    )
    # URL query-string pattern: access_token=<value>
    text = re.sub(
        r'(access_token=)[^&\s"]+',
        r"\1***REDACTED***",
        text,
    )
    return text


def _print(*args, **kwargs):
    """Print wrapper that applies token redaction unless --no-redact is set."""
    if _REDACT:
        args = tuple(redact_token_value(str(a)) for a in args)
    print(*args, **kwargs)


def _retry(func, *, description):
    """Call *func* with exponential backoff on transient google-auth errors.

    Retries on:
      - RefreshError  (token refresh / IAM propagation)
      - TransportError (network / mTLS)
      - ConnectionError (TCP-level)

    Fails immediately on:
      - OAuthError (invalid pool/provider — permanent)
      - DefaultCredentialsError (no creds configured — permanent)
    """
    backoff = INITIAL_BACKOFF
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func()
        except google.auth.exceptions.OAuthError as exc:
            # Permanent — bad audience / deleted pool
            _print(
                f"❌ {description}: WIF token exchange failed — the pool or "
                f"provider may not exist, may be disabled, or may have been "
                f"deleted.\n   {exc}",
                file=sys.stderr,
            )
            sys.exit(1)
        except google.auth.exceptions.RefreshError as exc:
            if attempt == MAX_RETRIES:
                _print(
                    f"❌ {description}: Credential refresh failed after {MAX_RETRIES} attempts: {exc}", file=sys.stderr
                )
                sys.exit(1)
            _print(f"  ⏳ {description}: Refresh failed (attempt {attempt}/{MAX_RETRIES}), retrying in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        except google.auth.exceptions.TransportError as exc:
            if attempt == MAX_RETRIES:
                _print(f"❌ {description}: Transport error after {MAX_RETRIES} attempts: {exc}", file=sys.stderr)
                sys.exit(1)
            _print(f"  ⏳ {description}: Transport error (attempt {attempt}/{MAX_RETRIES}), retrying in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        except requests.exceptions.ConnectionError as exc:
            if attempt == MAX_RETRIES:
                _print(f"❌ {description}: Connection error after {MAX_RETRIES} attempts: {exc}", file=sys.stderr)
                sys.exit(1)
            _print(f"  ⏳ {description}: Connection error (attempt {attempt}/{MAX_RETRIES}), retrying in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
    # Unreachable, but keeps type checkers happy
    sys.exit(1)


def main() -> int:
    # Load ADC — not retryable (configuration error)
    try:
        creds, project = google.auth.default(
            scopes=[
                "https://www.googleapis.com/auth/cloud-platform",
                "email",
            ],
        )
    except google.auth.exceptions.DefaultCredentialsError as exc:
        _print(
            f"❌ No Google credentials found: {exc}\n"
            "   Run `gcloud auth application-default login` or set "
            "GOOGLE_APPLICATION_CREDENTIALS.",
            file=sys.stderr,
        )
        return 1

    authed_session = google.auth.transport.requests.AuthorizedSession(creds)

    # Print what we know about the credentials
    cred_type = type(creds)
    _print(f"Credential type: {cred_type.__module__}.{cred_type.__name__}")
    sa_email = getattr(creds, "service_account_email", None)
    if sa_email:
        _print(f"Service account: {sa_email}")
    if project:
        _print(f"Project: {project}")

    # ── Verify ADC works: call the target project ──
    if project:
        _print("\n--- API Verification ---")

        resp = _retry(
            lambda: authed_session.get(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}",
            ),
            description="API verification",
        )

        if resp.ok:
            proj_info = resp.json()
            _print(f"Project name:   {proj_info.get('name')}")
            _print(f"Project number: {proj_info.get('projectNumber')}")
            _print(f"Lifecycle:      {proj_info.get('lifecycleState')}")
        else:
            _print(f"API call failed: {resp.status_code} {resp.text[:200]}")

    # ── Introspect the access token for identity info ──
    _print("\n--- Identity ---")

    _retry(
        lambda: creds.refresh(google.auth.transport.requests.Request()),
        description="Token refresh",
    )

    token = creds.token

    # Use Google's tokeninfo endpoint to discover the principal
    tokeninfo_url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
    try:
        token_resp = authed_session.get(tokeninfo_url)
    except requests.exceptions.RequestException as exc:
        _print(f"Token introspection request failed: {exc}", file=sys.stderr)
        return 1

    if token_resp.ok:
        info = token_resp.json()
        if info.get("email"):
            _print(f"Email:   {info['email']}")
        if info.get("sub"):
            _print(f"Subject: {info['sub']}")
        if info.get("azp"):
            _print(f"Azp:     {info['azp']}")
        if info.get("scope"):
            _print(f"Scopes:  {info['scope']}")
        exp = info.get("expires_in")
        if exp:
            _print(f"Expires: {exp}s")
    else:
        _print(f"Token introspection failed: {token_resp.status_code}")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable token redaction in output",
    )
    args = parser.parse_args()
    _REDACT = not args.no_redact
    sys.exit(main())
