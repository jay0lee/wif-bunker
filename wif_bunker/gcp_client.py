from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
import time
from typing import Any, ClassVar

import google.auth
import requests
from google.auth.transport.requests import Request as GoogleAuthRequest

from wif_bunker.config import LRO_TIMEOUT_SECONDS, MAX_BACKOFF_SECONDS
from wif_bunker.utils import with_retries

logger = logging.getLogger(__name__)


class GCPClient:
    """Thread-safe GCP API client.

    Supports two authentication modes:
    - **3-legged OAuth** (default): Opens a browser for user consent.
    - **ADC** (``use_adc=True``): Uses Application Default Credentials,
      e.g. from ``google-github-actions/auth`` or ``gcloud auth``.
    """

    # Default OAuth client for this tool.  Users can override with
    # --client-secrets-file pointing to their own Desktop OAuth client.
    _DEFAULT_CLIENT_ID = "284409941921-t4ukaudpiagsbl51t3adqtkgb30gu93o.apps.googleusercontent.com"
    _DEFAULT_CLIENT_SECRET = "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"
    _OAUTH_SCOPES: ClassVar[list[str]] = [
        # Project CRUD + project-level IAM policy
        "https://www.googleapis.com/auth/cloudplatformprojects",
        # Service accounts, WIF pools & providers
        "https://www.googleapis.com/auth/iam",
        # API enablement (batchEnable)
        "https://www.googleapis.com/auth/service.management",
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
    ]

    def __init__(
        self,
        *,
        use_adc: bool = False,
        client_secrets_file: str | None = None,
    ) -> None:
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._token_lock = threading.Lock()

        if use_adc:
            self._credentials, _ = google.auth.default(
                scopes=self._OAUTH_SCOPES,
            )
            self._auth_request = GoogleAuthRequest()
            self._credentials.refresh(self._auth_request)
            self._token = None
            # Log the identity we're authenticated as.
            identity = getattr(self._credentials, "service_account_email", None) or getattr(
                self._credentials, "signer_email", None
            )
            if not identity:
                # For user credentials, check tokeninfo.
                try:
                    info = self.session.get(
                        "https://oauth2.googleapis.com/tokeninfo",
                        params={"access_token": self._credentials.token},
                    ).json()
                    identity = info.get("email", "unknown")
                except Exception:
                    identity = "unknown"
            logger.info("Authenticated via Application Default Credentials as: %s", identity)
        else:
            self._credentials = None
            self._token = self._oauth_user_token(client_secrets_file)

    def _oauth_user_token(self, client_secrets_file: str | None) -> str:
        """3-legged OAuth flow — returns a short-lived access token.

        1. Starts a local redirect server on a random port.
        2. Opens the browser to Google's consent page.
        3. If the redirect works, captures the code automatically.
        4. If it fails (SSH, firewall), the user pastes the redirect URL.
        5. Exchanges the code for an access token with access_type=online
           (no refresh token stored).
        """
        import http.server
        import secrets
        import urllib.parse
        import webbrowser

        # Load OAuth client config.
        if client_secrets_file:
            with open(client_secrets_file) as f:
                client_config = json.load(f)
            installed = client_config.get("installed", client_config.get("web", {}))
            client_id = installed["client_id"]
            client_secret = installed.get("client_secret", "")
        else:
            client_id = self._DEFAULT_CLIENT_ID
            client_secret = self._DEFAULT_CLIENT_SECRET

        # CSRF protection + PKCE (RFC 7636).
        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)  # 43-128 chars
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        auth_code = None

        # Start a local redirect server on a random port.
        class _RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self_handler):
                nonlocal auth_code
                qs = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self_handler.path).query,
                )
                if qs.get("state", [None])[0] == state:
                    auth_code = qs.get("code", [None])[0]
                self_handler.send_response(200)
                self_handler.send_header("Content-Type", "text/html")
                self_handler.end_headers()
                self_handler.wfile.write(
                    b"<h2>Authorization complete.</h2><p>You may close this window and return to the terminal.</p>"
                )

            def log_message(self_handler, *args):
                pass  # Suppress request logging.

        server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        port = server.server_address[1]
        redirect_uri = f"http://localhost:{port}"

        # Build the authorization URL with PKCE.
        auth_params = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(self._OAUTH_SCOPES),
                "state": state,
                "access_type": "online",  # No refresh token.
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{auth_params}"

        # Google Workspace orgs may block untrusted OAuth apps (OWL).
        # Prompt the admin to allowlist the client ID before proceeding.
        logger.info("=" * 70)
        logger.info("If you are using a Google Workspace account, you may need to")
        logger.info("allowlist WIF Bunker's OAuth client before you can authorize.")
        logger.info("")
        logger.info("  1. Open the Admin Console API Controls page:")
        logger.info("     https://admin.google.com/ac/owl")
        logger.info("  2. Click 'Add app' → 'OAuth App Name Or Client ID'")
        logger.info("  3. Search for client ID:")
        logger.info("     %s", client_id)
        logger.info("  4. Select 'WIF Bunker' and set access to 'Trusted'")
        logger.info("")
        logger.info("Consumer Gmail accounts can skip this step.")
        logger.info("=" * 70)
        input("Press Enter to open the browser for authorization...")
        logger.info("")
        logger.info("Opening browser for authorization...")
        logger.info("If the browser doesn't open, visit this URL:")
        logger.info("  %s", auth_url)
        logger.info("")
        logger.info(
            "If you see a 'page not found' error after authorizing,\n"
            "    copy the FULL URL from the address bar and paste it here.\n"
            "    You can also paste just the authorization code."
        )

        # Try to open the browser.
        try:
            webbrowser.open(auth_url)
        except Exception:
            pass  # User will use the printed URL.

        # Wait for the auth code from either source:
        #   1. Local server catches the redirect automatically
        #   2. User pastes the redirect URL into stdin
        # Two daemon threads race; whichever gets the code first wins.
        code_event = threading.Event()

        def _serve_until_code():
            nonlocal auth_code
            server.timeout = 1
            while not code_event.is_set():
                server.handle_request()

        def _read_stdin_for_code():
            nonlocal auth_code
            while not code_event.is_set():
                try:
                    pasted = input().strip()
                except (EOFError, OSError):
                    return
                if pasted and not code_event.is_set():
                    # Accept either a full redirect URL or a raw code.
                    if "code=" in pasted:
                        qs = urllib.parse.parse_qs(
                            urllib.parse.urlparse(pasted).query,
                        )
                        code_list = qs.get("code")
                        if code_list:
                            auth_code = code_list[0]
                            code_event.set()
                            return
                    elif pasted.startswith("4/"):
                        # Raw Google auth codes start with "4/"
                        auth_code = pasted
                        code_event.set()
                        return

        # Patch the handler to signal the event when code is captured.
        orig_do_GET = _RedirectHandler.do_GET

        def _signaling_do_GET(self_handler):
            orig_do_GET(self_handler)
            if auth_code:
                code_event.set()

        _RedirectHandler.do_GET = _signaling_do_GET

        server_thread = threading.Thread(target=_serve_until_code, daemon=True)
        stdin_thread = threading.Thread(target=_read_stdin_for_code, daemon=True)
        server_thread.start()
        stdin_thread.start()

        code_event.wait()  # Blocks until either thread captures the code.
        server.server_close()

        if not auth_code:
            raise RuntimeError("Failed to obtain authorization code.")

        # Exchange the code for an access token (no refresh token).
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": auth_code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        access_token = token_data["access_token"]
        logger.info("    Authenticated successfully (token expires in %ss).", token_data.get("expires_in", "?"))
        return access_token

    def __enter__(self) -> GCPClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.session.close()

    @with_retries(max_attempts=10, expected_errors=(403, 404))
    def api_call(
        self,
        method: str,
        url: str,
        json_payload: dict | None = None,
    ) -> dict | None:
        if self._credentials:
            # ADC mode — auto-refresh and apply credentials.
            self._credentials.refresh(self._auth_request)
            headers = {}
            self._credentials.apply(headers)
        else:
            # OAuth mode — use the static short-lived token.
            headers = {"Authorization": f"Bearer {self._token}"}
        res = self.session.request(method, url, json=json_payload, headers=headers)
        res.raise_for_status()
        return res.json() if res.content else None

    def wait_for_lro(
        self,
        api_domain: str,
        op_name: str,
        timeout: int = LRO_TIMEOUT_SECONDS,
    ) -> dict:
        """Polls a Long-Running Operation until done, with a hard timeout."""
        url = f"https://{api_domain}/v1/{op_name}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            op_data = self.api_call("GET", url)
            if op_data and op_data.get("done"):
                return op_data
            time.sleep(2)
        raise TimeoutError(f"LRO {op_name} did not complete within {timeout}s")

    def wait_for_wif_resource(self, url: str, max_attempts: int = 12) -> dict:
        """Polls a WIF resource until it reaches ACTIVE state."""
        for attempt in range(max_attempts):
            data = self.api_call("GET", url)
            if data and data.get("state") == "ACTIVE":
                return data
            sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
            logger.debug(
                "WIF resource not ACTIVE yet (attempt %d/%d), sleeping %ds",
                attempt + 1,
                max_attempts,
                sleep_time,
            )
            time.sleep(sleep_time)
        raise TimeoutError(f"WIF resource at {url} did not become ACTIVE within {max_attempts} attempts")
