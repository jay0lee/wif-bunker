"""GCP API client: OAuth browser flow, ADC credentials, and REST helpers."""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import logging
import threading
import time
from typing import Any, ClassVar

import google.auth
import requests
from google.auth.exceptions import TransportError
from google.auth.transport.requests import Request as GoogleAuthRequest

from wif_bunker.config import API_RETRY_ATTEMPTS, LRO_TIMEOUT_SECONDS, MAX_BACKOFF_SECONDS

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
                    logger.debug("Failed to get email from ADC token", exc_info=True)
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
            with open(client_secrets_file, encoding="utf-8") as cfg_file:
                client_config = json.load(cfg_file)
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
            def do_GET(self_handler):  # pylint: disable=invalid-name,no-self-argument
                """Handle the OAuth redirect callback."""
                nonlocal auth_code
                query_string = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self_handler.path).query,
                )
                if query_string.get("state", [None])[0] == state:
                    auth_code = query_string.get("code", [None])[0]
                self_handler.send_response(200)
                self_handler.send_header("Content-Type", "text/html")
                self_handler.end_headers()
                self_handler.wfile.write(
                    b"<h2>Authorization complete.</h2><p>You may close this window and return to the terminal.</p>"
                )

            def log_message(self_handler, *args):  # pylint: disable=no-self-argument,arguments-differ
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
            logger.debug("Failed to open web browser", exc_info=True)

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
                        query_string = urllib.parse.parse_qs(
                            urllib.parse.urlparse(pasted).query,
                        )
                        code_list = query_string.get("code")
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
        orig_do_get = _RedirectHandler.do_GET

        def _signaling_do_get(self_handler):  # pylint: disable=invalid-name
            orig_do_get(self_handler)
            if auth_code:
                code_event.set()

        _RedirectHandler.do_GET = _signaling_do_get  # pylint: disable=invalid-name

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
            timeout=60,
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

    def api_call(
        self,
        method: str,
        url: str,
        json_payload: dict | None = None,
    ) -> dict | None:
        """Make a single authenticated GCP API call — no retries."""
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

    def api_call_with_iam_retry(
        self,
        method: str,
        url: str,
        json_payload: dict | None = None,
        max_attempts: int = API_RETRY_ATTEMPTS,
    ) -> dict | None:
        """api_call with retry on transient errors.

        Retries on:
          - HTTP 403 (IAM propagation delay after project/API setup)
          - HTTP 404 (newly created resource not yet visible)
          - ConnectionError / ConnectionResetError (transient network)
          - google.auth TransportError (STS/mTLS handshake reset)
        """
        # Extract a human-readable API name from the URL for log messages
        # e.g. "POST iam.googleapis.com/.../serviceAccounts"
        api_label = url.split("//")[-1] if "//" in url else url
        for attempt in range(max_attempts):
            try:
                return self.api_call(method, url, json_payload)
            except requests.exceptions.HTTPError as exc:
                if exc.response is not None and exc.response.status_code in (403, 404) and attempt < max_attempts - 1:
                    sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
                    logger.info(
                        "    Waiting for IAM/resource propagation (%d/%d), %ds... [%s %s]",
                        attempt + 1,
                        max_attempts,
                        sleep_time,
                        method,
                        api_label,
                    )
                    time.sleep(sleep_time)
                    continue
                raise
            except (requests.exceptions.ConnectionError, TransportError, OSError) as exc:
                if attempt < max_attempts - 1:
                    sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
                    logger.warning(
                        "    Transient connection error (%d/%d), retrying in %ds: %s [%s %s]",
                        attempt + 1,
                        max_attempts,
                        sleep_time,
                        exc,
                        method,
                        api_label,
                    )
                    time.sleep(sleep_time)
                    continue
                raise
        return None  # unreachable, but satisfies type checker

    def wait_for_lro(
        self,
        api_domain: str,
        op_name: str,
        timeout: int = LRO_TIMEOUT_SECONDS,
    ) -> dict:
        """Polls a Long-Running Operation until done, with a hard timeout.

        Raises RuntimeError if the completed operation contains an error
        (e.g. quota exceeded, permission denied).
        """
        url = f"https://{api_domain}/v1/{op_name}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            op_data = self.api_call("GET", url)
            if op_data and op_data.get("done"):
                if "error" in op_data:
                    err = op_data["error"]
                    code = err.get("code", "?")
                    msg = err.get("message", "unknown error")
                    raise RuntimeError(
                        f"LRO {op_name} failed (code {code}): {msg}"
                    )
                return op_data
            time.sleep(2)
        raise TimeoutError(f"LRO {op_name} did not complete within {timeout}s")

    def wait_for_wif_resource(self, url: str, max_attempts: int = API_RETRY_ATTEMPTS) -> dict:
        """Polls a WIF resource until it reaches ACTIVE state."""
        api_label = url.split("//")[-1] if "//" in url else url
        for attempt in range(max_attempts):
            try:
                data = self.api_call("GET", url)
            except requests.exceptions.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 404 and attempt < max_attempts - 1:
                    sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
                    logger.debug(
                        "WIF resource not found yet (attempt %d/%d), sleeping %ds [GET %s]",
                        attempt + 1,
                        max_attempts,
                        sleep_time,
                        api_label,
                    )
                    time.sleep(sleep_time)
                    continue
                raise
            if data and data.get("state") == "ACTIVE":
                return data
            sleep_time = min(2**attempt, MAX_BACKOFF_SECONDS)
            logger.debug(
                "WIF resource not ACTIVE yet (attempt %d/%d), sleeping %ds [GET %s]",
                attempt + 1,
                max_attempts,
                sleep_time,
                api_label,
            )
            time.sleep(sleep_time)
        raise TimeoutError(f"WIF resource at {url} did not become ACTIVE within {max_attempts} attempts")

    def ensure_project(self, project_id: str, folder: str | None = None) -> str:
        """Create or reuse GCP project.

        1. GET the project — if it exists, return its number immediately.
        2. If 403/404, the project doesn't exist — create it.
        3. POST returns an LRO; poll until done.
        4. GET the project number (with brief propagation retry).
        """
        crm_base = "cloudresourcemanager.googleapis.com"
        project_url = f"https://{crm_base}/v1/projects/{project_id}"

        # Step 1: check if the project already exists (no retry — 403/404 is the answer).
        try:
            return self.api_call("GET", project_url)["projectNumber"]
        except requests.exceptions.HTTPError as exc:
            if exc.response is not None and exc.response.status_code in (403, 404):
                pass  # Project doesn't exist — create it below.
            else:
                raise

        # Step 2: create the project.
        create_payload = {
            "projectId": project_id,
            "name": "WIF Bunker",
        }
        if folder:
            create_payload["parent"] = {
                "type": "folder",
                "id": folder,
            }
            logger.info("    Parent folder: %s", folder)

        try:
            operation = self.api_call(
                "POST",
                f"https://{crm_base}/v1/projects",
                create_payload,
            )
            self.wait_for_lro(crm_base, operation["name"])
        except requests.exceptions.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 409:
                logger.info("    Project already exists (409), reusing.")
            else:
                raise

        # Step 3: fetch project number (retry for IAM propagation after creation).
        result = self.api_call_with_iam_retry("GET", project_url)
        return result["projectNumber"]

    def enable_apis(self, project_number: str, api_list: list[str]) -> None:
        """Batch-enables the given APIs for the project."""
        su_base = "serviceusage.googleapis.com"
        operation = self.api_call_with_iam_retry(
            "POST",
            f"https://{su_base}/v1/projects/{project_number}/services:batchEnable",
            {"serviceIds": api_list},
        )
        self.wait_for_lro(su_base, operation["name"])

    def setup_wif_infrastructure(
        self,
        config: Any,
        project_number: str,
        cert_bundle: Any,
        reuse_pool: bool,
        use_sa: bool,
        sa_email: str | None = None,
        sa_name: str | None = None,
    ) -> tuple[str | None, str]:
        """Creates SA, WIF Pool, and WIF Provider in parallel."""
        iam_base = "iam.googleapis.com"
        pool_res_url = (
            f"https://{iam_base}/v1/projects/{project_number}/locations/global/workloadIdentityPools/{config.pool_id}"
        )
        provider_res_url = f"{pool_res_url}/providers/{config.provider_id}"

        def create_sa_task() -> str:
            logger.info("[Thread] Creating Service Account...")
            try:
                result = self.api_call_with_iam_retry(
                    "POST",
                    f"https://{iam_base}/v1/projects/{config.project_id}/serviceAccounts",
                    {
                        "accountId": sa_name or config.sa_name,
                        "serviceAccount": {"displayName": "WIF Bunker SA"},
                    },
                )
                return result["email"]
            except requests.exceptions.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 409:
                    email = f"{sa_name or config.sa_name}@{config.project_id}.iam.gserviceaccount.com"
                    logger.info("    SA already exists: %s", email)
                    return email
                raise

        def create_pool_task() -> None:
            logger.info("[Thread] Creating WIF Pool...")
            try:
                pool_op = self.api_call_with_iam_retry(
                    "POST",
                    f"https://{iam_base}/v1/projects/{project_number}"
                    f"/locations/global/workloadIdentityPools"
                    f"?workloadIdentityPoolId={config.pool_id}",
                    {"displayName": "WIF Bunker Pool", "disabled": False},
                )
                self.wait_for_lro(iam_base, pool_op["name"])
            except requests.exceptions.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 409:
                    logger.info("    Pool already exists: %s", config.pool_id)
                else:
                    raise
            self.wait_for_wif_resource(pool_res_url)

        def create_provider_task() -> None:
            if reuse_pool:
                try:
                    provs = self.api_call(
                        "GET",
                        f"{pool_res_url}/providers",
                    ).get("workloadIdentityPoolProviders", [])
                    for prov in provs:
                        pname = prov["name"].split("/")[-1]
                        if pname.startswith("bunker-x509-prov-") and pname != config.provider_id:
                            logger.info("    Deleting stale provider: %s", pname)
                            try:
                                del_op = self.api_call("DELETE", f"{pool_res_url}/providers/{pname}")
                                self.wait_for_lro(iam_base, del_op["name"])
                            except Exception:
                                logger.debug("Failed to delete stale provider", exc_info=True)
                except Exception:
                    logger.debug("Failed to list/delete providers", exc_info=True)

            cert_pin_condition = f'assertion.sha256Fingerprint == "{cert_bundle.sha256_fingerprint}"'
            logger.info("    Cert pin condition: %s", cert_pin_condition)
            provider_payload = {
                "displayName": "WIF Bunker X.509 Provider",
                "x509": {
                    "trustStore": {
                        "trustAnchors": [
                            {"pemCertificate": cert_bundle.trust_anchor_pem},
                        ],
                    },
                },
                "attributeMapping": {"google.subject": "assertion.subject.dn.cn"},
                "attributeCondition": cert_pin_condition,
            }

            if reuse_pool:
                logger.info("[Thread] Reusing WIF pool: %s", config.pool_id)

            logger.info("[Thread] Creating WIF X.509 Provider: %s", config.provider_id)
            prov_op = self.api_call_with_iam_retry(
                "POST",
                f"{pool_res_url}/providers?workloadIdentityPoolProviderId={config.provider_id}",
                provider_payload,
            )
            self.wait_for_lro(iam_base, prov_op["name"])
            self.wait_for_wif_resource(provider_res_url)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            if use_sa and not sa_email:
                futures.append(("sa", executor.submit(create_sa_task)))
            if not reuse_pool:
                futures.append(("pool", executor.submit(create_pool_task)))
            for tag, fut in futures:
                result = fut.result()
                if tag == "sa":
                    sa_email = result

        # Provider must be created after pool exists.
        create_provider_task()

        return sa_email, config.provider_id

    def apply_iam_bindings(
        self,
        config: Any,
        project_number: str,
        workload_cn: str,
        pool_id: str,
        sa_email: str | None = None,
        use_sa: bool = True,
    ) -> None:
        """Applies SA and project-level IAM bindings."""
        crm_base = "cloudresourcemanager.googleapis.com"
        iam_base = "iam.googleapis.com"

        wif_principal = (
            f"principal://iam.googleapis.com/projects/{project_number}"
            f"/locations/global/workloadIdentityPools/{pool_id}"
            f"/subject/{workload_cn}"
        )

        if use_sa and sa_email:
            sa_iam_url = f"https://{iam_base}/v1/projects/{config.project_id}/serviceAccounts/{sa_email}:setIamPolicy"
            sa_policy = self.api_call_with_iam_retry(
                "POST",
                sa_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
            )
            if sa_policy is None:
                sa_policy = {}
            sa_policy.setdefault("bindings", []).append(
                {"role": "roles/iam.workloadIdentityUser", "members": [wif_principal]},
            )
            self.api_call_with_iam_retry("POST", sa_iam_url, {"policy": sa_policy})

        proj_iam_url = f"https://{crm_base}/v1/projects/{config.project_id}:setIamPolicy"
        proj_policy = self.api_call_with_iam_retry(
            "POST",
            proj_iam_url.replace(":setIamPolicy", ":getIamPolicy"),
        )
        if proj_policy is None:
            proj_policy = {}
        if use_sa and sa_email:
            proj_member = f"serviceAccount:{sa_email}"
        else:
            proj_member = wif_principal
        proj_policy.setdefault("bindings", []).append(
            {"role": "roles/browser", "members": [proj_member]},
        )
        self.api_call_with_iam_retry("POST", proj_iam_url, {"policy": proj_policy})
