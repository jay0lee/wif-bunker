"""Localhost token-caching agent for WIF Bunker.

Runs a lightweight HTTP server bound strictly to ``127.0.0.1`` that speaks the
standard RFC 8693 STS ``/v1/token`` protocol expected by Google Cloud's
``external_account`` ADC.

Key properties:
- **1 hardware signature per hour** across all local client processes (e.g.
  20 parallel GAM worker processes looping over thousands of users).
- **RAM-only token cache:** access tokens never touch disk.
- **Per-session authentication:** a random 256-bit secret is written to a
  ``0600`` file and validated via ``hmac.compare_digest`` on every request,
  blocking other local users on multi-user machines.
- **Zero client dependencies:** downstream clients (GAM, Terraform, Python, Go,
  Node, Java) use 100% stock ADC with plain HTTP to localhost — no ``hardmtls``,
  no shared OpenSSL, no custom ``google-auth`` fork.
"""

from __future__ import annotations

import hmac
import http.server
import json
import logging
import os
import secrets
import signal
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

import requests

from wif_bunker.config import DEFAULT_AGENT_REFRESH_MARGIN_SECONDS, BunkerConfig
from wif_bunker.oidc import build_agent_adc_config, mint_google_access_token
from wif_bunker.utils import write_secure_file

logger = logging.getLogger(__name__)

_DEFAULT_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)


class TokenCache:
    """Thread-safe, single-flight in-RAM cache of Google OAuth2 access tokens.

    Tokens are keyed by ``frozenset(scopes)``. A lock serializes cache misses
    so concurrent client workers trigger only a single hardware signature + STS
    exchange per hour.
    """

    def __init__(
        self,
        bunker_cfg: BunkerConfig,
        signer: Any,
        *,
        refresh_margin_seconds: int = DEFAULT_AGENT_REFRESH_MARGIN_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        self._bunker_cfg = bunker_cfg
        self._signer = signer
        self._refresh_margin = int(refresh_margin_seconds)
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        # Maps frozenset(scopes) -> (access_token, expiry_unix_timestamp)
        self._entries: dict[frozenset[str], tuple[str, int]] = {}
        self.hardware_signs: int = 0
        self.cache_hits: int = 0

    def get_token(self, scopes: list[str] | tuple[str, ...] | None = None) -> tuple[str, int]:
        """Return ``(access_token, remaining_seconds)`` for *scopes*, caching in RAM."""
        norm_scopes = frozenset(s for s in (scopes or _DEFAULT_SCOPES) if s)
        if not norm_scopes:
            norm_scopes = frozenset(_DEFAULT_SCOPES)

        now = int(time.time())
        with self._lock:
            cached = self._entries.get(norm_scopes)
            if cached is not None:
                token, expiry = cached
                remaining = expiry - now
                if remaining > self._refresh_margin:
                    self.cache_hits += 1
                    return token, remaining

            logger.info(
                "Cache miss for scopes [%s] — signing OIDC JWT with hardware key...",
                ", ".join(sorted(norm_scopes)),
            )
            token, expiry = mint_google_access_token(
                self._bunker_cfg,
                self._signer,
                scopes=sorted(norm_scopes),
                session=self._session,
            )
            self._entries[norm_scopes] = (token, expiry)
            self.hardware_signs += 1
            remaining = max(1, expiry - int(time.time()))
            logger.info(
                "Minted access token (expires in %ds; total hardware signs: %d)",
                remaining,
                self.hardware_signs,
            )
            return token, remaining

    def stats(self) -> dict[str, Any]:
        """Return non-sensitive cache diagnostics for ``GET /health``."""
        now = int(time.time())
        with self._lock:
            active = sum(1 for _, (_, exp) in self._entries.items() if exp > now)
            return {
                "status": "ok",
                "cached_scope_sets": active,
                "hardware_signs": self.hardware_signs,
                "cache_hits": self.cache_hits,
                "project_id": self._bunker_cfg.project_id,
                "service_account_email": self._bunker_cfg.service_account_email,
                "signer_type": self._bunker_cfg.signer.get("type", "unknown"),
            }

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()


def _parse_token_request_body(content_type: str, raw_body: bytes) -> dict[str, Any]:
    """Parse either JSON or ``application/x-www-form-urlencoded`` STS request bodies."""
    ctype = (content_type or "").split(";")[0].strip().lower()
    text = raw_body.decode("utf-8", errors="replace")
    if ctype == "application/json" or text.lstrip().startswith("{"):
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("Expected JSON object in token request body")
        return parsed
    # Form-urlencoded (RFC 8693 standard used by google-auth & Go oauth2)
    qs = urllib.parse.parse_qs(text, keep_blank_values=False)
    return {k: v[0] for k, v in qs.items() if v}


class AgentHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer carrying WIF Bunker agent state."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        token_cache: TokenCache,
        session_secret: str,
    ) -> None:
        self.token_cache = token_cache
        self.session_secret = session_secret
        super().__init__(server_address, _AgentRequestHandler)

    @property
    def port(self) -> int:
        """Actual bound TCP port."""
        return int(self.server_address[1])


class _AgentRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler implementing ``POST /v1/token`` and ``GET /health``."""

    server: AgentHTTPServer  # type: ignore[assignment]

    def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # pylint: disable=invalid-name
        """Serve non-sensitive health/status metadata at ``/health``."""
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, self.server.token_cache.stats())
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # pylint: disable=invalid-name
        """Serve RFC 8693 token exchange requests at ``/v1/token``."""
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/v1/token":
            self._send_json(404, {"error": "not_found"})
            return

        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length <= 0 or content_length > 65536:
            self._send_json(400, {"error": "invalid_request", "error_description": "Invalid Content-Length"})
            return

        raw_body = self.rfile.read(content_length)
        try:
            params = _parse_token_request_body(self.headers.get("Content-Type", ""), raw_body)
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json(400, {"error": "invalid_request", "error_description": str(exc)})
            return

        subject_token = str(params.get("subject_token", "")).strip()
        if not subject_token or not hmac.compare_digest(subject_token, self.server.session_secret):
            logger.warning("Rejected unauthorized /v1/token request from %s", self.client_address[0])
            self._send_json(401, {"error": "invalid_grant", "error_description": "Invalid session secret"})
            return

        scope_str = str(params.get("scope", "")).strip()
        scopes = scope_str.split() if scope_str else list(_DEFAULT_SCOPES)

        try:
            access_token, remaining = self.server.token_cache.get_token(scopes)
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            detail = exc.response.text[:300] if exc.response is not None else str(exc)
            logger.error("Upstream Google token exchange failed (HTTP %s): %s", status, detail)
            self._send_json(502, {"error": "upstream_error", "error_description": f"HTTP {status}: {detail}"})
            return
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Token minting failed: %s", exc)
            self._send_json(500, {"error": "server_error", "error_description": str(exc)})
            return

        self._send_json(
            200,
            {
                "access_token": access_token,
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": remaining,
            },
        )

    def log_message(self, format: str, *args: Any) -> None:  # pylint: disable=redefined-builtin
        """Route HTTP access logs through Python's logger at DEBUG level."""
        logger.debug("agent %s - %s", self.client_address[0], format % args)


def _default_secret_path(adc_path: Path) -> Path:
    """Choose a secure path for the ephemeral per-session secret file.

    Prefers ``$XDG_RUNTIME_DIR`` (RAM-backed ``tmpfs`` on Linux) when writable,
    falling back to a dotfile alongside ``adc.json``.
    """
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        runtime_dir = Path(xdg_runtime)
        if runtime_dir.is_dir() and os.access(runtime_dir, os.W_OK):
            return runtime_dir / f"wif-bunker-secret-{os.getpid()}"
    return adc_path.parent / f".wif-bunker-secret-{os.getpid()}"


def start_agent(
    bunker_cfg: BunkerConfig,
    signer: Any,
    *,
    port: int = 0,
    adc_path: Path | str = "adc.json",
    secret_path: Path | str | None = None,
    refresh_margin_seconds: int = DEFAULT_AGENT_REFRESH_MARGIN_SECONDS,
    eager_warm: bool = False,
) -> tuple[AgentHTTPServer, Path, Path]:
    """Bind the localhost agent server, write the ``0600`` secret and ``adc.json``.

    Returns:
        Tuple of ``(server, resolved_adc_path, resolved_secret_path)``.
    """
    resolved_adc = Path(adc_path).resolve()
    resolved_secret = Path(secret_path).resolve() if secret_path else _default_secret_path(resolved_adc)
    session_secret = secrets.token_urlsafe(32)

    cache = TokenCache(
        bunker_cfg,
        signer,
        refresh_margin_seconds=refresh_margin_seconds,
    )
    server = AgentHTTPServer(("127.0.0.1", int(port)), cache, session_secret)

    # Write 0600 session secret and updated adc.json
    write_secure_file(resolved_secret, session_secret)
    adc_dict = build_agent_adc_config(
        bunker_cfg,
        port=server.port,
        secret_file=resolved_secret,
    )
    write_secure_file(resolved_adc, json.dumps(adc_dict, indent=2) + "\n")

    if eager_warm:
        cache.get_token()

    return server, resolved_adc, resolved_secret


def _snapshot_executable_adc(adc_path: Path) -> str | None:
    """Return raw text of *adc_path* if it is a pre-existing executable ADC config."""
    if not adc_path.exists():
        return None
    try:
        raw = adc_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, dict) and "executable" in data.get("credential_source", {}):
            return raw
    except (OSError, json.JSONDecodeError):
        pass
    return None


def run_agent_foreground(
    bunker_cfg: BunkerConfig,
    signer: Any,
    *,
    port: int = 0,
    adc_path: Path | str = "adc.json",
    secret_path: Path | str | None = None,
    refresh_margin_seconds: int = DEFAULT_AGENT_REFRESH_MARGIN_SECONDS,
    eager_warm: bool = False,
) -> None:
    """Start the WIF Bunker agent in the foreground until interrupted."""
    resolved_adc_target = Path(adc_path).resolve()
    saved_executable_adc = _snapshot_executable_adc(resolved_adc_target)

    server, resolved_adc, resolved_secret = start_agent(
        bunker_cfg,
        signer,
        port=port,
        adc_path=resolved_adc_target,
        secret_path=secret_path,
        refresh_margin_seconds=refresh_margin_seconds,
        eager_warm=eager_warm,
    )

    logger.info("=" * 70)
    logger.info("WIF Bunker Agent listening on http://127.0.0.1:%d", server.port)
    logger.info("  ADC config:      %s", resolved_adc)
    logger.info("  Session secret:  %s (mode 0600)", resolved_secret)
    logger.info("  Signer:          %s", bunker_cfg.signer.get("type", "unknown"))
    if bunker_cfg.service_account_email:
        logger.info("  Service Account: %s", bunker_cfg.service_account_email)
    else:
        logger.info("  Identity:        Direct WIF (no service account)")
    logger.info("")
    logger.info("Point standard ADC clients at this agent:")
    logger.info("  export GOOGLE_APPLICATION_CREDENTIALS=%s", resolved_adc)
    logger.info("Press Ctrl+C to stop.")
    logger.info("=" * 70)

    def _handle_sigterm(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    prev_sigterm = None
    try:
        prev_sigterm = signal.signal(signal.SIGTERM, _handle_sigterm)
    except (ValueError, AttributeError):
        pass  # Non-main thread or unsupported platform

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nShutting down WIF Bunker agent...")
    finally:
        server.server_close()
        server.token_cache.close()
        if prev_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, prev_sigterm)
            except (ValueError, AttributeError):
                pass
        try:
            if resolved_secret.exists():
                resolved_secret.unlink()
        except OSError:
            pass
        if saved_executable_adc is not None:
            try:
                write_secure_file(resolved_adc, saved_executable_adc)
                logger.info("Restored executable ADC config: %s", resolved_adc)
            except (OSError, RuntimeError):
                pass
