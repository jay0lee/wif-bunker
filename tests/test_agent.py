"""Tests for wif_bunker.agent (TokenCache, AgentHTTPServer, and stock google-auth ADC)."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import google.auth
import pytest
import requests
from google.auth.transport.requests import Request

from wif_bunker.agent import (
    TokenCache,
    _default_secret_path,
    _parse_token_request_body,
    run_agent_foreground,
    start_agent,
)
from wif_bunker.signers import load_signer


class TestTokenCache:
    def test_caches_token_and_counts_single_hardware_sign(self, sample_bunker_config):
        signer = load_signer(sample_bunker_config.signer)
        cache = TokenCache(sample_bunker_config, signer, refresh_margin_seconds=300)
        now = int(time.time())

        with patch("wif_bunker.agent.mint_google_access_token", return_value=("tok-1", now + 3600)) as mock_mint:
            tok1, rem1 = cache.get_token(["https://www.googleapis.com/auth/cloud-platform"])
            tok2, rem2 = cache.get_token(["https://www.googleapis.com/auth/cloud-platform"])
            tok3, rem3 = cache.get_token(["https://www.googleapis.com/auth/cloud-platform"])

        assert tok1 == tok2 == tok3 == "tok-1"
        assert 3590 <= rem1 <= 3600
        assert 3590 <= rem2 <= 3600
        assert 3590 <= rem3 <= 3600
        assert mock_mint.call_count == 1

        stats = cache.stats()
        assert stats["hardware_signs"] == 1
        assert stats["cache_hits"] == 2
        assert stats["cached_scope_sets"] == 1
        cache.close()

    def test_separates_cache_entries_by_scope_set(self, sample_bunker_config):
        signer = load_signer(sample_bunker_config.signer)
        cache = TokenCache(sample_bunker_config, signer)
        now = int(time.time())

        with patch(
            "wif_bunker.agent.mint_google_access_token",
            side_effect=[("tok-cloud", now + 3600), ("tok-iam", now + 3600)],
        ) as mock_mint:
            t1, _ = cache.get_token(["scope-a", "scope-b"])
            t2, _ = cache.get_token(["scope-b", "scope-a"])  # Same frozenset -> cache hit
            t3, _ = cache.get_token(["scope-c"])  # Different scope -> second mint

        assert t1 == t2 == "tok-cloud"
        assert t3 == "tok-iam"
        assert mock_mint.call_count == 2
        assert cache.stats()["cached_scope_sets"] == 2
        cache.close()

    def test_refreshes_when_within_margin(self, sample_bunker_config):
        signer = load_signer(sample_bunker_config.signer)
        cache = TokenCache(sample_bunker_config, signer, refresh_margin_seconds=300)
        now = int(time.time())

        with patch(
            "wif_bunker.agent.mint_google_access_token",
            side_effect=[("tok-expiring", now + 100), ("tok-fresh", now + 3600)],
        ) as mock_mint:
            t1, _ = cache.get_token(["scope-a"])
            t2, _ = cache.get_token(["scope-a"])

        assert t1 == "tok-expiring"
        assert t2 == "tok-fresh"
        assert mock_mint.call_count == 2
        cache.close()

    def test_concurrent_single_flight_does_only_one_hardware_sign(self, sample_bunker_config):
        """12 parallel workers requesting the same scope trigger exactly ONE hardware sign."""
        signer = load_signer(sample_bunker_config.signer)
        cache = TokenCache(sample_bunker_config, signer)
        now = int(time.time())
        calls = 0

        def slow_mint(*args, **kwargs):
            nonlocal calls
            calls += 1
            time.sleep(0.05)
            return ("tok-shared", now + 3600)

        with patch("wif_bunker.agent.mint_google_access_token", side_effect=slow_mint):
            with ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(lambda _: cache.get_token(["scope-x"])[0], range(12)))

        assert results == ["tok-shared"] * 12
        assert calls == 1
        assert cache.stats()["hardware_signs"] == 1
        assert cache.stats()["cache_hits"] == 11
        cache.close()


class TestAgentHttpServerAndStockGoogleAuth:
    def test_http_endpoints_and_stock_google_auth_adc(self, sample_bunker_config, tmp_path, monkeypatch):
        """End-to-end test: real localhost AgentHTTPServer + stock google.auth.default()."""
        signer = load_signer(sample_bunker_config.signer)
        adc_path = tmp_path / "adc.json"
        secret_path = tmp_path / ".agent-secret"

        server, written_adc, written_secret = start_agent(
            sample_bunker_config,
            signer,
            port=0,
            adc_path=adc_path,
            secret_path=secret_path,
        )
        port = server.server_address[1]
        assert port > 0
        assert written_adc.exists()
        assert written_secret.exists()

        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        now = int(time.time())

        try:
            # 1. Health endpoint works without auth
            health = requests.get(f"http://127.0.0.1:{port}/health", timeout=5)
            assert health.status_code == 200
            assert health.json()["status"] == "ok"

            # 2. Unauthorized POST rejected with 401
            bad = requests.post(
                f"http://127.0.0.1:{port}/v1/token",
                json={"subject_token": "wrong-secret"},
                timeout=5,
            )
            assert bad.status_code == 401

            # 3. Unknown path returns 404
            assert requests.get(f"http://127.0.0.1:{port}/nope", timeout=5).status_code == 404
            assert requests.post(f"http://127.0.0.1:{port}/nope", timeout=5).status_code == 404

            # 4. Real stock google.auth.default() across 3 independent clients -> ONLY 1 upstream mint!
            monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(written_adc))
            with patch(
                "wif_bunker.agent.mint_google_access_token",
                return_value=("ya29.cached-access-token", now + 3600),
            ) as mock_mint:
                for _ in range(3):
                    creds, _proj = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
                    creds.refresh(Request())
                    assert creds.token == "ya29.cached-access-token"

                assert mock_mint.call_count == 1

            # 5. Also verify JSON POST directly with correct secret hits cache
            secret_val = written_secret.read_text(encoding="utf-8").strip()
            ok_json = requests.post(
                f"http://127.0.0.1:{port}/v1/token",
                json={"subject_token": secret_val, "scope": "https://www.googleapis.com/auth/cloud-platform"},
                timeout=5,
            )
            assert ok_json.status_code == 200
            body = ok_json.json()
            assert body["access_token"] == "ya29.cached-access-token"
            assert body["token_type"] == "Bearer"
            assert body["expires_in"] > 3500

            health_after = requests.get(f"http://127.0.0.1:{port}/health", timeout=5).json()
            assert health_after["hardware_signs"] == 1
            assert health_after["cache_hits"] >= 3
        finally:
            server.shutdown()
            server.server_close()
            server.token_cache.close()

    def test_http_error_paths_400_502_500(self, sample_bunker_config, tmp_path):
        signer = load_signer(sample_bunker_config.signer)
        server, _adc, secret_file = start_agent(
            sample_bunker_config,
            signer,
            port=0,
            adc_path=tmp_path / "adc.json",
            secret_path=tmp_path / ".secret",
        )
        port = server.port
        secret_val = secret_file.read_text(encoding="utf-8").strip()
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            # Empty body -> 400
            r_empty = requests.post(f"http://127.0.0.1:{port}/v1/token", data=b"", timeout=5)
            assert r_empty.status_code == 400

            # Malformed JSON -> 400
            r_bad_json = requests.post(
                f"http://127.0.0.1:{port}/v1/token",
                data=b"{not-json",
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            assert r_bad_json.status_code == 400

            # Upstream HTTPError -> 502
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.text = "denied"
            http_err = requests.exceptions.HTTPError("denied", response=mock_resp)
            with patch("wif_bunker.agent.mint_google_access_token", side_effect=http_err):
                r_502 = requests.post(
                    f"http://127.0.0.1:{port}/v1/token",
                    json={"subject_token": secret_val},
                    timeout=5,
                )
            assert r_502.status_code == 502
            assert r_502.json()["error"] == "upstream_error"

            # Unexpected internal error -> 500
            with patch("wif_bunker.agent.mint_google_access_token", side_effect=RuntimeError("tpm locked")):
                r_500 = requests.post(
                    f"http://127.0.0.1:{port}/v1/token",
                    json={"subject_token": secret_val},
                    timeout=5,
                )
            assert r_500.status_code == 500
            assert r_500.json()["error"] == "server_error"
        finally:
            server.shutdown()
            server.server_close()
            server.token_cache.close()


class TestAgentHelpersAndLifecycle:
    def test_empty_scopes_falls_back_to_default(self, sample_bunker_config):
        signer = load_signer(sample_bunker_config.signer)
        cache = TokenCache(sample_bunker_config, signer)
        now = int(time.time())
        with patch("wif_bunker.agent.mint_google_access_token", return_value=("tok-def", now + 3600)) as mock_mint:
            tok, _ = cache.get_token(["", ""])
        assert tok == "tok-def"
        assert mock_mint.call_args.kwargs["scopes"] == ["https://www.googleapis.com/auth/cloud-platform"]
        cache.close()

    def test_parse_token_request_body_non_dict_json_raises(self):
        with pytest.raises(ValueError, match="Expected JSON object"):
            _parse_token_request_body("application/json", b'["not", "a", "dict"]')

    def test_default_secret_path_uses_xdg_runtime_dir(self, tmp_path, monkeypatch):
        runtime_dir = tmp_path / "run"
        runtime_dir.mkdir()
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
        secret_path = _default_secret_path(tmp_path / "adc.json")
        assert secret_path.parent == runtime_dir

    def test_start_agent_eager_warm(self, sample_bunker_config, tmp_path):
        signer = load_signer(sample_bunker_config.signer)
        now = int(time.time())
        with patch("wif_bunker.agent.mint_google_access_token", return_value=("tok-warm", now + 3600)) as mock_mint:
            server, _adc, _secret = start_agent(
                sample_bunker_config,
                signer,
                port=0,
                adc_path=tmp_path / "adc.json",
                secret_path=tmp_path / ".secret",
                eager_warm=True,
            )
            try:
                assert mock_mint.call_count == 1
                assert server.token_cache.hardware_signs == 1
            finally:
                server.server_close()
                server.token_cache.close()

    def test_run_agent_foreground_keyboard_interrupt_and_cleanup(self, sample_bunker_config, tmp_path):
        signer = load_signer(sample_bunker_config.signer)
        adc_path = tmp_path / "adc.json"
        secret_path = tmp_path / ".secret"

        with patch("wif_bunker.agent.AgentHTTPServer.serve_forever", side_effect=KeyboardInterrupt):
            run_agent_foreground(
                sample_bunker_config,
                signer,
                port=0,
                adc_path=adc_path,
                secret_path=secret_path,
            )
        assert adc_path.exists()
        assert not secret_path.exists()

    def test_run_agent_foreground_restores_preexisting_executable_adc(self, sample_bunker_config, tmp_path):
        signer = load_signer(sample_bunker_config.signer)
        adc_path = tmp_path / "adc.json"
        secret_path = tmp_path / ".secret"
        original_exec_adc = '{"type": "external_account", "credential_source": {"executable": {"command": "x"}}}\n'
        adc_path.write_text(original_exec_adc, encoding="utf-8")

        saw_agent_adc = {}

        def fake_serve(self_srv):
            saw_agent_adc["during"] = adc_path.read_text(encoding="utf-8")
            raise KeyboardInterrupt

        with patch("wif_bunker.agent.AgentHTTPServer.serve_forever", fake_serve):
            run_agent_foreground(
                sample_bunker_config,
                signer,
                port=0,
                adc_path=adc_path,
                secret_path=secret_path,
            )
        assert "127.0.0.1:" in saw_agent_adc["during"]
        assert adc_path.read_text(encoding="utf-8") == original_exec_adc
        assert not secret_path.exists()

    def test_run_agent_foreground_direct_wif_and_sigterm(self, sample_bunker_config, tmp_path):
        sample_bunker_config.service_account_email = None
        signer = load_signer(sample_bunker_config.signer)
        adc_path = tmp_path / "adc.json"
        secret_path = tmp_path / ".secret"
        captured_handler = {}

        def fake_signal(sig, handler):
            captured_handler["fn"] = handler
            return MagicMock()

        def fake_serve(self_srv):
            # Trigger the registered SIGTERM handler to verify graceful shutdown path
            captured_handler["fn"](15, None)
            time.sleep(0.05)

        with (
            patch("wif_bunker.agent.signal.signal", side_effect=fake_signal),
            patch("wif_bunker.agent.AgentHTTPServer.serve_forever", fake_serve),
        ):
            run_agent_foreground(
                sample_bunker_config,
                signer,
                port=0,
                adc_path=adc_path,
                secret_path=secret_path,
            )
        assert not secret_path.exists()
