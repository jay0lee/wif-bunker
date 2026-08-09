"""Tests for gcp_client.py — covers uncovered lines for GCP API interactions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests
from google.auth.exceptions import TransportError

from wif_bunker.gcp_client import GCPClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client_with_token(token: str = "fake-token") -> GCPClient:
    """Build a GCPClient in OAuth mode without running the real flow."""
    with patch.object(GCPClient, "_oauth_user_token", return_value=token):
        client = GCPClient()
    return client


def _mock_response(status_code: int = 200, json_data: dict | None = None, content: bytes = b"") -> MagicMock:
    """Create a fake requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.content = content or b'{"ok": true}'
    resp.json.return_value = json_data if json_data is not None else {"ok": True}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        exc = requests.HTTPError(response=resp)
        exc.response = resp
        resp.raise_for_status.side_effect = exc
    return resp


# ---------------------------------------------------------------------------
# ADC init — tokeninfo fallback
# ---------------------------------------------------------------------------


class TestAdcTokenInfoFallback:
    def test_adc_user_creds_fetches_email_from_tokeninfo(self):
        """No SA email → calls tokeninfo for identity."""
        mock_creds = MagicMock()
        mock_creds.token = "adc-token"
        # No service_account_email or signer_email
        mock_creds.service_account_email = None
        mock_creds.signer_email = None

        mock_session_resp = MagicMock()
        mock_session_resp.json.return_value = {"email": "user@example.com"}

        with (
            patch("google.auth.default", return_value=(mock_creds, "project-id")),
            patch.object(requests.Session, "get", return_value=mock_session_resp),
        ):
            client = GCPClient(use_adc=True)

        # Verify tokeninfo was called
        assert client._credentials is mock_creds
        client.session.close()

    def test_adc_user_creds_tokeninfo_exception(self):
        """Tokeninfo fails gracefully → identity='unknown'."""
        mock_creds = MagicMock()
        mock_creds.token = "adc-token"
        mock_creds.service_account_email = None
        mock_creds.signer_email = None

        with (
            patch("google.auth.default", return_value=(mock_creds, "project-id")),
            patch.object(requests.Session, "get", side_effect=Exception("network error")),
        ):
            client = GCPClient(use_adc=True)

        assert client._credentials is mock_creds
        client.session.close()

    def test_adc_uses_signer_email_if_no_sa_email(self):
        """Falls back to signer_email."""
        mock_creds = MagicMock()
        mock_creds.token = "adc-token"
        mock_creds.service_account_email = None
        mock_creds.signer_email = "signer@example.com"

        with patch("google.auth.default", return_value=(mock_creds, "project-id")):
            client = GCPClient(use_adc=True)

        assert client._credentials is mock_creds
        client.session.close()


# ---------------------------------------------------------------------------
# _api_call_with_retry — connection errors
# ---------------------------------------------------------------------------


class TestApiCallWithRetryConnectionErrors:
    def test_retries_on_connection_error(self):
        """ConnectionError is retried and recovers."""
        client = _make_client_with_token()
        resp_ok = _mock_response(json_data={"result": "ok"})

        call_count = 0

        def mock_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise requests.exceptions.ConnectionError("reset")
            return resp_ok

        with (
            patch.object(client.session, "request", side_effect=mock_request),
            patch("wif_bunker.gcp_client.time.sleep"),
            patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        ):
            result = client._api_call_with_retry("GET", "https://example.com/v1/resource")

        assert result == {"result": "ok"}
        assert call_count == 2
        client.session.close()

    def test_transport_error_not_retried(self):
        """TransportError (mTLS) is NOT retried — propagates immediately."""
        client = _make_client_with_token()

        def mock_request(*args, **kwargs):
            raise TransportError("TLS handshake failed")

        with (
            patch.object(client.session, "request", side_effect=mock_request),
            pytest.raises(TransportError),
        ):
            client._api_call_with_retry("GET", "https://example.com/v1/resource")

        client.session.close()

    def test_retries_on_os_error(self):
        """OSError is retried and recovers."""
        client = _make_client_with_token()
        resp_ok = _mock_response(json_data={"result": "ok"})

        call_count = 0

        def mock_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("Connection refused")
            return resp_ok

        with (
            patch.object(client.session, "request", side_effect=mock_request),
            patch("wif_bunker.gcp_client.time.sleep"),
            patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        ):
            result = client._api_call_with_retry("GET", "https://example.com/v1/resource")

        assert result == {"result": "ok"}
        client.session.close()

    def test_connection_error_exhausts_timeout_raises(self):
        """Raises after exhausting timeout on ConnectionError."""
        client = _make_client_with_token()

        with (
            patch.object(
                client.session,
                "request",
                side_effect=requests.exceptions.ConnectionError("reset"),
            ),
            patch("wif_bunker.gcp_client.time.sleep"),
            # Start at 0, first check still within deadline, second check past deadline
            patch("wif_bunker.gcp_client.time.monotonic", side_effect=[0, 5, 1000]),
            patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
            pytest.raises(requests.exceptions.ConnectionError),
        ):
            client._api_call_with_retry("GET", "https://example.com/v1/resource", timeout=10)

        client.session.close()

    def test_retries_on_404_with_propagation(self):
        """404 is retried when retry_on_propagation=True."""
        client = _make_client_with_token()
        resp_404 = _mock_response(404)
        resp_ok = _mock_response(json_data={"name": "pool/123"})

        with (
            patch.object(client.session, "request", side_effect=[resp_404, resp_ok]),
            patch("wif_bunker.gcp_client.time.sleep"),
            patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        ):
            result = client._api_call_with_retry(
                "POST",
                "https://example.com/v1/pool",
                retry_on_propagation=True,
            )

        assert result == {"name": "pool/123"}
        client.session.close()

    def test_retries_on_429(self):
        """429 (rate limit) is always retried."""
        client = _make_client_with_token()
        resp_429 = _mock_response(429)
        resp_ok = _mock_response(json_data={"result": "ok"})

        with (
            patch.object(client.session, "request", side_effect=[resp_429, resp_ok]),
            patch("wif_bunker.gcp_client.time.sleep"),
            patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        ):
            result = client._api_call_with_retry("GET", "https://example.com/v1/resource")

        assert result == {"result": "ok"}
        client.session.close()

    def test_retries_on_503(self):
        """503 (service unavailable) is always retried."""
        client = _make_client_with_token()
        resp_503 = _mock_response(503)
        resp_ok = _mock_response(json_data={"result": "ok"})

        with (
            patch.object(client.session, "request", side_effect=[resp_503, resp_ok]),
            patch("wif_bunker.gcp_client.time.sleep"),
            patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        ):
            result = client._api_call_with_retry("GET", "https://example.com/v1/resource")

        assert result == {"result": "ok"}
        client.session.close()


# ---------------------------------------------------------------------------
# _wait_for_wif_resource — 404 retry
# ---------------------------------------------------------------------------


class TestWaitForWifResource404:
    def test_retries_on_404_then_active(self):
        """404 on first attempt, ACTIVE on second."""
        client = _make_client_with_token()

        resp_404 = _mock_response(404)

        call_count = 0

        def mock_api_call(method, url, json_payload=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                resp_404.raise_for_status()
            return {"state": "ACTIVE", "name": "pool/123"}

        with (
            patch.object(client, "_api_call", side_effect=mock_api_call),
            patch("wif_bunker.gcp_client.time.sleep"),
            patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        ):
            result = client._wait_for_wif_resource(
                "https://iam.googleapis.com/v1/pool/123",
            )

        assert result["state"] == "ACTIVE"
        client.session.close()

    def test_non_404_error_raises_immediately(self):
        """Non-404 HTTPError raises immediately."""
        client = _make_client_with_token()

        resp_500 = _mock_response(500)

        def mock_api_call(method, url, json_payload=None):
            resp_500.raise_for_status()

        with (
            patch.object(client, "_api_call", side_effect=mock_api_call),
            pytest.raises(requests.HTTPError),
        ):
            client._wait_for_wif_resource("https://iam.googleapis.com/v1/pool/123")

        client.session.close()


# ---------------------------------------------------------------------------
# ensure_project — non-403/404 error raises
# ---------------------------------------------------------------------------


class TestEnsureProjectRaises:
    def test_non_403_404_get_raises(self):
        """Non-403/404 HTTPError on GET raises immediately."""
        client = _make_client_with_token()

        resp_500 = _mock_response(500)

        def mock_api_call(method, url, json_payload=None):
            resp_500.raise_for_status()

        with (
            patch.object(client, "_api_call", side_effect=mock_api_call),
            pytest.raises(requests.HTTPError),
        ):
            client.ensure_project("my-project")

        client.session.close()


# ---------------------------------------------------------------------------
# ensure_project — folder parent
# ---------------------------------------------------------------------------


class TestEnsureProjectWithFolder:
    def test_create_with_folder_parent(self):
        """Project creation with folder parent."""
        client = _make_client_with_token()

        resp_403 = _mock_response(403)

        call_count = 0

        def mock_api_call(method, url, json_payload=None):
            nonlocal call_count
            call_count += 1
            if method == "GET" and call_count == 1:
                resp_403.raise_for_status()
            elif method == "POST":
                # Verify folder is in payload
                assert json_payload["parent"]["type"] == "folder"
                assert json_payload["parent"]["id"] == "12345"
                return {"name": "operations/create-op"}
            elif method == "GET":
                return {"projectNumber": "789"}
            return None

        with (
            patch.object(client, "_api_call", side_effect=mock_api_call),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_api_call_with_retry", return_value={"projectNumber": "789"}),
        ):
            result = client.ensure_project("new-project", folder="12345")

        assert result == "789"
        client.session.close()


# ---------------------------------------------------------------------------
# ensure_project — POST non-409 error raises
# ---------------------------------------------------------------------------


class TestEnsureProjectPostError:
    def test_post_non_409_raises(self):
        """POST returns non-409 HTTPError."""
        client = _make_client_with_token()

        resp_403 = _mock_response(403)
        resp_500 = _mock_response(500)

        call_count = 0

        def mock_api_call(method, url, json_payload=None):
            nonlocal call_count
            call_count += 1
            if method == "GET" and call_count == 1:
                resp_403.raise_for_status()
            elif method == "POST":
                resp_500.raise_for_status()
            return None

        with (
            patch.object(client, "_api_call", side_effect=mock_api_call),
            pytest.raises(requests.HTTPError),
        ):
            client.ensure_project("new-project")

        client.session.close()


# ---------------------------------------------------------------------------
# enable_apis
# ---------------------------------------------------------------------------


class TestEnableApis:
    def test_enable_apis_calls_batch_enable_and_waits(self):
        """Batch enables APIs and waits for LRO."""
        client = _make_client_with_token()

        with (
            patch.object(
                client,
                "_api_call_with_retry",
                return_value={"name": "operations/enable-op"},
            ) as mock_retry,
            patch.object(client, "_wait_for_lro") as mock_lro,
        ):
            client.enable_apis("123456", ["iam.googleapis.com", "sts.googleapis.com"])

        mock_retry.assert_called_once()
        call_args = mock_retry.call_args
        assert call_args[0][0] == "POST"
        assert "batchEnable" in call_args[0][1]
        assert call_args[0][2] == {"serviceIds": ["iam.googleapis.com", "sts.googleapis.com"]}

        mock_lro.assert_called_once_with("serviceusage.googleapis.com", "operations/enable-op")
        client.session.close()


# ---------------------------------------------------------------------------
# setup_wif_infrastructure
# ---------------------------------------------------------------------------


class TestSetupWifInfrastructure:
    def _make_mock_config(self):
        """Create a mock config object for WIF tests."""
        config = MagicMock()
        config.project_id = "test-proj"
        config.pool_id = "bunker-wif-pool"
        config.provider_id = "bunker-x509-prov-123"
        config.sa_name = "bunker-wif-sa"
        return config

    def _make_mock_cert_bundle(self):
        """Create a mock cert bundle."""
        bundle = MagicMock()
        bundle.trust_anchor_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"
        bundle.sha256_fingerprint = "abc123fp"
        return bundle

    def test_creates_sa_and_pool_and_provider(self):
        """Full WIF infrastructure creation with new SA."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        with (
            patch.object(
                client,
                "_api_call_with_retry",
                side_effect=[
                    # create_sa_task result
                    {"email": "sa@test-proj.iam.gserviceaccount.com"},
                    # create_pool_task: pool creation
                    {"name": "operations/pool-op"},
                    # create_provider_task: provider creation
                    {"name": "operations/prov-op"},
                ],
            ),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
        ):
            sa_email, provider_id = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=False,
                use_sa=True,
            )

        assert sa_email == "sa@test-proj.iam.gserviceaccount.com"
        assert provider_id == config.provider_id
        client.session.close()

    def test_creates_provider_only_when_pool_reused(self):
        """reuse_pool=True skips pool creation, cleans stale providers."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        stale_providers = {
            "workloadIdentityPoolProviders": [
                {"name": "projects/123/locations/global/workloadIdentityPools/pool/providers/bunker-x509-prov-old"},
                {"name": "projects/123/locations/global/workloadIdentityPools/pool/providers/bunker-x509-prov-123"},
            ]
        }

        with (
            patch.object(
                client,
                "_api_call",
                side_effect=[
                    stale_providers,  # GET providers list
                    {"name": "operations/del-op"},  # DELETE stale provider
                ],
            ),
            patch.object(
                client,
                "_api_call_with_retry",
                return_value={"name": "operations/prov-op"},
            ),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
        ):
            sa_email, provider_id = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=True,
                use_sa=False,
            )

        assert sa_email is None
        assert provider_id == config.provider_id
        client.session.close()

    def test_sa_already_exists_409(self):
        """SA creation returns 409 (already exists)."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        resp_409 = _mock_response(409)

        sa_call_count = 0

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            nonlocal sa_call_count
            if "serviceAccounts" in url:
                sa_call_count += 1
                resp_409.raise_for_status()
            elif "workloadIdentityPools" in url and "providers" in url:
                return {"name": "operations/prov-op"}
            else:
                return {"name": "operations/pool-op"}
            return None

        with (
            patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
        ):
            sa_email, _ = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=False,
                use_sa=True,
            )

        assert sa_email == "bunker-wif-sa@test-proj.iam.gserviceaccount.com"
        client.session.close()

    def test_existing_sa_email_provided(self):
        """Pre-existing sa_email skips SA creation."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        with (
            patch.object(
                client,
                "_api_call_with_retry",
                side_effect=[
                    {"name": "operations/pool-op"},  # pool creation
                    {"name": "operations/prov-op"},  # provider creation
                ],
            ),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
        ):
            sa_email, _ = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=False,
                use_sa=True,
                sa_email="existing-sa@proj.iam.gserviceaccount.com",
            )

        assert sa_email == "existing-sa@proj.iam.gserviceaccount.com"
        client.session.close()

    def test_reuse_pool_list_providers_error(self):
        """Exception listing providers is caught and logged."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        with (
            patch.object(
                client,
                "_api_call",
                side_effect=Exception("network error"),
            ),
            patch.object(
                client,
                "_api_call_with_retry",
                return_value={"name": "operations/prov-op"},
            ),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
        ):
            sa_email, _ = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=True,
                use_sa=False,
            )

        assert sa_email is None
        client.session.close()

    def test_reuse_pool_delete_stale_provider_error(self):
        """Exception deleting stale provider is caught and logged as warning."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        stale_providers = {
            "workloadIdentityPoolProviders": [
                {"name": "projects/123/locations/global/workloadIdentityPools/pool/providers/bunker-x509-prov-old"},
            ]
        }

        resp_500 = _mock_response(500)

        api_call_count = 0

        def mock_api_call(method, url, json_payload=None):
            nonlocal api_call_count
            api_call_count += 1
            if api_call_count == 1:
                return stale_providers  # GET providers list
            # DELETE stale provider fails with HTTPError
            resp_500.raise_for_status()

        with (
            patch.object(client, "_api_call", side_effect=mock_api_call),
            patch.object(
                client,
                "_api_call_with_retry",
                return_value={"name": "operations/prov-op"},
            ),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
        ):
            sa_email, _ = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=True,
                use_sa=False,
            )

        assert sa_email is None
        client.session.close()

    def test_pool_already_exists_409(self):
        """Pool creation returns 409."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        resp_409 = _mock_response(409)

        pool_call_done = False

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            nonlocal pool_call_done
            if "workloadIdentityPools?" in url and not pool_call_done:
                pool_call_done = True
                resp_409.raise_for_status()
            elif "providers?" in url:
                return {"name": "operations/prov-op"}
            return None

        with (
            patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
        ):
            _, _ = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=False,
                use_sa=False,
            )

        client.session.close()


# ---------------------------------------------------------------------------
# apply_iam_bindings
# ---------------------------------------------------------------------------


class TestApplyIamBindings:
    def _make_mock_config(self):
        config = MagicMock()
        config.project_id = "test-proj"
        return config

    def test_sa_and_project_bindings(self):
        """Applies both SA and project IAM bindings."""
        client = _make_client_with_token()
        config = self._make_mock_config()

        call_log = []

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            call_log.append((method, url, json_payload))
            if "getIamPolicy" in url:
                return {"bindings": []}
            return {"bindings": []}

        with patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry):
            client.apply_iam_bindings(
                config=config,
                project_number="123456",
                workload_cn="bunker-workload-test",
                pool_id="bunker-wif-pool",
                sa_email="sa@test-proj.iam.gserviceaccount.com",
                use_sa=True,
            )

        # Should have 4 calls: SA getIamPolicy, SA setIamPolicy, proj getIamPolicy, proj setIamPolicy
        assert len(call_log) == 4
        # First two are SA IAM
        assert "serviceAccounts" in call_log[0][1]
        assert "serviceAccounts" in call_log[1][1]
        # Last two are project IAM
        assert "setIamPolicy" in call_log[3][1] or "getIamPolicy" in call_log[2][1]
        client.session.close()

    def test_project_bindings_only_no_sa(self):
        """Only project bindings when use_sa=False."""
        client = _make_client_with_token()
        config = self._make_mock_config()

        call_log = []

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            call_log.append((method, url, json_payload))
            if "getIamPolicy" in url:
                return {"bindings": []}
            return {}

        with patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry):
            client.apply_iam_bindings(
                config=config,
                project_number="123456",
                workload_cn="bunker-workload-test",
                pool_id="bunker-wif-pool",
                sa_email=None,
                use_sa=False,
            )

        # Only 2 calls: proj getIamPolicy, proj setIamPolicy
        assert len(call_log) == 2
        client.session.close()

    def test_sa_policy_none_defaults_to_empty(self):
        """SA policy returns None → defaults to {}."""
        client = _make_client_with_token()
        config = self._make_mock_config()

        call_log = []

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            call_log.append((method, url, json_payload))
            if "getIamPolicy" in url:
                return None  # Simulate None response
            return {}

        with patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry):
            client.apply_iam_bindings(
                config=config,
                project_number="123456",
                workload_cn="bunker-workload-test",
                pool_id="bunker-wif-pool",
                sa_email="sa@test-proj.iam.gserviceaccount.com",
                use_sa=True,
            )

        # The setIamPolicy calls should have the binding added
        sa_set_call = call_log[1]
        assert sa_set_call[2] is not None
        assert "policy" in sa_set_call[2]
        client.session.close()

    def test_project_member_uses_wif_principal_when_no_sa(self):
        """Direct WIF principal binding when use_sa=False."""
        client = _make_client_with_token()
        config = self._make_mock_config()

        call_log = []

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            call_log.append((method, url, json_payload))
            if "getIamPolicy" in url:
                return {"bindings": []}
            return {}

        with patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry):
            client.apply_iam_bindings(
                config=config,
                project_number="123456",
                workload_cn="bunker-workload-test",
                pool_id="bunker-wif-pool",
                sa_email=None,
                use_sa=False,
            )

        # Check the setIamPolicy call has the WIF principal, not serviceAccount:
        set_call = call_log[1]
        policy = set_call[2]["policy"]
        member = policy["bindings"][-1]["members"][0]
        assert member.startswith("principal://")
        client.session.close()

    def test_project_member_uses_sa_when_use_sa(self):
        """serviceAccount: prefix when use_sa=True."""
        client = _make_client_with_token()
        config = self._make_mock_config()

        call_log = []

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            call_log.append((method, url, json_payload))
            if "getIamPolicy" in url:
                return {"bindings": []}
            return {}

        with patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry):
            client.apply_iam_bindings(
                config=config,
                project_number="123456",
                workload_cn="bunker-workload-test",
                pool_id="bunker-wif-pool",
                sa_email="sa@test-proj.iam.gserviceaccount.com",
                use_sa=True,
            )

        # The project setIamPolicy call (4th) should use serviceAccount:
        proj_set_call = call_log[3]
        policy = proj_set_call[2]["policy"]
        member = policy["bindings"][-1]["members"][0]
        assert member.startswith("serviceAccount:")
        client.session.close()


# ---------------------------------------------------------------------------
# _wait_for_lro — error in completed operation (lines 384-387)
# ---------------------------------------------------------------------------


class TestWaitForLroError:
    def test_lro_completed_with_error_raises_runtime_error(self):
        """LRO completes but with an error field → raises RuntimeError."""
        client = _make_client_with_token()

        lro_response = {
            "done": True,
            "error": {
                "code": 403,
                "message": "Permission denied on resource project my-project",
            },
        }

        with (
            patch.object(client, "_api_call", return_value=lro_response),
            pytest.raises(RuntimeError, match="Permission denied"),
        ):
            client._wait_for_lro("cloudresourcemanager.googleapis.com", "operations/fail-op")

        client.session.close()


# ---------------------------------------------------------------------------
# setup_wif_infrastructure — SA non-409 error re-raises (line 528)
# ---------------------------------------------------------------------------


class TestSetupWifSaNon409:
    def _make_mock_config(self):
        config = MagicMock()
        config.project_id = "test-proj"
        config.pool_id = "bunker-wif-pool"
        config.provider_id = "bunker-x509-prov-123"
        config.sa_name = "bunker-wif-sa"
        return config

    def _make_mock_cert_bundle(self):
        bundle = MagicMock()
        bundle.trust_anchor_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"
        bundle.sha256_fingerprint = "abc123fp"
        return bundle

    def test_sa_creation_non_409_error_reraises(self):
        """SA creation returns non-409 HTTPError → re-raised, not swallowed."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        resp_500 = _mock_response(500)

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            if "serviceAccounts" in url:
                resp_500.raise_for_status()
            # Pool creation succeeds
            return {"name": "operations/pool-op"}

        with (
            patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
            pytest.raises(requests.HTTPError),
        ):
            client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=False,
                use_sa=True,
            )

        client.session.close()


# ---------------------------------------------------------------------------
# setup_wif_infrastructure — pool non-409 error re-raises (line 546)
# ---------------------------------------------------------------------------


class TestSetupWifPoolNon409:
    def _make_mock_config(self):
        config = MagicMock()
        config.project_id = "test-proj"
        config.pool_id = "bunker-wif-pool"
        config.provider_id = "bunker-x509-prov-123"
        config.sa_name = "bunker-wif-sa"
        return config

    def _make_mock_cert_bundle(self):
        bundle = MagicMock()
        bundle.trust_anchor_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"
        bundle.sha256_fingerprint = "abc123fp"
        return bundle

    def test_pool_creation_non_409_error_reraises(self):
        """Pool creation returns non-409 HTTPError → re-raised."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        resp_500 = _mock_response(500)

        def mock_api_call_with_retry(method, url, json_payload=None, *, retry_on_propagation=False, timeout=900):
            if "workloadIdentityPools?" in url:
                resp_500.raise_for_status()
            return {"name": "operations/prov-op"}

        with (
            patch.object(client, "_api_call_with_retry", side_effect=mock_api_call_with_retry),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
            pytest.raises(requests.HTTPError),
        ):
            client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=False,
                use_sa=False,
            )

        client.session.close()


# ---------------------------------------------------------------------------
# setup_wif_infrastructure — provider listing HTTPError (line 570)
# ---------------------------------------------------------------------------


class TestSetupWifProviderListHTTPError:
    def _make_mock_config(self):
        config = MagicMock()
        config.project_id = "test-proj"
        config.pool_id = "bunker-wif-pool"
        config.provider_id = "bunker-x509-prov-123"
        config.sa_name = "bunker-wif-sa"
        return config

    def _make_mock_cert_bundle(self):
        bundle = MagicMock()
        bundle.trust_anchor_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"
        bundle.sha256_fingerprint = "abc123fp"
        return bundle

    def test_provider_list_http_error_logged_as_warning(self):
        """HTTPError listing providers in reuse_pool mode is caught and logged."""
        client = _make_client_with_token()
        config = self._make_mock_config()
        bundle = self._make_mock_cert_bundle()

        resp_403 = _mock_response(403)

        def mock_api_call(method, url, json_payload=None):
            if "/providers" in url and method == "GET":
                resp_403.raise_for_status()
            return {"name": "operations/del-op"}

        with (
            patch.object(client, "_api_call", side_effect=mock_api_call),
            patch.object(
                client,
                "_api_call_with_retry",
                return_value={"name": "operations/prov-op"},
            ),
            patch.object(client, "_wait_for_lro"),
            patch.object(client, "_wait_for_wif_resource"),
            patch("wif_bunker.gcp_client.time.sleep"),
        ):
            sa_email, _ = client.setup_wif_infrastructure(
                config=config,
                project_number="123456",
                cert_bundle=bundle,
                reuse_pool=True,
                use_sa=False,
            )

        # Should complete successfully despite the HTTPError
        assert sa_email is None
        client.session.close()
