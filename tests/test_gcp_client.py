"""Tests for GCPClient — mocked HTTP, no GCP credentials required."""

from unittest.mock import MagicMock, patch

import pytest
import requests

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
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    return resp


# ---------------------------------------------------------------------------
# __init__ (ADC mode)
# ---------------------------------------------------------------------------


def test_init_adc_mode():
    """ADC mode refreshes credentials and logs the identity."""
    mock_creds = MagicMock()
    mock_creds.token = "adc-token"
    mock_creds.service_account_email = "sa@test.iam.gserviceaccount.com"

    with patch("google.auth.default", return_value=(mock_creds, "project-id")):
        client = GCPClient(use_adc=True)

    mock_creds.refresh.assert_called_once()
    assert client._credentials is mock_creds
    assert client._token is None
    client.session.close()


def test_init_oauth_mode():
    """OAuth mode calls _oauth_user_token and stores the token."""
    client = _make_client_with_token("my-oauth-token")
    assert client._token == "my-oauth-token"
    assert client._credentials is None
    client.session.close()


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


def test_context_manager():
    """Entering returns self, exiting closes session."""
    client = _make_client_with_token()
    with patch.object(client.session, "close") as mock_close:
        with client as c:
            assert c is client
        mock_close.assert_called_once()


# ---------------------------------------------------------------------------
# _api_call
# ---------------------------------------------------------------------------


def test_api_call_get_oauth():
    """OAuth mode sends Bearer token and returns JSON."""
    client = _make_client_with_token("tok-123")
    mock_resp = _mock_response(json_data={"name": "projects/123"})

    with patch.object(client.session, "request", return_value=mock_resp) as mock_req:
        result = client._api_call("GET", "https://example.com/v1/projects/123")

    assert result == {"name": "projects/123"}
    call_args = mock_req.call_args
    assert call_args[1]["headers"]["Authorization"] == "Bearer tok-123"
    client.session.close()


def test_api_call_get_adc():
    """ADC mode refreshes and applies credentials."""
    mock_creds = MagicMock()
    mock_creds.token = "adc-token"
    mock_creds.service_account_email = "sa@test.iam.gserviceaccount.com"

    with patch("google.auth.default", return_value=(mock_creds, "proj")):
        client = GCPClient(use_adc=True)

    mock_resp = _mock_response(json_data={"result": "ok"})
    with patch.object(client.session, "request", return_value=mock_resp):
        result = client._api_call("GET", "https://example.com/v1/resource")

    assert result == {"result": "ok"}
    # refresh called at init + once for _api_call
    assert mock_creds.refresh.call_count == 2
    mock_creds.apply.assert_called_once()
    client.session.close()


def test_api_call_post_with_payload():
    """POST sends JSON payload."""
    client = _make_client_with_token()
    mock_resp = _mock_response(json_data={"name": "operations/op1"})

    with patch.object(client.session, "request", return_value=mock_resp) as mock_req:
        result = client._api_call("POST", "https://example.com/v1/resource", json_payload={"key": "value"})

    assert result == {"name": "operations/op1"}
    call_args = mock_req.call_args
    assert call_args[1]["json"] == {"key": "value"}
    client.session.close()


def test_api_call_empty_response():
    """Returns None when response has no content."""
    client = _make_client_with_token()
    mock_resp = _mock_response(json_data=None, content=b"")
    mock_resp.content = b""

    with patch.object(client.session, "request", return_value=mock_resp):
        result = client._api_call("DELETE", "https://example.com/v1/resource")

    assert result is None
    client.session.close()


# ---------------------------------------------------------------------------
# _wait_for_lro
# ---------------------------------------------------------------------------


def test_wait_for_lro_completes_immediately():
    """LRO returns done on first poll."""
    client = _make_client_with_token()

    with patch.object(client, "_api_call", return_value={"done": True, "response": {"name": "proj/123"}}):
        result = client._wait_for_lro("cloudresourcemanager.googleapis.com", "operations/op1")

    assert result["done"] is True
    client.session.close()


def test_wait_for_lro_polls_until_done():
    """LRO polls multiple times before completing."""
    client = _make_client_with_token()

    responses = [
        {"done": False},
        {"done": False},
        {"done": True, "response": {"name": "proj/123"}},
    ]

    with (
        patch.object(client, "_api_call", side_effect=responses),
        patch("wif_bunker.gcp_client.time.sleep"),
        patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
    ):
        result = client._wait_for_lro("cloudresourcemanager.googleapis.com", "operations/op1")

    assert result["done"] is True
    client.session.close()


def test_wait_for_lro_timeout():
    """LRO raises TimeoutError when deadline exceeded."""
    client = _make_client_with_token()

    with (
        patch.object(client, "_api_call", return_value={"done": False}),
        patch("wif_bunker.gcp_client.time.sleep"),
        patch("wif_bunker.gcp_client.time.monotonic", side_effect=[0, 0, 1000]),
        patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        pytest.raises(TimeoutError, match="did not complete"),
    ):
        client._wait_for_lro("cloudresourcemanager.googleapis.com", "operations/op1", timeout=10)

    client.session.close()


# ---------------------------------------------------------------------------
# _wait_for_wif_resource
# ---------------------------------------------------------------------------


def test_wait_for_wif_resource_active_immediately():
    """Resource is ACTIVE on first check."""
    client = _make_client_with_token()

    with patch.object(client, "_api_call", return_value={"state": "ACTIVE", "name": "pool/123"}):
        result = client._wait_for_wif_resource("https://iam.googleapis.com/v1/pool/123")

    assert result["state"] == "ACTIVE"
    client.session.close()


def test_wait_for_wif_resource_polls_until_active():
    """Resource polls multiple times before becoming ACTIVE."""
    client = _make_client_with_token()

    responses = [
        {"state": "CREATING"},
        {"state": "CREATING"},
        {"state": "ACTIVE", "name": "pool/123"},
    ]

    with (
        patch.object(client, "_api_call", side_effect=responses),
        patch("wif_bunker.gcp_client.time.sleep"),
        patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
    ):
        result = client._wait_for_wif_resource("https://iam.googleapis.com/v1/pool/123")

    assert result["state"] == "ACTIVE"
    client.session.close()


def test_wait_for_wif_resource_timeout():
    """Raises TimeoutError after timeout exceeded."""
    client = _make_client_with_token()

    with (
        patch.object(client, "_api_call", return_value={"state": "CREATING"}),
        patch("wif_bunker.gcp_client.time.sleep"),
        patch("wif_bunker.gcp_client.time.monotonic", side_effect=[0, 0, 1000]),
        patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        pytest.raises(TimeoutError, match="did not become ACTIVE"),
    ):
        client._wait_for_wif_resource("https://iam.googleapis.com/v1/pool/123", timeout=10)

    client.session.close()


# ---------------------------------------------------------------------------
# _api_call_with_retry
# ---------------------------------------------------------------------------


def test_retry_succeeds_first_try():
    """No retry needed — returns result immediately."""
    client = _make_client_with_token()
    mock_resp = _mock_response(json_data={"name": "sa@proj.iam"})

    with patch.object(client.session, "request", return_value=mock_resp) as mock_req:
        result = client._api_call_with_retry("POST", "https://example.com/v1/sa")

    assert result == {"name": "sa@proj.iam"}
    assert mock_req.call_count == 1
    client.session.close()


def test_retry_retries_403_when_propagation_enabled():
    """Retries on 403 when retry_on_propagation=True and succeeds on second attempt."""
    client = _make_client_with_token()
    resp_403 = _mock_response(403)
    resp_ok = _mock_response(json_data={"name": "pool/123"})

    with (
        patch.object(client.session, "request", side_effect=[resp_403, resp_ok]),
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


def test_retry_does_not_retry_403_without_propagation():
    """403 raises immediately when retry_on_propagation=False."""
    client = _make_client_with_token()
    resp_403 = _mock_response(403)

    with (
        patch.object(client.session, "request", return_value=resp_403) as mock_req,
        pytest.raises(requests.HTTPError),
    ):
        client._api_call_with_retry("POST", "https://example.com/v1/pool")

    assert mock_req.call_count == 1
    client.session.close()


def test_retry_exhausts_timeout():
    """Raises after timeout on persistent 403s with propagation enabled."""
    client = _make_client_with_token()
    resp_403 = _mock_response(403)

    with (
        patch.object(client.session, "request", return_value=resp_403),
        patch("wif_bunker.gcp_client.time.sleep"),
        # Start at 0, first check still within deadline, second check past deadline
        patch("wif_bunker.gcp_client.time.monotonic", side_effect=[0, 5, 1000]),
        patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
        pytest.raises(requests.HTTPError),
    ):
        client._api_call_with_retry(
            "POST",
            "https://example.com/v1/pool",
            retry_on_propagation=True,
            timeout=10,
        )

    client.session.close()


def test_retry_retries_500_always():
    """500 is always retried (server-side transient error)."""
    client = _make_client_with_token()
    resp_500 = _mock_response(500)
    resp_ok = _mock_response(json_data={"result": "ok"})

    with (
        patch.object(client.session, "request", side_effect=[resp_500, resp_ok]),
        patch("wif_bunker.gcp_client.time.sleep"),
        patch("wif_bunker.gcp_client.random.uniform", return_value=0.1),
    ):
        result = client._api_call_with_retry("POST", "https://example.com/v1/pool")

    assert result == {"result": "ok"}
    client.session.close()


def test_retry_does_not_retry_400():
    """400 (bad request) raises immediately — not retryable."""
    client = _make_client_with_token()
    resp_400 = _mock_response(400)

    with (
        patch.object(client.session, "request", return_value=resp_400) as mock_req,
        pytest.raises(requests.HTTPError),
    ):
        client._api_call_with_retry("POST", "https://example.com/v1/pool")

    assert mock_req.call_count == 1
    client.session.close()


# ---------------------------------------------------------------------------
# ensure_project
# ---------------------------------------------------------------------------


def test_ensure_project_exists():
    """If the project already exists, return its number immediately — no retry."""
    client = _make_client_with_token()

    with patch.object(client, "_api_call", return_value={"projectNumber": "123456"}) as mock_call:
        result = client.ensure_project("my-project")

    assert result == "123456"
    # Only one GET call — no retry, no POST.
    mock_call.assert_called_once_with(
        "GET",
        "https://cloudresourcemanager.googleapis.com/v1/projects/my-project",
    )
    client.session.close()


def test_ensure_project_creates_new():
    """If project doesn't exist (403), create it via LRO."""
    client = _make_client_with_token()

    get_403 = _mock_response(403)

    call_count = 0

    def mock_api_call(method, url, json_payload=None):
        nonlocal call_count
        call_count += 1
        if method == "GET" and call_count == 1:
            # First GET: project doesn't exist
            get_403.raise_for_status()
        elif method == "POST":
            return {"name": "operations/create-op"}
        elif method == "GET":
            return {"projectNumber": "789"}
        return None

    with (
        patch.object(client, "_api_call", side_effect=mock_api_call),
        patch.object(client, "_wait_for_lro"),
        patch.object(client, "_api_call_with_retry", return_value={"projectNumber": "789"}),
        patch("wif_bunker.gcp_client.time.sleep"),
    ):
        result = client.ensure_project("new-project")

    assert result == "789"
    client.session.close()


def test_ensure_project_409_already_exists():
    """If POST returns 409 (project already exists), reuse it."""
    client = _make_client_with_token()

    call_count = 0

    def mock_api_call(method, url, json_payload=None):
        nonlocal call_count
        call_count += 1
        if method == "GET" and call_count == 1:
            # First GET: 403
            resp = _mock_response(403)
            resp.raise_for_status()
        elif method == "POST":
            # POST: 409 — already exists
            resp = _mock_response(409)
            resp.raise_for_status()
        elif method == "GET":
            return {"projectNumber": "42"}
        return None

    with (
        patch.object(client, "_api_call", side_effect=mock_api_call),
        patch.object(client, "_api_call_with_retry", return_value={"projectNumber": "42"}),
        patch("wif_bunker.gcp_client.time.sleep"),
    ):
        result = client.ensure_project("existing-project")

    assert result == "42"
    client.session.close()


def test_api_call_does_not_retry_403():
    """_api_call raises HTTPError immediately on 403 — no retries."""
    client = _make_client_with_token()

    resp_403 = _mock_response(403)
    with (
        patch.object(client.session, "request", return_value=resp_403) as mock_req,
        pytest.raises(requests.HTTPError),
    ):
        client._api_call("GET", "https://example.com/v1/resource")

    # Only one request — no retries.
    assert mock_req.call_count == 1
    client.session.close()


def test_ensure_project_propagation_retry():
    """Final GET uses _api_call_with_retry with retry_on_propagation=True."""
    client = _make_client_with_token()

    call_count = 0

    def mock_api_call(method, url, json_payload=None):
        nonlocal call_count
        call_count += 1
        if method == "GET" and call_count == 1:
            # First GET: project doesn't exist
            resp = _mock_response(403)
            resp.raise_for_status()
        elif method == "POST":
            return {"name": "operations/create-op"}
        return None

    with (
        patch.object(client, "_api_call", side_effect=mock_api_call),
        patch.object(client, "_wait_for_lro"),
        patch.object(client, "_api_call_with_retry", return_value={"projectNumber": "999"}) as mock_retry,
        patch("wif_bunker.gcp_client.time.sleep"),
    ):
        result = client.ensure_project("slow-project")

    assert result == "999"
    # Verify propagation retry was used for the final GET
    mock_retry.assert_called_once()
    call_kwargs = mock_retry.call_args
    assert call_kwargs[1].get("retry_on_propagation") is True
    client.session.close()
