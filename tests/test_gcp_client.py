"""Tests for GCPClient — mocked HTTP, no GCP credentials required."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from wif_bunker import GCPClient

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

    with patch("wif_bunker.google_auth_default", return_value=(mock_creds, "project-id")):
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
# api_call
# ---------------------------------------------------------------------------


def test_api_call_get_oauth():
    """OAuth mode sends Bearer token and returns JSON."""
    client = _make_client_with_token("tok-123")
    mock_resp = _mock_response(json_data={"name": "projects/123"})

    with patch.object(client.session, "request", return_value=mock_resp) as mock_req:
        result = client.api_call("GET", "https://example.com/v1/projects/123")

    assert result == {"name": "projects/123"}
    call_args = mock_req.call_args
    assert call_args[1]["headers"]["Authorization"] == "Bearer tok-123"
    client.session.close()


def test_api_call_get_adc():
    """ADC mode refreshes and applies credentials."""
    mock_creds = MagicMock()
    mock_creds.token = "adc-token"
    mock_creds.service_account_email = "sa@test.iam.gserviceaccount.com"

    with patch("wif_bunker.google_auth_default", return_value=(mock_creds, "proj")):
        client = GCPClient(use_adc=True)

    mock_resp = _mock_response(json_data={"result": "ok"})
    with patch.object(client.session, "request", return_value=mock_resp):
        result = client.api_call("GET", "https://example.com/v1/resource")

    assert result == {"result": "ok"}
    # refresh called at init + once for api_call
    assert mock_creds.refresh.call_count == 2
    mock_creds.apply.assert_called_once()
    client.session.close()


def test_api_call_post_with_payload():
    """POST sends JSON payload."""
    client = _make_client_with_token()
    mock_resp = _mock_response(json_data={"name": "operations/op1"})

    with patch.object(client.session, "request", return_value=mock_resp) as mock_req:
        result = client.api_call("POST", "https://example.com/v1/resource", json_payload={"key": "value"})

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
        result = client.api_call("DELETE", "https://example.com/v1/resource")

    assert result is None
    client.session.close()


# ---------------------------------------------------------------------------
# wait_for_lro
# ---------------------------------------------------------------------------


def test_wait_for_lro_completes_immediately():
    """LRO returns done on first poll."""
    client = _make_client_with_token()

    with patch.object(client, "api_call", return_value={"done": True, "response": {"name": "proj/123"}}):
        result = client.wait_for_lro("cloudresourcemanager.googleapis.com", "operations/op1")

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
        patch.object(client, "api_call", side_effect=responses),
        patch("wif_bunker.time.sleep"),
    ):
        result = client.wait_for_lro("cloudresourcemanager.googleapis.com", "operations/op1")

    assert result["done"] is True
    client.session.close()


def test_wait_for_lro_timeout():
    """LRO raises TimeoutError when deadline exceeded."""
    client = _make_client_with_token()

    with (
        patch.object(client, "api_call", return_value={"done": False}),
        patch("wif_bunker.time.sleep"),
        patch("wif_bunker.time.monotonic", side_effect=[0, 0, 1000]),
        pytest.raises(TimeoutError, match="did not complete"),
    ):
        client.wait_for_lro("cloudresourcemanager.googleapis.com", "operations/op1", timeout=10)

    client.session.close()


# ---------------------------------------------------------------------------
# wait_for_wif_resource
# ---------------------------------------------------------------------------


def test_wait_for_wif_resource_active_immediately():
    """Resource is ACTIVE on first check."""
    client = _make_client_with_token()

    with patch.object(client, "api_call", return_value={"state": "ACTIVE", "name": "pool/123"}):
        result = client.wait_for_wif_resource("https://iam.googleapis.com/v1/pool/123")

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
        patch.object(client, "api_call", side_effect=responses),
        patch("wif_bunker.time.sleep"),
    ):
        result = client.wait_for_wif_resource("https://iam.googleapis.com/v1/pool/123")

    assert result["state"] == "ACTIVE"
    client.session.close()


def test_wait_for_wif_resource_timeout():
    """Raises TimeoutError after max_attempts."""
    client = _make_client_with_token()

    with (
        patch.object(client, "api_call", return_value={"state": "CREATING"}),
        patch("wif_bunker.time.sleep"),
        pytest.raises(TimeoutError, match="did not become ACTIVE"),
    ):
        client.wait_for_wif_resource("https://iam.googleapis.com/v1/pool/123", max_attempts=2)

    client.session.close()
