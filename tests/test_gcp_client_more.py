from unittest.mock import MagicMock, patch

import requests

from wif_bunker.gcp_client import GCPClient


def _mock_response(status_code: int = 200, json_data: dict | None = None, content: bytes = b"") -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.content = content or b'{"ok": true}'
    resp.json.return_value = json_data if json_data is not None else {"ok": True}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    return resp


def test_init_adc_mode_tokeninfo_fail():
    mock_creds = MagicMock()
    mock_creds.token = "adc-token"
    mock_creds.service_account_email = None
    mock_creds.signer_email = None

    with patch("google.auth.default", return_value=(mock_creds, "project-id")):
        with patch("requests.Session.get", side_effect=Exception("err")):
            client = GCPClient(use_adc=True)
            assert client._credentials is mock_creds


@patch("webbrowser.open")
@patch("http.server.HTTPServer")
def test_oauth_user_token(mock_server_cls, mock_open):
    # We will simulate a quick stdin return
    mock_server = MagicMock()
    mock_server.server_address = ("127.0.0.1", 8080)
    mock_server_cls.return_value = mock_server

    with patch("builtins.input", return_value="4/somecode"), patch("requests.post") as mock_post:
        mock_post.return_value = _mock_response(json_data={"access_token": "token123", "expires_in": 3600})
        client = GCPClient(use_adc=False)
        assert client._token == "token123"


def test_api_call_with_iam_retry_connection_error():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    with patch.object(
        client.session,
        "request",
        side_effect=[requests.exceptions.ConnectionError("err"), _mock_response(json_data={"ok": "yes"})],
    ):
        with patch("wif_bunker.gcp_client.time.sleep"):
            res = client.api_call_with_iam_retry("GET", "http://test")
            assert res == {"ok": "yes"}


def test_wait_for_wif_resource_404():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    resp_404 = _mock_response(404)
    with patch.object(
        client, "api_call", side_effect=[requests.exceptions.HTTPError(response=resp_404), {"state": "ACTIVE"}]
    ):
        with patch("wif_bunker.gcp_client.time.sleep"):
            res = client.wait_for_wif_resource("http://test")
            assert res == {"state": "ACTIVE"}


def test_ensure_project_with_folder():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    resp_404 = _mock_response(404)

    def mock_api_call(method, url, json_payload=None):
        if method == "GET" and "v1/projects/" in url and "retry" not in url:
            raise requests.exceptions.HTTPError(response=resp_404)
        if method == "POST":
            assert json_payload["parent"]["id"] == "folder123"
            return {"name": "op1"}
        return {"projectNumber": "123"}

    with patch.object(client, "api_call", side_effect=mock_api_call), patch.object(client, "wait_for_lro"):
        with patch.object(client, "api_call_with_iam_retry", return_value={"projectNumber": "123"}):
            res = client.ensure_project("test-proj", folder="folder123")
            assert res == "123"


def test_enable_apis():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    with patch.object(client, "api_call_with_iam_retry", return_value={"name": "op1"}):
        with patch.object(client, "wait_for_lro"):
            client.enable_apis("123", ["api1"])


def test_setup_wif_infrastructure():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    config = MagicMock()
    config.pool_id = "pool1"
    config.provider_id = "prov1"
    config.project_id = "proj1"
    config.sa_name = "sa1"

    cert_bundle = MagicMock()
    cert_bundle.sha256_fingerprint = "fp"
    cert_bundle.trust_anchor_pem = "pem"

    with patch.object(client, "api_call_with_iam_retry", return_value={"name": "op", "email": "sa@x.com"}):
        with patch.object(client, "wait_for_lro"):
            with patch.object(client, "wait_for_wif_resource"):
                sa_email, prov_id = client.setup_wif_infrastructure(config, "123", cert_bundle, False, True)
                assert sa_email == "sa@x.com"
                assert prov_id == "prov1"


def test_apply_iam_bindings():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    config = MagicMock()
    config.project_id = "proj1"

    with patch.object(client, "api_call_with_iam_retry", return_value={"bindings": []}):
        client.apply_iam_bindings(config, "123", "cn1", "pool1", "sa@x.com", True)

        # Test reuse case
        client.apply_iam_bindings(config, "123", "cn1", "pool1", None, False)
