from unittest.mock import MagicMock, patch

import google.auth.exceptions
import pytest
import requests

from wif_bunker.config import WorkloadConfig
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

    with (
        patch.object(
            client.session,
            "request",
            side_effect=[requests.exceptions.ConnectionError("err"), _mock_response(json_data={"ok": "yes"})],
        ),
        patch("wif_bunker.gcp_client.time.sleep"),
    ):
        res = client._api_call_with_retry("GET", "http://test")
        assert res == {"ok": "yes"}


def test_wait_for_wif_resource_404():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    resp_404 = _mock_response(404)
    with (
        patch.object(
            client, "_api_call", side_effect=[requests.exceptions.HTTPError(response=resp_404), {"state": "ACTIVE"}]
        ),
        patch("wif_bunker.gcp_client.time.sleep"),
    ):
        res = client._wait_for_wif_resource("http://test")
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

    with patch.object(client, "_api_call", side_effect=mock_api_call), patch.object(client, "_wait_for_lro"):
        with patch.object(client, "_api_call_with_retry", return_value={"projectNumber": "123"}):
            res = client.ensure_project("test-proj", folder="folder123")
            assert res == "123"


def test_enable_apis():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    with patch.object(client, "_api_call_with_retry", return_value={"name": "op1"}):
        with patch.object(client, "_wait_for_lro"):
            client.enable_apis("123", ["api1"])


def test_setup_wif_infrastructure():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    config = MagicMock()
    config.pool_id = "pool1"
    config.provider_id = "bunker-oidc-prov-1"
    config.project_id = "proj1"
    config.sa_name = "sa1"
    config.issuer_uri = "https://wif-bunker.internal/bunker-oidc-prov-1"

    jwks = {"keys": [{"kty": "EC", "crv": "P-256", "x": "aa", "y": "bb", "alg": "ES256", "kid": "k1", "use": "sig"}]}

    with patch.object(client, "_api_call_with_retry", return_value={"name": "op", "email": "sa@x.com"}) as mock_call:
        with patch.object(client, "_wait_for_lro"):
            with patch.object(client, "_wait_for_wif_resource"):
                sa_email, prov_id = client.setup_wif_infrastructure(config, "123", jwks, False, True)
                assert sa_email == "sa@x.com"
                assert prov_id == "bunker-oidc-prov-1"
                # Verify static-JWKS OIDC provider payload was sent
                prov_calls = [
                    c for c in mock_call.call_args_list if "providers?workloadIdentityPoolProviderId" in c[0][1]
                ]
                assert len(prov_calls) == 1
                payload = prov_calls[0][0][2]
                assert payload["oidc"]["issuerUri"] == config.issuer_uri
                assert "jwksJson" in payload["oidc"]
                assert payload["attributeMapping"] == {"google.subject": "assertion.sub"}


def test_apply_iam_bindings():
    with patch.object(GCPClient, "_oauth_user_token", return_value="tok"):
        client = GCPClient()

    config = MagicMock()
    config.project_id = "proj1"

    with patch.object(client, "_api_call_with_retry", return_value={"bindings": []}):
        client.apply_iam_bindings(config, "123", "cn1", "pool1", "sa@x.com", True)

        # Test reuse case
        client.apply_iam_bindings(config, "123", "cn1", "pool1", None, False)


class TestGCPClientAdcErrorsAndProviderEdgeCases:
    @pytest.mark.parametrize(
        ("exc", "match"),
        [
            (google.auth.exceptions.DefaultCredentialsError("missing"), "No Google credentials found"),
            (google.auth.exceptions.OAuthError("bad pool"), "WIF token exchange failed"),
            (google.auth.exceptions.RefreshError("revoked"), "Failed to refresh Google credentials"),
            (google.auth.exceptions.TransportError("offline"), "Network error during authentication"),
        ],
    )
    def test_use_adc_auth_errors_wrapped_as_runtime_error(self, exc, match):
        if isinstance(exc, google.auth.exceptions.DefaultCredentialsError):
            with patch("wif_bunker.gcp_client.google.auth.default", side_effect=exc):
                with pytest.raises(RuntimeError, match=match):
                    GCPClient(use_adc=True)
        else:
            mock_creds = MagicMock()
            mock_creds.refresh.side_effect = exc
            with patch("wif_bunker.gcp_client.google.auth.default", return_value=(mock_creds, None)):
                with pytest.raises(RuntimeError, match=match):
                    GCPClient(use_adc=True)

    def test_reuse_provider_non_404_error_reraises(self):
        client = GCPClient.__new__(GCPClient)
        resp_500 = MagicMock(status_code=500)
        http_500 = requests.exceptions.HTTPError("boom", response=resp_500)
        client._api_call_with_retry = MagicMock(side_effect=http_500)
        cfg = WorkloadConfig()
        cfg.project_id = "proj"
        cfg.pool_id = "pool"
        cfg.provider_id = "prov"
        with pytest.raises(requests.exceptions.HTTPError):
            client.setup_wif_infrastructure(
                cfg, "123", {"keys": []}, reuse_pool=True, use_sa=False, reuse_provider=True
            )

    def test_create_provider_non_409_error_reraises(self):
        client = GCPClient.__new__(GCPClient)
        resp_403 = MagicMock(status_code=403)
        http_403 = requests.exceptions.HTTPError("forbidden", response=resp_403)
        client._api_call_with_retry = MagicMock(side_effect=http_403)
        cfg = WorkloadConfig()
        cfg.project_id = "proj"
        cfg.pool_id = "pool"
        cfg.provider_id = "prov"
        with pytest.raises(requests.exceptions.HTTPError):
            client.setup_wif_infrastructure(
                cfg, "123", {"keys": []}, reuse_pool=True, use_sa=False, reuse_provider=False
            )

    def test_create_pool_409_soft_deleted_raises(self):
        client = GCPClient.__new__(GCPClient)
        resp_409 = MagicMock(status_code=409)
        http_409 = requests.exceptions.HTTPError("exists", response=resp_409)
        client._api_call_with_retry = MagicMock(side_effect=http_409)
        client._api_call = MagicMock(return_value={"state": "DELETED"})
        cfg = WorkloadConfig()
        cfg.project_id = "proj"
        cfg.pool_id = "pool"
        cfg.provider_id = "prov"
        with pytest.raises(RuntimeError, match="soft-deleted"):
            client.setup_wif_infrastructure(cfg, "123", {"keys": []}, reuse_pool=False, use_sa=False)
