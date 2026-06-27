from __future__ import annotations

from ai_diffusion.backend.comfy_client import ComfyClient, websocket_args
from ai_diffusion.backend.network import RequestManager


# ---------------------------------------------------------------------------
# Test RequestManager Auth Header Injection
# ---------------------------------------------------------------------------
def test_request_manager_bearer_auth():
    rm = RequestManager()
    rm.set_auth("my-jwt-token-123")

    # Access private method to construct a request
    # _prepare_request returns a QNetworkRequest
    request = rm._prepare_request("http://127.0.0.1:8188/system_stats")

    assert request.hasRawHeader(b"Authorization")
    assert request.rawHeader(b"Authorization") == b"Bearer my-jwt-token-123"


def test_request_manager_override_auth():
    rm = RequestManager()
    rm.set_auth("default-token")

    # Passing explicit bearer to _prepare_request should override default
    request = rm._prepare_request("http://127.0.0.1:8188/system_stats", bearer="override-token")

    assert request.hasRawHeader(b"Authorization")
    assert request.rawHeader(b"Authorization") == b"Bearer override-token"


# ---------------------------------------------------------------------------
# Test ComfyClient Auth Initialization
# ---------------------------------------------------------------------------
def test_comfy_client_http_auth_setup():
    token = "secret-token-comfy"
    client = ComfyClient("http://127.0.0.1:8188", access_token=token)

    # Verify that the token is set on RequestManager
    assert client._token == token
    request = client._requests._prepare_request("http://127.0.0.1:8188/system_stats")
    assert request.hasRawHeader(b"Authorization")
    assert request.rawHeader(b"Authorization") == b"Bearer secret-token-comfy"


def test_comfy_client_websocket_args():
    token = "websocket-jwt-token"
    args = websocket_args(token)

    assert "additional_headers" in args
    assert args["additional_headers"] == {"Authorization": "Bearer websocket-jwt-token"}
    assert args["max_size"] == 2**30
    assert args["ping_timeout"] == 60


def test_comfy_client_websocket_args_empty():
    args = websocket_args("")
    assert "additional_headers" not in args
    assert args["max_size"] == 2**30
    assert args["ping_timeout"] == 60
