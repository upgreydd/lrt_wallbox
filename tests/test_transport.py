"""Transport-level behaviour: success decode, error wrapping, kind mapping."""

import logging

import pytest
import requests

from lrt_wallbox import (
    WallboxClient,
    WallboxConnectionError,
    WallboxTimeoutError,
    WallboxError,
    WallboxPermissionError,
    WallboxNotFoundError,
)
from lrt_wallbox.msg_types import InfoSerialGetResponse

from .conftest import FakeResponse, ok, err


def test_send_decodes_dataclass(client, monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(ok({"serialNumber": "SN123"}))
    )
    result = client.info_serial_get()
    assert isinstance(result, InfoSerialGetResponse)
    assert result.serialNumber == "SN123"


def test_request_prefixes_key_and_sends_sessionid(client, monkeypatch):
    captured = {}

    def fake_post(url, headers=None, data=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResponse(ok({"serialNumber": "SN"}))

    monkeypatch.setattr(requests, "post", fake_post)
    client.info_serial_get()
    assert captured["url"] == "http://10.0.0.5/api"
    assert captured["headers"]["SESSIONID"] == client.session_id
    assert captured["headers"]["Content-Type"] == "application/cbor"


def test_timeout_is_wrapped(client, monkeypatch):
    def boom(*a, **k):
        raise requests.exceptions.ConnectTimeout("slow")

    monkeypatch.setattr(requests, "post", boom)
    with pytest.raises(WallboxTimeoutError) as exc:
        client.info_serial_get()
    assert isinstance(exc.value, WallboxError)  # subclass of the base


def test_connection_error_is_wrapped(client, monkeypatch):
    def boom(*a, **k):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(requests, "post", boom)
    with pytest.raises(WallboxConnectionError) as exc:
        client.info_serial_get()
    assert isinstance(exc.value, WallboxError)


def test_http_error_is_wrapped(client, monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse({"x": 1}, status_code=500)
    )
    with pytest.raises(WallboxConnectionError):
        client.info_serial_get()


def test_error_kind_maps_to_subclass(client, monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(err("NotFound", "no tag"))
    )
    with pytest.raises(WallboxNotFoundError) as exc:
        client.info_serial_get()
    assert exc.value.kind == "NotFound"
    assert exc.value.message == "no tag"


def test_unknown_kind_falls_back_to_base(client, monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(err("Weird"))
    )
    with pytest.raises(WallboxError) as exc:
        client.info_serial_get()
    # Base class, not one of the typed subclasses.
    assert type(exc.value) is WallboxError
    assert exc.value.kind == "Weird"


def test_permission_error_is_permission_subclass(client, monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(err("Permission"))
    )
    # No auth flags on info_serial_get → no retry → the Permission error surfaces.
    with pytest.raises(WallboxPermissionError):
        client.info_serial_get()


def test_password_not_logged_at_debug(client, monkeypatch, caplog):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(ok({"authenticated": True}))
    )
    with caplog.at_level(logging.DEBUG, logger="lrt_wallbox.wallbox"):
        client.auth_password("tester", "s3cr3t-password")
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "s3cr3t-password" not in joined
    assert "***" in joined  # redaction marker present
