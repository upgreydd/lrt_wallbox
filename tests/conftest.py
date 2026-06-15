"""Shared test helpers for the lrt_wallbox client.

All tests mock the HTTP transport (``requests.post``) so no device is needed.
"""

import cbor2
import pytest


class FakeResponse:
    """Minimal stand-in for ``requests.Response`` carrying CBOR content."""

    def __init__(self, payload, status_code=200):
        self.content = cbor2.dumps(payload)
        self.status_code = status_code
        self.ok = 200 <= status_code < 300

    def raise_for_status(self):
        if not self.ok:
            import requests

            raise requests.exceptions.HTTPError(f"status {self.status_code}")


@pytest.fixture
def client(tmp_path):
    """A WallboxClient whose keypair lives under a throwaway tmp dir."""
    from lrt_wallbox import WallboxClient

    return WallboxClient(
        ip="10.0.0.5",
        username="tester",
        password="hunter2",
        key_path=str(tmp_path / "keys"),
        session_valid=0.0,  # never cache auth, keeps tests deterministic
    )


def ok(body):
    """Build a successful device response envelope."""
    return {"key": "response/x", "body": body}


def err(kind, message="boom", field=None):
    """Build a device error response envelope."""
    return {"key": "response/x", "error": {"kind": kind, "message": message, "field": field}}
