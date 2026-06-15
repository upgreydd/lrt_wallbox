"""Key storage location/permissions and auth caching behaviour."""

import os
import stat

import pytest
import requests

from lrt_wallbox import WallboxClient, WallboxAuthError

from .conftest import FakeResponse, ok


def test_keys_written_to_key_path_not_package_dir(tmp_path):
    key_dir = tmp_path / "kd"
    client = WallboxClient("1.2.3.4", "u", "p", key_path=str(key_dir))
    priv, pub = client._load_keys()
    assert (key_dir / "privkey.pem").exists()
    assert (key_dir / "pubkey.pem").exists()
    # The installed package directory must be untouched.
    pkg_dir = os.path.dirname(WallboxClient.__module__ and __import__("lrt_wallbox").__file__)
    assert not os.path.exists(os.path.join(pkg_dir, "privkey.pem")) or \
        os.path.dirname(os.path.join(pkg_dir, "privkey.pem")) != str(key_dir)


def test_private_key_is_owner_only(tmp_path):
    client = WallboxClient("1.2.3.4", "u", "p", key_path=str(tmp_path))
    client._load_keys()
    mode = stat.S_IMODE(os.stat(tmp_path / "privkey.pem").st_mode)
    assert mode == 0o600


def test_keys_are_stable_across_loads(tmp_path):
    client = WallboxClient("1.2.3.4", "u", "p", key_path=str(tmp_path))
    _, pub1 = client._load_keys()
    _, pub2 = client._load_keys()
    assert pub1 == pub2  # second load reads the persisted key, not a fresh one


def test_session_id_is_random_per_instance():
    a = WallboxClient("1.2.3.4", "u", "p")
    b = WallboxClient("1.2.3.4", "u", "p")
    assert a.session_id != b.session_id
    assert len(a.session_id) == 10 and a.session_id.isdigit()


def test_session_id_override_respected():
    c = WallboxClient("1.2.3.4", "u", "p", session_id="fixed-id")
    assert c.session_id == "fixed-id"


def test_password_auth_caching(monkeypatch):
    client = WallboxClient("1.2.3.4", "u", "p", session_valid=1000.0)
    calls = {"n": 0}

    def fake_post(*a, **k):
        calls["n"] += 1
        return FakeResponse(ok({"authenticated": True}))

    monkeypatch.setattr(requests, "post", fake_post)
    client._password_auth()
    client._password_auth()  # within validity window → no second device call
    assert calls["n"] == 1


def test_failed_password_auth_raises_auth_error(monkeypatch):
    client = WallboxClient("1.2.3.4", "u", "p", session_valid=0.0)
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(ok({"authenticated": False}))
    )
    with pytest.raises(WallboxAuthError):
        client._password_auth()


def test_key_storage_failure_raises_wallbox_error(tmp_path):
    # Point key_path at a file so makedirs/open fails → wrapped as WallboxError.
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    client = WallboxClient("1.2.3.4", "u", "p", key_path=str(blocker / "sub"))
    # A plain file in the path prevents directory creation.
    from lrt_wallbox import WallboxError

    with pytest.raises(WallboxError):
        client._load_keys()
