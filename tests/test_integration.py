#!/usr/bin/env python3
"""
Integration tests for encrypted blob storage — tests against a live server.

Run with:
    pytest test_integration.py -v

Override the server URL with:
    BASE_URL=http://localhost:8080 pytest test_integration.py -v

These tests are safe to run against a production server. All test accounts use
randomly-generated credentials that will not collide with any real account
using a strong password.
"""

import os
import json
import secrets
import pytest
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")


@pytest.fixture(scope="session", autouse=True)
def check_server():
    try:
        requests.get(f"{BASE_URL}/_/login", timeout=5)
    except requests.ConnectionError:
        pytest.skip(f"Server not reachable at {BASE_URL}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def rand_creds():
    return secrets.token_hex(12), secrets.token_hex(12)


class Client:
    """Thin wrapper around requests.Session that handles login."""

    def __init__(self, username, password):
        self.base    = BASE_URL
        self.user    = username
        self.pw      = password
        self.session = requests.Session()

    def login(self, invite=None):
        data = {"username": self.user, "password": self.pw}
        if invite:
            data["invite"] = invite
        return self.session.post(f"{self.base}/_/login", data=data,
                                 allow_redirects=True)

    def get(self, path, **kw):
        return self.session.get(f"{self.base}/{path.lstrip('/')}", **kw)

    def put(self, path, data=b"", mime="application/octet-stream", **kw):
        headers = kw.pop("headers", {})
        headers.setdefault("Content-Type", mime)
        return self.session.put(f"{self.base}/{path.lstrip('/')}", data=data,
                                headers=headers, **kw)

    def delete(self, path):
        """Empty-body PUT = delete."""
        return self.session.put(f"{self.base}/{path.lstrip('/')}", data=b"",
                                headers={"Content-Type": "application/octet-stream"})

    def admin(self, **kw):
        return self.session.get(f"{self.base}/_/admin", **kw)

    def logout(self):
        return self.session.get(f"{self.base}/_/logout")


@pytest.fixture
def client():
    c = Client(*rand_creds())
    c.login()
    return c


@pytest.fixture
def two_clients():
    c1 = Client(*rand_creds())
    c2 = Client(*rand_creds())
    c1.login()
    c2.login()
    return c1, c2


# ═════════════════════════════════════════════════════════════════════════════
# Auth
# ═════════════════════════════════════════════════════════════════════════════

class TestAuth:
    def test_login_sets_cookie(self):
        c = Client(*rand_creds())
        r = c.login()
        assert r.status_code == 200
        assert "bs_session" in c.session.cookies

    def test_unauthenticated_redirects_to_login(self):
        s = requests.Session()
        r = s.get(f"{BASE_URL}/any/path", allow_redirects=False)
        assert r.status_code == 302
        assert "/_/login" in r.headers["Location"]

    def test_logout_clears_cookie(self, client):
        client.logout()
        r = client.admin(allow_redirects=False)
        assert r.status_code == 302

    def test_different_passwords_are_different_namespaces(self):
        u = secrets.token_hex(12)
        c1 = Client(u, secrets.token_hex(12))
        c2 = Client(u, secrets.token_hex(12))
        c1.login()
        c2.login()
        path = f"test/{secrets.token_hex(8)}.txt"
        c1.put(path, b"account1 only", "text/plain")
        r = c2.get(path)
        assert r.status_code == 404


# ═════════════════════════════════════════════════════════════════════════════
# Blob PUT / GET
# ═════════════════════════════════════════════════════════════════════════════

class TestBlobPutGet:
    def test_put_and_get_text(self, client):
        path = f"test/{secrets.token_hex(8)}.txt"
        client.put(path, b"hello integration", "text/plain")
        r = client.get(path)
        assert r.status_code == 200
        assert r.content == b"hello integration"
        assert "text/plain" in r.headers["Content-Type"]

    def test_put_and_get_binary(self, client):
        path = f"test/{secrets.token_hex(8)}.bin"
        data = secrets.token_bytes(512)
        client.put(path, data, "application/octet-stream")
        r = client.get(path)
        assert r.status_code == 200
        assert r.content == data

    def test_missing_path_returns_404(self, client):
        r = client.get(f"definitely/not/here/{secrets.token_hex(8)}.txt")
        assert r.status_code == 404

    def test_overwrite(self, client):
        path = f"test/{secrets.token_hex(8)}.txt"
        client.put(path, b"version 1", "text/plain")
        client.put(path, b"version 2", "text/plain")
        r = client.get(path)
        assert r.content == b"version 2"

    def test_namespace_isolation(self, two_clients):
        c1, c2 = two_clients
        path = f"shared/{secrets.token_hex(8)}.txt"
        c1.put(path, b"c1 secret", "text/plain")
        r = c2.get(path)
        assert r.status_code == 404

    def test_content_type_preserved(self, client):
        path = f"test/{secrets.token_hex(8)}.json"
        payload = json.dumps({"key": "value"}).encode()
        client.put(path, payload, "application/json")
        r = client.get(path)
        assert "application/json" in r.headers["Content-Type"]

    def test_large_blob(self, client):
        path = f"test/{secrets.token_hex(8)}.bin"
        data = secrets.token_bytes(1024 * 512)  # 512 KB
        client.put(path, data, "application/octet-stream")
        r = client.get(path)
        assert r.status_code == 200
        assert r.content == data

    def test_unicode_content(self, client):
        path = f"test/{secrets.token_hex(8)}.txt"
        text = "Hello 🌍 — café — naïve résumé".encode("utf-8")
        client.put(path, text, "text/plain")
        r = client.get(path)
        assert r.content == text

    def test_reserved_path_blocked(self, client):
        r = client.put("_/locked", b"anything", "text/plain")
        assert r.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# Delete
# ═════════════════════════════════════════════════════════════════════════════

class TestBlobDelete:
    def test_delete_existing(self, client):
        path = f"test/{secrets.token_hex(8)}.txt"
        client.put(path, b"to be deleted", "text/plain")
        r = client.delete(path)
        assert r.status_code == 204
        assert client.get(path).status_code == 404

    def test_delete_missing_returns_404(self, client):
        r = client.delete(f"test/{secrets.token_hex(8)}_nonexistent.txt")
        assert r.status_code == 404

    def test_delete_only_affects_own_namespace(self, two_clients):
        c1, c2 = two_clients
        path = f"shared/{secrets.token_hex(8)}.txt"
        c1.put(path, b"c1 data", "text/plain")
        c2.put(path, b"c2 data", "text/plain")
        c1.delete(path)
        r = c2.get(path)
        assert r.status_code == 200
        assert r.content == b"c2 data"


# ═════════════════════════════════════════════════════════════════════════════
# HTTP Range support
# ═════════════════════════════════════════════════════════════════════════════

class TestRange:
    def test_range_middle(self, client):
        path = f"test/{secrets.token_hex(8)}.bin"
        client.put(path, b"0123456789abcdef", "application/octet-stream")
        r = client.get(path, headers={"Range": "bytes=4-7"})
        assert r.status_code == 206
        assert r.content == b"4567"

    def test_range_from_start(self, client):
        path = f"test/{secrets.token_hex(8)}.bin"
        client.put(path, b"abcdefghij", "application/octet-stream")
        r = client.get(path, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        assert r.content == b"abcd"

    def test_range_to_end(self, client):
        path = f"test/{secrets.token_hex(8)}.bin"
        client.put(path, b"abcdefghij", "application/octet-stream")
        r = client.get(path, headers={"Range": "bytes=7-9"})
        assert r.status_code == 206
        assert r.content == b"hij"

    def test_invalid_range(self, client):
        path = f"test/{secrets.token_hex(8)}.bin"
        client.put(path, b"short", "application/octet-stream")
        r = client.get(path, headers={"Range": "bytes=100-200"})
        assert r.status_code == 416


# ═════════════════════════════════════════════════════════════════════════════
# Lock
# ═════════════════════════════════════════════════════════════════════════════

class TestLock:
    def _lock(self, client, wp):
        return client.session.post(f"{BASE_URL}/_/admin",
                                   data={"action": "lock", "wp": wp, "wp2": wp})

    def _unlock(self, client, wp):
        return client.session.post(f"{BASE_URL}/_/admin",
                                   data={"action": "remove_lock", "wp": wp})

    def test_locked_namespace_rejects_put(self, client):
        self._lock(client, "writepass123")
        r = client.put(f"test/{secrets.token_hex(8)}.txt", b"blocked", "text/plain")
        assert r.status_code == 403
        self._unlock(client, "writepass123")

    def test_locked_namespace_allows_get(self, client):
        path = f"test/{secrets.token_hex(8)}.txt"
        client.put(path, b"readable", "text/plain")
        self._lock(client, "writepass456")
        r = client.get(path)
        assert r.status_code == 200
        assert r.content == b"readable"
        self._unlock(client, "writepass456")

    def test_unlock_wrong_password_fails(self, client):
        self._lock(client, "correctpass")
        r = self._unlock(client, "wrongpass")
        assert "Incorrect" in r.text
        self._unlock(client, "correctpass")

    def test_lock_isolated_between_namespaces(self, two_clients):
        c1, c2 = two_clients
        self._lock(c1, "wp")
        r = c2.put(f"test/{secrets.token_hex(8)}.txt", b"c2 unaffected", "text/plain")
        assert r.status_code == 201
        self._unlock(c1, "wp")


# ═════════════════════════════════════════════════════════════════════════════
# Index
# ═════════════════════════════════════════════════════════════════════════════

class TestIndex:
    def _create_index(self, client):
        for _ in range(2):
            client.session.put(f"{BASE_URL}/_/index",
                               data=json.dumps({"files": {}}).encode(),
                               headers={"Content-Type": "application/json"})

    def test_index_not_enabled_by_default(self, client):
        r = client.admin()
        assert "Index not enabled" in r.text

    def test_index_create_appears_in_admin(self, client):
        self._create_index(client)
        r = client.admin()
        assert "Index not enabled" not in r.text

    def test_uploaded_file_appears_in_index(self, client):
        self._create_index(client)
        path = f"indexed/{secrets.token_hex(8)}.txt"
        client.put(path, b"indexed content", "text/plain")
        r = client.admin()
        assert path in r.text

    def test_deleted_file_removed_from_index(self, client):
        self._create_index(client)
        path = f"indexed/{secrets.token_hex(8)}.txt"
        client.put(path, b"will be deleted", "text/plain")
        client.delete(path)
        r = client.admin()
        assert path not in r.text

    def test_index_isolated_between_namespaces(self, two_clients):
        c1, c2 = two_clients
        self._create_index(c1)
        path = f"private/{secrets.token_hex(8)}.txt"
        c1.put(path, b"c1 private", "text/plain")
        r = c2.admin()
        assert path not in r.text


# ═════════════════════════════════════════════════════════════════════════════
# Admin page
# ═════════════════════════════════════════════════════════════════════════════

class TestAdmin:
    def test_admin_accessible_when_logged_in(self, client):
        r = client.admin()
        assert r.status_code == 200

    def test_admin_shows_username(self):
        u, p = rand_creds()
        c = Client(u, p)
        c.login()
        r = c.admin()
        assert u in r.text

    def test_admin_redirects_when_not_logged_in(self):
        r = requests.get(f"{BASE_URL}/_/admin", allow_redirects=False)
        assert r.status_code == 302