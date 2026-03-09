"""
Unit tests for encrypted blob storage — mechanics and correctness.

Tests crypto primitives, blob storage, index, lock, and session cookie
in isolation. Each test is self-contained: it creates whatever state it
needs and leaves nothing behind (temp_db fixture in conftest.py handles
database isolation per test).

Run with:
    uv run pytest tests/test_unit.py -v --cov=encrypted_blob_server
"""

import json
import hmac
import struct
import secrets
import sqlite3
import pytest
from base64 import b64encode

import encrypted_blob_server.app as server


# ── Helpers ───────────────────────────────────────────────────────────────────

def rand_creds():
    return secrets.token_hex(12), secrets.token_hex(12)

def token_for(username, password):
    return server.derive_session_token(username, password)


# ═════════════════════════════════════════════════════════════════════════════
# Key derivation
# ═════════════════════════════════════════════════════════════════════════════

class TestDeriveSessionToken:
    def test_returns_32_bytes(self):
        assert len(token_for("alice", "hunter2")) == 32

    def test_deterministic(self):
        assert token_for("alice", "hunter2") == token_for("alice", "hunter2")

    def test_different_password_different_token(self):
        assert token_for("alice", "pass1") != token_for("alice", "pass2")

    def test_different_username_different_token(self):
        assert token_for("alice", "pass") != token_for("bob", "pass")

    def test_username_and_password_not_independently_separable(self):
        # "ali" + "ce:pass" must not produce the same token as "alice" + ":pass"
        # (i.e. the separator is included in the derivation input)
        assert token_for("ali", "ce:pass") != token_for("alice", "pass")


class TestDeriveWriteKey:
    def test_returns_32_bytes(self):
        assert len(server.derive_write_key("alice", "wp")) == 32

    def test_distinct_from_session_token(self):
        assert token_for("alice", "pass") != server.derive_write_key("alice", "pass")

    def test_deterministic(self):
        assert (server.derive_write_key("alice", "wp") ==
                server.derive_write_key("alice", "wp"))


# ═════════════════════════════════════════════════════════════════════════════
# Encryption / decryption
# ═════════════════════════════════════════════════════════════════════════════

class TestEncryptDecrypt:
    def test_roundtrip(self):
        key = secrets.token_bytes(32)
        nonce, ct = server.encrypt(key, b"hello")
        assert server.decrypt(key, nonce, ct) == b"hello"

    def test_roundtrip_with_aad(self):
        key = secrets.token_bytes(32)
        nonce, ct = server.encrypt(key, b"hello", b"aad")
        assert server.decrypt(key, nonce, ct, b"aad") == b"hello"

    def test_wrong_aad_raises(self):
        key = secrets.token_bytes(32)
        nonce, ct = server.encrypt(key, b"hello", b"correct")
        with pytest.raises(Exception):
            server.decrypt(key, nonce, ct, b"wrong")

    def test_wrong_key_raises(self):
        k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
        nonce, ct = server.encrypt(k1, b"hello")
        with pytest.raises(Exception):
            server.decrypt(k2, nonce, ct)

    def test_nonce_is_random_each_call(self):
        key = secrets.token_bytes(32)
        n1, _ = server.encrypt(key, b"hello")
        n2, _ = server.encrypt(key, b"hello")
        assert n1 != n2


# ═════════════════════════════════════════════════════════════════════════════
# Path hashing
# ═════════════════════════════════════════════════════════════════════════════

class TestPathHash:
    def test_deterministic(self):
        key = secrets.token_bytes(32)
        assert server.path_hash(key, "a/b") == server.path_hash(key, "a/b")

    def test_different_path_different_hash(self):
        key = secrets.token_bytes(32)
        assert server.path_hash(key, "a/b") != server.path_hash(key, "a/c")

    def test_different_key_different_hash(self):
        k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
        assert server.path_hash(k1, "a/b") != server.path_hash(k2, "a/b")

    def test_namespace_scoped(self):
        t1 = token_for(*rand_creds())
        t2 = token_for(*rand_creds())
        k1 = server.enc_key(t1)
        k2 = server.enc_key(t2)
        assert server.path_hash(k1, "index.html") != server.path_hash(k2, "index.html")


# ═════════════════════════════════════════════════════════════════════════════
# Blob put / get / delete
# ═════════════════════════════════════════════════════════════════════════════

class TestBlobPutGet:
    def test_roundtrip(self):
        token = token_for(*rand_creds())
        server.blob_put(token, "hello.txt", b"hello", "text/plain")
        mime, data = server.blob_get(token, "hello.txt")
        assert mime == "text/plain"
        assert data == b"hello"

    def test_missing_returns_none(self):
        token = token_for(*rand_creds())
        mime, data = server.blob_get(token, "does/not/exist.bin")
        assert mime is None and data is None

    def test_overwrite(self):
        token = token_for(*rand_creds())
        server.blob_put(token, "f.txt", b"v1", "text/plain")
        server.blob_put(token, "f.txt", b"v2", "text/plain")
        _, data = server.blob_get(token, "f.txt")
        assert data == b"v2"

    def test_binary_roundtrip(self):
        token = token_for(*rand_creds())
        data = secrets.token_bytes(4096)
        server.blob_put(token, "bin.bin", data, "application/octet-stream")
        _, result = server.blob_get(token, "bin.bin")
        assert result == data

    def test_namespace_isolation(self):
        t1, t2 = token_for(*rand_creds()), token_for(*rand_creds())
        server.blob_put(t1, "file.txt", b"secret", "text/plain")
        mime, _ = server.blob_get(t2, "file.txt")
        assert mime is None

    def test_same_username_different_password_isolated(self):
        u = secrets.token_hex(8)
        t1 = token_for(u, "pass1")
        t2 = token_for(u, "pass2")
        server.blob_put(t1, "file.txt", b"for pass1 only", "text/plain")
        mime, _ = server.blob_get(t2, "file.txt")
        assert mime is None


class TestBlobDelete:
    def test_delete_existing(self):
        token = token_for(*rand_creds())
        server.blob_put(token, "bye.txt", b"bye", "text/plain")
        assert server.blob_del(token, "bye.txt") is True
        assert server.blob_get(token, "bye.txt") == (None, None)

    def test_delete_missing_returns_false(self):
        token = token_for(*rand_creds())
        assert server.blob_del(token, "never.txt") is False

    def test_delete_does_not_affect_other_namespace(self):
        t1, t2 = token_for(*rand_creds()), token_for(*rand_creds())
        server.blob_put(t1, "shared.txt", b"t1", "text/plain")
        server.blob_put(t2, "shared.txt", b"t2", "text/plain")
        server.blob_del(t1, "shared.txt")
        mime, data = server.blob_get(t2, "shared.txt")
        assert mime == "text/plain" and data == b"t2"


# ═════════════════════════════════════════════════════════════════════════════
# Index
# ═════════════════════════════════════════════════════════════════════════════

class TestIndex:
    def _make_index(self, token):
        server.blob_put(token, server.INDEX_PATH,
                        json.dumps({"files": {}}).encode(), "application/json")

    def test_none_by_default(self):
        assert server.index_get(token_for(*rand_creds())) is None

    def test_create_and_retrieve(self):
        token = token_for(*rand_creds())
        self._make_index(token)
        idx = server.index_get(token)
        assert idx is not None and idx["files"] == {}

    def test_add_entry(self):
        token = token_for(*rand_creds())
        self._make_index(token)
        server.index_update(token, add="img/cat.jpg", size=1234)
        idx = server.index_get(token)
        assert idx is not None
        assert "img/cat.jpg" in idx["files"]
        assert idx["files"]["img/cat.jpg"]["size"] == 1234

    def test_remove_entry(self):
        token = token_for(*rand_creds())
        server.blob_put(token, server.INDEX_PATH,
                        json.dumps({"files": {"a.txt": {"size": 1, "uploaded": "2024-01-01 00:00"}}}).encode(),
                        "application/json")
        server.index_update(token, remove="a.txt")
        idx = server.index_get(token)
        assert idx is not None
        assert "a.txt" not in idx["files"]

    def test_update_noop_without_index(self):
        token = token_for(*rand_creds())
        server.index_update(token, add="file.txt", size=100)  # must not raise
        assert server.index_get(token) is None


# ═════════════════════════════════════════════════════════════════════════════
# Lock
# ═════════════════════════════════════════════════════════════════════════════

class TestLock:
    def test_not_locked_by_default(self):
        assert server.lock_exists(token_for(*rand_creds())) is False

    def test_create_and_exists(self):
        u, p = rand_creds()
        token = token_for(u, p)
        server.lock_create(token, u, "wp")
        assert server.lock_exists(token) is True

    def test_verify_correct_password(self):
        u, p = rand_creds()
        token = token_for(u, p)
        server.lock_create(token, u, "wp")
        assert server.lock_verify(token, u, "wp") is True

    def test_verify_wrong_password(self):
        u, p = rand_creds()
        token = token_for(u, p)
        server.lock_create(token, u, "wp")
        assert server.lock_verify(token, u, "wrong") is False

    def test_remove(self):
        u, p = rand_creds()
        token = token_for(u, p)
        server.lock_create(token, u, "wp")
        server.lock_remove(token)
        assert server.lock_exists(token) is False

    def test_isolated_between_namespaces(self):
        u1, p1 = rand_creds()
        u2, p2 = rand_creds()
        t1 = token_for(u1, p1)
        t2 = token_for(u2, p2)
        server.lock_create(t1, u1, "wp")
        assert server.lock_exists(t2) is False


# ═════════════════════════════════════════════════════════════════════════════
# Session cookie
# ═════════════════════════════════════════════════════════════════════════════

class TestCookie:
    def _request_with_cookie(self, cookie_value):
        """Return get_token() result inside a fake request context."""
        with server.app.test_request_context(
            headers={"Cookie": f"{server.SESSION_COOKIE}={cookie_value}"}
        ):
            return server.get_token()

    def test_valid_cookie_returns_token(self):
        token = secrets.token_bytes(32)
        cookie = server._make_cookie(token)
        assert self._request_with_cookie(cookie) == token

    def test_expired_cookie_rejected(self):
        token = secrets.token_bytes(32)
        expiry_bytes = struct.pack(">I", 1)  # Unix epoch + 1s — always expired
        msg = token + expiry_bytes
        sig = hmac.digest(server._cookie_hmac_key, msg, "sha256")
        cookie = b64encode(msg + sig).decode()
        assert self._request_with_cookie(cookie) is None

    def test_tampered_token_rejected(self):
        import base64
        token = secrets.token_bytes(32)
        cookie = server._make_cookie(token)
        # LOL, claude:
        #raw = bytearray(b64encode.__module__ and __import__('base64').b64decode(cookie))
        raw = bytearray(base64.b64decode(cookie))
        raw[0] ^= 0xFF
        tampered = base64.b64encode(bytes(raw)).decode()
        assert self._request_with_cookie(tampered) is None

    def test_tampered_expiry_rejected(self):
        """Bumping the expiry timestamp must invalidate the HMAC."""
        import base64, struct
        token = secrets.token_bytes(32)
        cookie = server._make_cookie(token)
        raw = bytearray(base64.b64decode(cookie))
        # Bytes 32-35 are the expiry — set to far future
        raw[32:36] = struct.pack(">I", 0xFFFFFFFF)
        tampered = base64.b64encode(bytes(raw)).decode()
        assert self._request_with_cookie(tampered) is None

    def test_wrong_length_rejected(self):
        cookie = b64encode(secrets.token_bytes(20)).decode()
        assert self._request_with_cookie(cookie) is None

    def test_each_cookie_has_unique_token_bytes(self):
        # _make_cookie is deterministic for same token — but two different
        # tokens must produce different cookies
        t1, t2 = secrets.token_bytes(32), secrets.token_bytes(32)
        assert server._make_cookie(t1) != server._make_cookie(t2)
        