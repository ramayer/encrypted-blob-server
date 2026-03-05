#!/usr/bin/env python3
"""
Encrypted Blob Storage Server

Each username+password combination derives a unique encryption key via PBKDF2.
Blobs are stored encrypted in SQLite; credentials are never stored anywhere.
Different credentials = completely isolated, indistinguishable namespaces.

Reserved paths (not writable via PUT):
  /_/locked   — lock blob (write-protection state)
  /_/index    — index blob (file listing + metadata)

UI routes:
  /_/login
  /_/logout
  /_/readonly   — set/unset write lock
  /_/index      — file manager home page
"""

import sqlite3
import hashlib
import secrets
import threading
from pathlib import Path
from base64 import b64encode, b64decode
from datetime import datetime, timezone
from flask import Flask, request, make_response, Response, redirect, render_template_string
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hmac
import json

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COOKIE_NAME       = "blob_session"
WRITE_COOKIE_NAME = "blob_write"
COOKIE_MAX_AGE    = 3600 * 24  # 24 hours

# Change this in production — it salts every derived key in the system.
STATIC_SALT = b"encrypted-blob-storage-v1-salt-change-in-production"

# Reserved internal paths — protected from direct user writes.
LOCK_PATH  = "_/locked"
INDEX_PATH = "_/index"
RESERVED_PATHS = {LOCK_PATH, INDEX_PATH}


# ---------------------------------------------------------------------------
# Write-session store
#
# Maps a random write-token (str) → namespace_id (bytes).
# A write-token is set when the user proves knowledge of the write password.
# Server restart clears all write sessions, which is acceptable behaviour.
# ---------------------------------------------------------------------------

_write_sessions: dict[str, bytes] = {}
_write_sessions_lock = threading.Lock()


def _create_write_session(namespace_id: bytes) -> str:
    """Mint a new write token for this namespace and store it."""
    token = secrets.token_hex(32)
    with _write_sessions_lock:
        _write_sessions[token] = namespace_id
    return token


def _check_write_session(token: str, namespace_id: bytes) -> bool:
    """Return True if token grants write access to this namespace."""
    with _write_sessions_lock:
        stored = _write_sessions.get(token)
    return stored is not None and hmac.compare_digest(stored, namespace_id)


def _revoke_write_session(token: str):
    with _write_sessions_lock:
        _write_sessions.pop(token, None)


# ---------------------------------------------------------------------------
# Blob cache
#
# Keyed on (path_hash_b64, db_path) — never on the raw session token.
# Thread-safe via a simple lock around the dict.
# ---------------------------------------------------------------------------

_blob_cache: dict[tuple, tuple[str, bytes]] = {}
_blob_cache_lock = threading.Lock()
_CACHE_MAX_ENTRIES = 64


def _cache_get(path_hash_b64: str, db_path: str) -> tuple[str, bytes] | None:
    with _blob_cache_lock:
        return _blob_cache.get((path_hash_b64, db_path))


def _cache_set(path_hash_b64: str, db_path: str, mime: str, content: bytes):
    with _blob_cache_lock:
        if len(_blob_cache) >= _CACHE_MAX_ENTRIES:
            # Evict the oldest entry (insertion-ordered dict, Python 3.7+)
            _blob_cache.pop(next(iter(_blob_cache)))
        _blob_cache[(path_hash_b64, db_path)] = (mime, content)


def _cache_invalidate(path_hash_b64: str, db_path: str):
    with _blob_cache_lock:
        _blob_cache.pop((path_hash_b64, db_path), None)


def _cache_clear():
    with _blob_cache_lock:
        _blob_cache.clear()


# ---------------------------------------------------------------------------
# HTML Assets
# ---------------------------------------------------------------------------

class HtmlAssets:
    """HTML templates and shared styling."""

    COMMON_STYLE = """
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            max-width: 500px;
            margin: 80px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .box {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { margin-top: 0; color: #333; font-size: 24px; }
        h2 { color: #444; font-size: 18px; margin-top: 30px; }
        p  { color: #666; line-height: 1.5; }
        input[type="text"],
        input[type="password"],
        input[type="file"] {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            box-sizing: border-box;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        input:focus { outline: none; border-color: #007bff; }
        button {
            width: 100%;
            padding: 12px 20px;
            background: #007bff;
            color: white;
            border: none;
            cursor: pointer;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            margin-top: 8px;
        }
        button:hover    { background: #0056b3; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
        button.danger   { background: #dc3545; }
        button.danger:hover { background: #a71d2a; }
        button.secondary { background: #6c757d; }
        button.secondary:hover { background: #545b62; }
        .note {
            font-size: 12px;
            color: #888;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        pre {
            background: #f4f4f4;
            padding: 12px;
            border-radius: 4px;
            font-size: 12px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        a { color: #007bff; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
        .nav {
            display: flex;
            gap: 16px;
            margin-bottom: 24px;
            font-size: 14px;
        }
        .status-badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-locked   { background: #ffeeba; color: #856404; }
        .status-unlocked { background: #d4edda; color: #155724; }
    """

    LOGIN_FORM = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login — Encrypted Blob Storage</title>
        <style>""" + COMMON_STYLE + """</style>
    </head>
    <body>
        <div class="box">
            <h1>🔐 Login</h1>
            <p>Each username + password combination opens a unique encrypted namespace.
               Your credentials are never stored — only a derived session token.</p>
            <form method="POST" action="/_/login?next={{ next_url }}">
                <input type="text"     name="username" placeholder="Username" required autofocus>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" id="loginBtn" onclick="this.disabled=true;this.textContent='Logging in…';this.form.submit();">
                    Login
                </button>
            </form>
            <div class="note">
                Different username/password combinations access completely separate,
                indistinguishable storage spaces.
            </div>
        </div>
    </body>
    </html>
    """

    LOGOUT_PAGE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logged Out</title>
        <style>""" + COMMON_STYLE + """
            .box { text-align: center; }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>👋 Logged Out</h1>
            <p>Your session has been cleared.</p>
            <p><a href="/_/login">Login again</a></p>
        </div>
    </body>
    </html>
    """

    INDEX_PAGE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Index</title>
        <style>""" + COMMON_STYLE + """
            body { max-width: 700px; }
            table { width: 100%; border-collapse: collapse; margin-top: 16px; }
            th {
                text-align: left;
                font-size: 12px;
                color: #888;
                font-weight: 600;
                padding: 6px 8px;
                border-bottom: 2px solid #eee;
            }
            td {
                padding: 10px 8px;
                border-bottom: 1px solid #f0f0f0;
                font-size: 14px;
                vertical-align: middle;
            }
            td.path a { color: #333; font-weight: 500; }
            td.meta   { color: #999; font-size: 12px; white-space: nowrap; }
            td.action { width: 40px; text-align: right; }
            .del-btn {
                background: none;
                border: none;
                cursor: pointer;
                color: #ccc;
                font-size: 16px;
                padding: 4px 6px;
                width: auto;
                margin: 0;
                border-radius: 4px;
            }
            .del-btn:hover { color: #dc3545; background: #fff0f0; }
            .empty { color: #999; font-style: italic; padding: 20px 0; }
            .upload-area {
                margin-top: 30px;
                padding: 24px;
                background: #f8f9fa;
                border-radius: 8px;
                border: 2px dashed #dee2e6;
            }
            .lock-status { margin-bottom: 16px; }
        </style>
    </head>
    <body>
        <div class="nav">
            <a href="/_/index">📁 Index</a>
            <a href="/_/readonly">🔒 Access</a>
            <a href="/_/logout">Logout</a>
        </div>

        <div class="lock-status">
            {% if locked %}
                <span class="status-badge status-locked">🔒 Read-only</span>
                {% if write_enabled %}
                    <span class="status-badge status-unlocked" style="margin-left:8px">✏️ Write unlocked</span>
                {% endif %}
            {% else %}
                <span class="status-badge status-unlocked">✏️ Writable</span>
            {% endif %}
        </div>

        <h1>File Index</h1>

        {% if files %}
        <table>
            <tr>
                <th>Path</th>
                <th>Size</th>
                <th>Uploaded</th>
                <th></th>
            </tr>
            {% for f in files %}
            <tr id="row-{{ loop.index }}">
                <td class="path"><a href="/{{ f.path }}">{{ f.path }}</a></td>
                <td class="meta">{{ f.size }}</td>
                <td class="meta">{{ f.uploaded }}</td>
                <td class="action">
                    <button class="del-btn" title="Delete" onclick="deleteBlob('{{ f.path }}', 'row-{{ loop.index }}')">🗑</button>
                </td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
            <p class="empty">No files yet.</p>
        {% endif %}

        <div class="upload-area">
            <h2 style="margin-top:0">📤 Upload</h2>
            <input type="file" id="fileInput">
            <input type="text"  id="pathInput" placeholder="Path (e.g. images/photo.jpg)">
            <button id="uploadBtn" onclick="uploadFile()">Upload</button>
            <div class="note">
                You can also upload with curl:<br>
                <pre>curl -c cookies.txt -d 'username=alice&password=secret' http://localhost:5000/_/login
curl -b cookies.txt -X PUT --data-binary @file.mp4 \\
     -H 'Content-Type: video/mp4' http://localhost:5000/videos/movie.mp4</pre>
            </div>
        </div>

        <script>
        async function deleteBlob(path, rowId) {
            if (!confirm("Delete /" + path + "?")) return;
            const resp = await fetch("/" + path, { method: "PUT", body: "" });
            if (resp.status === 204) {
                const row = document.getElementById(rowId);
                if (row) row.remove();
            } else {
                alert("Delete failed: " + resp.statusText);
            }
        }

        async function uploadFile() {
            const file = document.getElementById("fileInput").files[0];
            const pathVal = document.getElementById("pathInput").value.trim();
            const btn = document.getElementById("uploadBtn");

            if (!file) { alert("Choose a file first."); return; }

            let path = pathVal || file.name;
            // strip leading slash
            path = path.replace(/^\\/+/, "");

            btn.disabled = true;
            btn.textContent = "Uploading…";

            try {
                const resp = await fetch("/" + path, {
                    method: "PUT",
                    body: file,
                    headers: { "Content-Type": file.type || "application/octet-stream" }
                });
                if (resp.ok) {
                    window.location.reload();
                } else {
                    const msg = await resp.text();
                    alert("Upload failed: " + msg);
                    btn.disabled = false;
                    btn.textContent = "Upload";
                }
            } catch (err) {
                alert("Upload error: " + err.message);
                btn.disabled = false;
                btn.textContent = "Upload";
            }
        }
        </script>
    </body>
    </html>
    """

    NOT_FOUND_PAGE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Not Found — {{ path }}</title>
        <style>""" + COMMON_STYLE + """
            body { max-width: 700px; }
            h1 { color: #dc3545; }
        </style>
    </head>
    <body>
        <div class="nav">
            <a href="/_/index">📁 Index</a>
            <a href="/_/logout">Logout</a>
        </div>
        <h1>404 — Not Found</h1>
        <p>No blob at <code>/{{ path }}</code> in your namespace.</p>
        <p><a href="/_/index">Go to file index</a> to upload or browse files.</p>
    </body>
    </html>
    """

    READONLY_PAGE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Access Control</title>
        <style>""" + COMMON_STYLE + """</style>
    </head>
    <body>
        <div class="nav">
            <a href="/_/index">📁 Index</a>
            <a href="/_/logout">Logout</a>
        </div>
        <div class="box">
            <h1>🔒 Access Control</h1>

            {% if locked %}
                <p>This namespace is <strong>locked (read-only)</strong>.</p>
                {% if write_enabled %}
                    <p>You have write access for this session.</p>
                    <form method="POST">
                        <input type="hidden" name="action" value="relock">
                        <button class="danger" type="submit">Revoke write access</button>
                    </form>
                {% else %}
                    <p>Enter your write password to unlock writes for this session.</p>
                    <form method="POST">
                        <input type="hidden" name="action" value="unlock">
                        <input type="password" name="write_password" placeholder="Write password" required autofocus>
                        <button type="submit">Unlock writes</button>
                    </form>
                {% endif %}

                <h2>Remove lock entirely</h2>
                <p>This permanently removes write protection from the namespace.</p>
                <form method="POST">
                    <input type="hidden" name="action" value="remove_lock">
                    <input type="password" name="write_password" placeholder="Write password" required>
                    <button class="danger" type="submit">Remove lock</button>
                </form>

            {% else %}
                <p>This namespace is <strong>unlocked</strong>. Anyone with the session cookie can write.</p>
                <p>Set a write password to make the namespace read-only by default,
                   requiring a separate password to make changes.</p>
                <form method="POST">
                    <input type="hidden" name="action" value="lock">
                    <input type="password" name="write_password" placeholder="Write password" required autofocus>
                    <input type="password" name="write_password2" placeholder="Confirm write password" required>
                    <button type="submit">Enable write lock</button>
                </form>
            {% endif %}

            {% if message %}
                <p style="margin-top:20px; color: {% if error %}#dc3545{% else %}#155724{% endif %}">
                    {{ message }}
                </p>
            {% endif %}
        </div>
    </body>
    </html>
    """


# ---------------------------------------------------------------------------
# CryptoManager
# ---------------------------------------------------------------------------

class CryptoManager:
    """Handles all encryption/decryption operations for a session."""

    def __init__(self, session_token: bytes):
        # Derive encryption key from session token (fast SHA-256, done once)
        self.key = hashlib.sha256(b"encryption:" + session_token).digest()
        self.cipher = ChaCha20Poly1305(self.key)
        # A stable namespace identifier — used for write-session scoping.
        # Derived separately so we never expose the encryption key.
        self.namespace_id = hashlib.sha256(b"namespace:" + session_token).digest()

    def encrypt(self, data: bytes) -> tuple[bytes, bytes]:
        """Encrypt data. Returns (nonce, ciphertext)."""
        nonce = secrets.token_bytes(12)
        ciphertext = self.cipher.encrypt(nonce, data, None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt data. Raises on authentication failure."""
        return self.cipher.decrypt(nonce, ciphertext, None)

    def compute_path_hash(self, path: str) -> bytes:
        """Compute a namespace-scoped hash for a path."""
        combined = f"{path}:{self.key.hex()}"
        return hashlib.sha256(combined.encode()).digest()

    @staticmethod
    def derive_session_token(username: str, password: str) -> bytes:
        """Derive session token via PBKDF2 (expensive — done once at login)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=STATIC_SALT,
            iterations=100_000,
        )
        return kdf.derive(f"{username}:{password}".encode())

    @staticmethod
    def derive_write_key(username: str, write_password: str) -> bytes:
        """Derive a write-access key from username + write password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=STATIC_SALT,
            iterations=100_000,
        )
        return kdf.derive(f"write:{username}:{write_password}".encode())

    @staticmethod
    def compute_write_proof(write_key: bytes, lock_secret: bytes) -> bytes:
        """Compute HMAC-SHA256 proof that write_key authorises this lock_secret."""
        return hmac.digest(write_key, lock_secret, "sha256")


# ---------------------------------------------------------------------------
# BlobStorage
# ---------------------------------------------------------------------------

class BlobStorage:
    """Manages encrypted blob storage in SQLite."""

    def __init__(self, db_path: str = "blobs.sqlite3"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blobs (
                    id            INTEGER PRIMARY KEY,
                    path_hash     TEXT    NOT NULL UNIQUE,
                    mime_nonce    BLOB    NOT NULL,
                    mime_enc      BLOB    NOT NULL,
                    content_nonce BLOB    NOT NULL,
                    content_enc   BLOB    NOT NULL
                )
            """)
            conn.commit()

    def get_blob(self, path_hash_b64: str) -> tuple | None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT mime_nonce, mime_enc, content_nonce, content_enc "
                "FROM blobs WHERE path_hash = ?",
                (path_hash_b64,)
            )
            return cursor.fetchone()

    def store_blob(self, path_hash_b64: str, mime_nonce: bytes, mime_enc: bytes,
                   content_nonce: bytes, content_enc: bytes):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO blobs
                    (path_hash, mime_nonce, mime_enc, content_nonce, content_enc)
                VALUES (?, ?, ?, ?, ?)
            """, (path_hash_b64, mime_nonce, mime_enc, content_nonce, content_enc))
            conn.commit()

    def delete_blob(self, path_hash_b64: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM blobs WHERE path_hash = ?", (path_hash_b64,)
            )
            conn.commit()
            return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session:
    """Manages an authenticated user session."""

    def __init__(self, token: bytes):
        self.token = token
        self.crypto = CryptoManager(token)
        self.storage = BlobStorage("blobs.sqlite3")

    @staticmethod
    def from_request() -> 'Session | None':
        """Extract session from the session cookie."""
        cookie = request.cookies.get(COOKIE_NAME)
        if not cookie:
            return None
        try:
            token = b64decode(cookie)
            if len(token) != 32:
                return None
            return Session(token)
        except Exception:
            return None

    def set_cookie(self, response: Response):
        response.set_cookie(
            COOKIE_NAME,
            b64encode(self.token).decode(),
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=False,   # ⚠ Set True in production (HTTPS only) — cookie IS the key
            samesite='Lax'
        )

    # ------------------------------------------------------------------
    # Core blob operations
    # ------------------------------------------------------------------

    def _path_hash_b64(self, path: str) -> str:
        return b64encode(self.crypto.compute_path_hash(path)).decode()

    def get_blob(self, path: str) -> tuple[str, bytes] | tuple[None, None]:
        """Get and decrypt a blob. Returns (mime_type, content) or (None, None)."""
        phb64 = self._path_hash_b64(path)

        # Check cache first
        cached = _cache_get(phb64, self.storage.db_path)
        if cached is not None:
            return cached

        row = self.storage.get_blob(phb64)
        if not row:
            return None, None

        mime_nonce, mime_enc, content_nonce, content_enc = row
        try:
            mime_type = self.crypto.decrypt(mime_nonce, mime_enc).decode()
            content   = self.crypto.decrypt(content_nonce, content_enc)
            _cache_set(phb64, self.storage.db_path, mime_type, content)
            return mime_type, content
        except Exception as e:
            print(f"Decryption error for path hash {phb64[:8]}…: {e}")
            return None, None

    def store_blob(self, path: str, content: bytes, mime_type: str):
        """Encrypt and store a blob."""
        phb64 = self._path_hash_b64(path)
        mime_nonce, mime_enc       = self.crypto.encrypt(mime_type.encode())
        content_nonce, content_enc = self.crypto.encrypt(content)
        self.storage.store_blob(phb64, mime_nonce, mime_enc, content_nonce, content_enc)
        _cache_invalidate(phb64, self.storage.db_path)

    def delete_blob(self, path: str) -> bool:
        """Delete a blob. Returns True if it existed."""
        phb64 = self._path_hash_b64(path)
        deleted = self.storage.delete_blob(phb64)
        if deleted:
            _cache_invalidate(phb64, self.storage.db_path)
        return deleted

    # ------------------------------------------------------------------
    # Lock / write-protection
    # ------------------------------------------------------------------

    def is_locked(self) -> bool:
        mime, _ = self.get_blob(LOCK_PATH)
        return mime is not None

    def create_lock(self, username: str, write_password: str) -> bool:
        """Create a write lock. Returns False if already locked."""
        if self.is_locked():
            return False
        write_key   = CryptoManager.derive_write_key(username, write_password)
        lock_secret = secrets.token_bytes(32)
        write_proof = CryptoManager.compute_write_proof(write_key, lock_secret)
        payload = {
            "lock_secret": lock_secret.hex(),
            "write_proof": write_proof.hex(),
        }
        self.store_blob(LOCK_PATH, json.dumps(payload).encode(), "application/json")
        return True

    def verify_write_password(self, username: str, write_password: str) -> bool:
        """Return True if write_password is correct for this lock."""
        mime, content = self.get_blob(LOCK_PATH)
        if not mime:
            return False
        try:
            payload     = json.loads(content.decode())
            lock_secret = bytes.fromhex(payload["lock_secret"])
            stored_proof = bytes.fromhex(payload["write_proof"])
            write_key   = CryptoManager.derive_write_key(username, write_password)
            computed    = CryptoManager.compute_write_proof(write_key, lock_secret)
            return hmac.compare_digest(stored_proof, computed)
        except Exception:
            return False

    def remove_lock(self):
        """Remove the write lock entirely."""
        self.delete_blob(LOCK_PATH)

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def get_index(self) -> dict:
        """Return the index dict, or a fresh empty one."""
        mime, content = self.get_blob(INDEX_PATH)
        if mime:
            try:
                return json.loads(content.decode())
            except Exception:
                pass
        return {"version": 2, "files": {}}

    def save_index(self, index: dict):
        self.store_blob(INDEX_PATH, json.dumps(index).encode(), "application/json")

    def update_index(self, add_path: str = None, remove_path: str = None,
                     size: int = None):
        index = self.get_index()
        files = index.setdefault("files", {})

        if add_path:
            files[add_path] = {
                "uploaded": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                "size": _format_size(size) if size is not None else "?",
            }
        if remove_path:
            files.pop(remove_path, None)

        index["files"] = files
        self.save_index(index)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _get_write_token_from_request() -> str | None:
    return request.cookies.get(WRITE_COOKIE_NAME)


def _session_has_write(session_obj: Session) -> bool:
    """Return True if the current request has write access."""
    if not session_obj.is_locked():
        return True
    token = _get_write_token_from_request()
    if not token:
        return False
    return _check_write_session(token, session_obj.crypto.namespace_id)


def send_partial_content(content: bytes, mime_type: str) -> Response:
    """Serve content with HTTP Range support."""
    total = len(content)
    range_header = request.headers.get('Range')

    if range_header:
        try:
            byte_range = range_header.replace('bytes=', '').strip()
            raw_start, raw_end = byte_range.split('-')
            start = int(raw_start) if raw_start else 0
            end   = int(raw_end)   if raw_end   else total - 1

            if start >= total or start < 0 or end < start:
                resp = make_response("Invalid range", 416)
                resp.headers['Content-Range'] = f'bytes */{total}'
                return resp

            end   = min(end, total - 1)
            chunk = content[start:end + 1]
            resp  = make_response(chunk)
            resp.status_code = 206
            resp.headers['Content-Range'] = f'bytes {start}-{end}/{total}'
            resp.headers['Content-Length'] = len(chunk)
        except (ValueError, IndexError):
            resp = make_response("Invalid range format", 416)
            resp.headers['Content-Range'] = f'bytes */{total}'
            return resp
    else:
        resp = make_response(content)
        resp.headers['Content-Length'] = total

    resp.headers['Content-Type']   = mime_type
    resp.headers['Accept-Ranges']  = 'bytes'
    resp.headers['Cache-Control']  = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma']         = 'no-cache'
    resp.headers['Expires']        = '0'
    resp.headers['Access-Control-Allow-Origin']  = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp


# ---------------------------------------------------------------------------
# Routes — auth
# ---------------------------------------------------------------------------

@app.route('/_/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next', '/_/index')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username and password:
            token      = CryptoManager.derive_session_token(username, password)
            session_obj = Session(token)
            response   = redirect(next_url)
            session_obj.set_cookie(response)
            # Store username in a plain, non-secret cookie for display purposes only
            response.set_cookie('blob_username', username,
                                max_age=COOKIE_MAX_AGE, httponly=False, samesite='Lax')
            return response

    return render_template_string(HtmlAssets.LOGIN_FORM, next_url=next_url)


@app.route('/_/logout')
def logout():
    write_token = _get_write_token_from_request()
    if write_token:
        _revoke_write_session(write_token)
    _cache_clear()
    resp = make_response(render_template_string(HtmlAssets.LOGOUT_PAGE))
    resp.set_cookie(COOKIE_NAME, '', expires=0)
    resp.set_cookie(WRITE_COOKIE_NAME, '', expires=0)
    resp.set_cookie('blob_username', '', expires=0)
    return resp


# ---------------------------------------------------------------------------
# Routes — access control (replaces separate lock/unlock routes)
# ---------------------------------------------------------------------------

@app.route('/_/readonly', methods=['GET', 'POST'])
def readonly():
    session_obj = Session.from_request()
    if not session_obj:
        return redirect('/_/login?next=/_/readonly')

    locked       = session_obj.is_locked()
    write_enabled = _session_has_write(session_obj) and locked
    message      = None
    error        = False
    response     = None

    if request.method == 'POST':
        action         = request.form.get('action', '')
        write_password = request.form.get('write_password', '')
        username       = request.cookies.get('blob_username', '')

        if action == 'lock':
            wp2 = request.form.get('write_password2', '')
            if write_password != wp2:
                message = "Passwords do not match."
                error   = True
            elif not write_password:
                message = "Write password cannot be empty."
                error   = True
            else:
                session_obj.create_lock(username, write_password)
                locked  = True
                message = "Namespace locked."

        elif action == 'unlock':
            if session_obj.verify_write_password(username, write_password):
                token = _create_write_session(session_obj.crypto.namespace_id)
                resp  = make_response(redirect('/_/readonly'))
                resp.set_cookie(WRITE_COOKIE_NAME, token,
                                max_age=COOKIE_MAX_AGE, httponly=True, samesite='Lax')
                return resp
            else:
                message = "Incorrect write password."
                error   = True

        elif action == 'relock':
            write_token = _get_write_token_from_request()
            if write_token:
                _revoke_write_session(write_token)
            write_enabled = False
            message = "Write access revoked for this session."
            response = make_response(
                render_template_string(HtmlAssets.READONLY_PAGE,
                                       locked=locked, write_enabled=write_enabled,
                                       message=message, error=error)
            )
            response.set_cookie(WRITE_COOKIE_NAME, '', expires=0)
            return response

        elif action == 'remove_lock':
            if session_obj.verify_write_password(username, write_password):
                session_obj.remove_lock()
                write_token = _get_write_token_from_request()
                if write_token:
                    _revoke_write_session(write_token)
                locked        = False
                write_enabled = False
                message = "Lock removed. Namespace is now fully writable."
                response = make_response(
                    render_template_string(HtmlAssets.READONLY_PAGE,
                                           locked=locked, write_enabled=write_enabled,
                                           message=message, error=error)
                )
                response.set_cookie(WRITE_COOKIE_NAME, '', expires=0)
                return response
            else:
                message = "Incorrect write password."
                error   = True

    return render_template_string(
        HtmlAssets.READONLY_PAGE,
        locked=locked,
        write_enabled=write_enabled,
        message=message,
        error=error
    )


# ---------------------------------------------------------------------------
# Routes — index / file manager
# ---------------------------------------------------------------------------

@app.route('/_/index', methods=['GET'])
def view_index():
    session_obj = Session.from_request()
    if not session_obj:
        return redirect('/_/login?next=/_/index')

    index = session_obj.get_index()
    files = [
        {"path": path, **meta}
        for path, meta in sorted(index.get("files", {}).items())
    ]

    return render_template_string(
        HtmlAssets.INDEX_PAGE,
        files=files,
        locked=session_obj.is_locked(),
        write_enabled=_session_has_write(session_obj),
    )


# ---------------------------------------------------------------------------
# Routes — blob get / put
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET'])
def get_root():
    return get_blob('index.html')

@app.route('/', methods=['PUT', 'POST'])
def put_root():
    return put_blob('index.html')

@app.route('/<path:blob_path>', methods=['GET'])
def get_blob(blob_path):
    session_obj = Session.from_request()
    if not session_obj:
        return redirect(f'/_/login?next=/{blob_path}')

    mime_type, content = session_obj.get_blob(blob_path)
    if not mime_type:
        return render_template_string(HtmlAssets.NOT_FOUND_PAGE, path=blob_path), 404

    return send_partial_content(content, mime_type)


@app.route('/<path:blob_path>', methods=['PUT', 'POST'])
def put_blob(blob_path):
    session_obj = Session.from_request()
    if not session_obj:
        return redirect(f'/_/login?next=/{blob_path}')

    # Protect internal reserved paths
    if blob_path in RESERVED_PATHS:
        return "Path is reserved", 403

    # Enforce write lock
    if not _session_has_write(session_obj):
        return "Namespace is locked (read-only). Visit /_/readonly to unlock.", 403

    content   = request.get_data()
    mime_type = request.content_type or 'application/octet-stream'

    # Empty body = delete
    if len(content) == 0:
        deleted = session_obj.delete_blob(blob_path)
        if deleted:
            session_obj.update_index(remove_path=blob_path)
            return '', 204
        else:
            return "Blob not found", 404

    session_obj.store_blob(blob_path, content, mime_type)
    session_obj.update_index(add_path=blob_path, size=len(content))
    return make_response(f"Stored /{blob_path}", 201)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    session_obj = Session.from_request()
    if not session_obj:
        return redirect(f'/_/login?next={request.path}')

    path = request.path.lstrip('/')
    if not path or path.startswith('_/'):
        return "Not found", 404

    return render_template_string(HtmlAssets.NOT_FOUND_PAGE, path=path), 404


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("🔐 Encrypted Blob Storage Server")
    print("=" * 60)
    print(f"\n  Home:   http://localhost:5000/_/index")
    print(f"  Login:  http://localhost:5000/_/login")
    print(f"  Access: http://localhost:5000/_/readonly")
    print("\n  Each username+password = isolated encrypted namespace")
    print("\n  curl quickstart:")
    print("    curl -c c.txt -d 'username=alice&password=secret' http://localhost:5000/_/login")
    print("    curl -b c.txt -X PUT --data-binary @file.mp4 \\")
    print("         -H 'Content-Type: video/mp4' http://localhost:5000/videos/movie.mp4")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    main()