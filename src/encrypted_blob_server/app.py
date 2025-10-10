#!/usr/bin/env python3
"""
Minimal encrypted-blob Flask app (generic).

Behavior summary:
- Authentication:
  - If a cookie named 'password' exists, use it.
  - Else if Authorization: Basic ... header exists, derive password from it, set cookie, and continue.
  - Else respond 401 + WWW-Authenticate so browsers prompt.
- Password => per-namespace key derived via PBKDF2 (static salt for determinism).
- Path lookup: path_hash = HMAC-SHA256(key, path). This isolates identical paths across different passwords.
- All blobs stored encrypted (mime, content) with AES-GCM and random nonces.
- Supports PUT/POST to write blobs and GET (+ Range) to read them.
- LRU cache (hex-keyed) for decrypted blobs to avoid repeated decryption.
"""
from __future__ import annotations

import os
import sqlite3
import hmac as _hmac
import hashlib
import secrets
from base64 import b64decode
from datetime import datetime
from functools import lru_cache
from typing import Optional, Tuple

from flask import Flask, request, make_response, g
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration ---
DB_FILE = os.environ.get("ENCBLOB_DB", "blobs.sqlite")
STATIC_SALT = os.environ.get("ENCBLOB_STATIC_SALT", "encblob-static-salt").encode()
LRU_CACHE_MAX = int(os.environ.get("LRU_CACHE_MAX", "128"))

app = Flask(__name__)


# ---------- DB helpers ----------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blobs (
                id INTEGER PRIMARY KEY,
                path_hash BLOB NOT NULL,
                mime_nonce BLOB NOT NULL,
                mime_enc   BLOB NOT NULL,
                content_nonce BLOB NOT NULL,
                content_enc   BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_blobs_path_hash ON blobs(path_hash)")
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# ---------- Crypto helpers ----------
def derive_key(password: str) -> bytes:
    """Derive a 32-byte key for the given password (deterministic across restarts)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=STATIC_SALT,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_blob(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce, ct


def decrypt_blob(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


def path_hash(key: bytes, path: str) -> bytes:
    return _hmac.new(key, path.encode("utf-8"), hashlib.sha256).digest()


# ---------- Cached decryption ----------
@lru_cache(maxsize=LRU_CACHE_MAX)
def decrypt_cached(
    key_hex: str,
    mime_nonce_hex: str,
    mime_enc_hex: str,
    content_nonce_hex: str,
    content_enc_hex: str,
) -> Tuple[str, bytes]:
    key = bytes.fromhex(key_hex)
    mime_nonce = bytes.fromhex(mime_nonce_hex)
    mime_enc = bytes.fromhex(mime_enc_hex)
    content_nonce = bytes.fromhex(content_nonce_hex)
    content_enc = bytes.fromhex(content_enc_hex)

    mime = decrypt_blob(key, mime_nonce, mime_enc).decode("utf-8", errors="replace")
    content = decrypt_blob(key, content_nonce, content_enc)
    return mime, content


# ---------- Auth helpers ----------
def password_from_authorization_header() -> Optional[str]:
    print("trying auth")
    print(request.url)
    print(request.headers)
    auth = request.authorization
    
    if not auth:
        return None
    print(f"request authorization was {auth} with {auth.password} and {auth.username}")
    # auth.password may be None if client sent only a username or malformed header
    return auth.password


def get_effective_password() -> Tuple[Optional[str], bool]:
    """
    Returns (password, set_cookie_flag)
    - password: from cookie or Authorization header
    - set_cookie_flag: True if password came from Authorization header and we should set the cookie in the response
    """
    pw = password_from_authorization_header()
    if pw:
        return pw, True
    pw = request.cookies.get("password")
    if pw:
        return pw, False
    return None, False


from flask import render_template_string

@app.errorhandler(404)
def not_found(e):
    """Show an upload form when a blob is missing."""
    path = request.path.lstrip("/")
    upload_form = f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Upload new blob — {path}</title>
      <style>
        body {{ font-family: sans-serif; margin: 2em; }}
        form {{ border: 1px solid #ccc; padding: 1em; border-radius: 8px; max-width: 500px; }}
        input[type=file], input[type=text] {{ width: 100%; margin-bottom: 1em; }}
        button {{ padding: 0.6em 1em; border: none; border-radius: 4px; background: #2d7cf5; color: white; }}
      </style>
    </head>
    <body>
      <h1>404 — No blob at “/{path}”</h1>
      <p>You can upload a new blob here to create it.</p>
      <form action="/{path}" method="POST" enctype="multipart/form-data">
        <label>File:</label>
        <input type="file" name="file" required><br>
        <label>MIME type (optional):</label>
        <input type="text" name="mime_type" placeholder="e.g. image/png or text/html">
        <button type="submit">Upload</button>
      </form>
      <p><a href="/">Back to root</a></p>
    </body>
    </html>
    """
    return render_template_string(upload_form), 404


# ---------- Routes ----------
@app.route("/", defaults={"path": ""}, methods=["GET", "PUT", "POST"])
@app.route("/<path:path>", methods=["GET", "PUT", "POST"])
def blob_handler(path: str):
    """
    Generic blob handler:
      - GET: return blob (supports Range)
      - PUT/POST: store blob (overwrites existing for same password+path)
    Authentication:
      - cookie 'password' preferred
      - else Authorization: Basic is accepted and used to set cookie
      - else 401 + WWW-Authenticate
    """
    pw, set_cookie_flag = get_effective_password()
    if not pw:
        resp = make_response("Authentication required", 401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="Encrypted Blob Server"'
        return resp

    key = derive_key(pw)

    # GET
    if request.method == "GET":
        ph = path_hash(key, "/" + path)
        row = get_db().execute(
            "SELECT mime_nonce, mime_enc, content_nonce, content_enc FROM blobs WHERE path_hash=?",
            (ph,),
        ).fetchone()
        if not row:
            resp = make_response("Not found", 404)
            if set_cookie_flag:
                resp.set_cookie("password", pw, httponly=True, samesite="Lax")
            return resp

        key_hex = key.hex()
        mime_nonce_hex = row["mime_nonce"].hex()
        mime_enc_hex = row["mime_enc"].hex()
        content_nonce_hex = row["content_nonce"].hex()
        content_enc_hex = row["content_enc"].hex()

        mime, content = decrypt_cached(
            key_hex, mime_nonce_hex, mime_enc_hex, content_nonce_hex, content_enc_hex
        )

        # Range support
        range_header = request.headers.get("Range")
        if range_header:
            try:
                unit, rng = range_header.split("=")
                if unit.strip() != "bytes":
                    raise ValueError("Unsupported Range unit")
                start_str, end_str = rng.split("-")
                start = int(start_str) if start_str.strip() != "" else 0
                end = int(end_str) if end_str.strip() != "" else len(content) - 1
                if start < 0 or end < start:
                    raise ValueError("Invalid range values")
                if start >= len(content):
                    return ("Requested Range Not Satisfiable", 416)
                if end >= len(content):
                    end = len(content) - 1
                sliced = content[start : end + 1]
                resp = make_response(sliced, 206)
                resp.headers["Content-Type"] = mime or "application/octet-stream"
                resp.headers["Content-Range"] = f"bytes {start}-{end}/{len(content)}"
                resp.headers["Content-Length"] = str(len(sliced))
                resp.headers["Accept-Ranges"] = "bytes"
                if set_cookie_flag:
                    resp.set_cookie("password", pw, httponly=True, samesite="Lax")
                return resp
            except Exception:
                return ("Invalid Range", 416)

        # Full content
        resp = make_response(content)
        resp.headers["Content-Type"] = mime or "application/octet-stream"
        resp.headers["Accept-Ranges"] = "bytes"
        if set_cookie_flag:
            resp.set_cookie("password", pw, httponly=True, samesite="Lax")
        return resp

    # PUT/POST: upload
    if request.method in ("PUT", "POST"):
        mime = request.headers.get("Content-Type", "application/octet-stream")
        content = request.get_data(cache=False)
        ph = path_hash(key, "/" + path)
        m_nonce, m_enc = encrypt_blob(key, mime.encode("utf-8"))
        c_nonce, c_enc = encrypt_blob(key, content)
        db = get_db()
        db.execute("DELETE FROM blobs WHERE path_hash=?", (ph,))
        db.execute(
            "INSERT INTO blobs (path_hash, mime_nonce, mime_enc, content_nonce, content_enc, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (ph, m_nonce, m_enc, c_nonce, c_enc, datetime.utcnow().isoformat()),
        )
        db.commit()
        # clear cache (coarse but safe)
        decrypt_cached.cache_clear()
        resp = make_response("Stored", 201)
        if set_cookie_flag:
            resp.set_cookie("password", pw, httponly=True, samesite="Lax")
        return resp

from flask import redirect
@app.route("/_logout", methods=["GET", "POST"])
def logout_route():
    """
    Clear password cookie and ask for Basic Auth again by returning 401 + unique realm.
    Browsers usually prompt a credential dialog when the realm changes.
    """
    # Clear cookie
    resp = make_response(redirect("/_login"))
    #resp = make_response("Logged out; please re-authenticate", 401)
    resp.delete_cookie("password")  # remove cookie so future requests won't use it

    # create a unique realm to encourage browsers to reprompt for credentials
    nonce = secrets.token_urlsafe(8)
    resp.headers["WWW-Authenticate"] = f'Basic realm="Encrypted Blob Server - {nonce}"'
    return resp

from flask import abort
@app.route("/_login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return (
            "<h1>Login</h1>"
            "<form method='POST'>"
            "<input type='password' name='password' placeholder='Password' autofocus required/>"
            "<button type='submit'>Login</button>"
            "</form>"
        )
    password = request.form.get("password") or (request.json or {}).get("password")
    if not password:
        abort(400, "Missing password")
    resp = make_response(redirect("/"))
    resp.set_cookie("password", password, httponly=True, samesite="Lax")
    return resp

# ---------- CLI entry ----------
def main():
    print("Encrypted blob server starting.")
    print(f"DB: {DB_FILE}")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)


if __name__ == "__main__":
    main()
