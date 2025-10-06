import sqlite3
import base64, hmac, hashlib, os
from datetime import datetime
from functools import lru_cache

from flask import Flask, request, make_response, g
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
DB_FILE = "blobs.sqlite"

# --- DB Setup ---
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.execute("""
            CREATE TABLE IF NOT EXISTS blobs (
                id INTEGER PRIMARY KEY,
                path_hash BLOB NOT NULL,
                mime_nonce BLOB NOT NULL,
                mime_enc   BLOB NOT NULL,
                content_nonce BLOB NOT NULL,
                content_enc   BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    if "db" in g:
        g.db.close()

# --- Crypto helpers ---
def derive_key(password: str) -> bytes:
    # simple PBKDF2 for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"static_salt",  # fixed salt for consistency
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_blob(key: bytes, plaintext: bytes) -> (bytes, bytes):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_blob(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def path_hash(key: bytes, path: str) -> bytes:
    return hmac.new(key, path.encode(), hashlib.sha256).digest()

# --- Cache decrypted blobs ---
@lru_cache(maxsize=128)
def get_decrypted_blob(key: bytes, phash: bytes, row):
    mime = decrypt_blob(key, row[0], row[1]).decode()
    content = decrypt_blob(key, row[2], row[3])
    return mime, content

# --- Routes ---
@app.route("/", defaults={"path": ""}, methods=["GET", "PUT", "POST"])
@app.route("/<path:path>", methods=["GET", "PUT", "POST"])
def blob_handler(path):
    password = request.cookies.get("password")
    if not password:
        return login_form()
    key = derive_key(password)

    if request.method == "GET":
        phash = path_hash(key, "/" + path)
        row = get_db().execute(
            "SELECT mime_nonce, mime_enc, content_nonce, content_enc FROM blobs WHERE path_hash=?",
            (phash,)
        ).fetchone()
        if not row:
            return "Not found", 404

        mime, content = get_decrypted_blob(key, phash, row)

        # Handle Range requests for video playback
        range_header = request.headers.get("Range")
        if range_header:
            try:
                units, rng = range_header.split("=")
                if units.strip() != "bytes":
                    raise ValueError
                start_str, end_str = rng.split("-")
                start = int(start_str) if start_str else 0
                end = int(end_str) if end_str else len(content) - 1
                if end >= len(content):
                    end = len(content) - 1
                sliced = content[start:end+1]
                resp = make_response(sliced, 206)
                resp.headers["Content-Type"] = mime
                resp.headers["Content-Range"] = f"bytes {start}-{end}/{len(content)}"
                resp.headers["Content-Length"] = str(len(sliced))
                return resp
            except Exception:
                return "Invalid Range", 416

        # Full content
        resp = make_response(content)
        resp.headers["Content-Type"] = mime
        return resp

    elif request.method in ("PUT", "POST"):
        mime = request.headers.get("Content-Type", "application/octet-stream")
        content = request.get_data()

        phash = path_hash(key, "/" + path)
        mime_nonce, mime_enc = encrypt_blob(key, mime.encode())
        content_nonce, content_enc = encrypt_blob(key, content)

        db = get_db()
        db.execute("DELETE FROM blobs WHERE path_hash=?", (phash,))
        db.execute(
            "INSERT INTO blobs (path_hash, mime_nonce, mime_enc, content_nonce, content_enc, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (phash, mime_nonce, mime_enc, content_nonce, content_enc, datetime.utcnow().isoformat())
        )
        db.commit()
        return "Stored", 201

def login_form():
    return """
    <html><body>
    <form method="POST">
      <input type="password" name="password" placeholder="Password"/>
      <input type="submit" value="Login"/>
    </form>
    </body></html>
    """, 401

@app.route("/", defaults={"path": ""}, methods=["POST"])
@app.route("/<path:path>", methods=["POST"])
def set_cookie(path=""):
    password = request.form.get("password")
    if password:
        resp = make_response("Logged in, try again")
        resp.set_cookie("password", password, httponly=True)
        return resp
    return "Missing password", 400

if __name__ == "__main__":
    app.run(port=5000, debug=True)
