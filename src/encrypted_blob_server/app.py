#!/usr/bin/env python3
"""
refactored by claude
https://claude.ai/public/artifacts/6256c1b6-ee37-484c-976d-07900ad84816
"""

import sqlite3
import hashlib
import secrets
import functools
from pathlib import Path
from base64 import b64encode, b64decode
from datetime import datetime
from flask import Flask, request, make_response, Response, redirect, render_template_string
from flask import session
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hmac
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

COOKIE_NAME = "blob_session"
COOKIE_MAX_AGE = 3600 * 24  # 24 hours
STATIC_SALT = b"encrypted-blob-storage-v1-salt-change-in-production"
LOCK_PATH = "/.meta/locked"
INDEX_PATH = "/.meta/index"

class HtmlAssets:
    """HTML templates and shared styling."""
    
    COMMON_STYLE = """
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            max-width: 450px; 
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
        h1 { 
            margin-top: 0;
            color: #333;
            font-size: 24px;
        }
        p {
            color: #666;
            line-height: 1.5;
        }
        input[type="text"],
        input[type="password"],
        input[type="file"] { 
            width: 100%; 
            padding: 12px; 
            margin: 10px 0; 
            box-sizing: border-box;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #007bff;
        }
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
            margin-top: 10px;
        }
        button:hover { 
            background: #0056b3; 
        }
        button:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
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
        a { 
            color: #007bff; 
            text-decoration: none;
            font-weight: 500;
        }
        a:hover {
            text-decoration: underline;
        }
    """
    
    LOGIN_FORM = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Encrypted Blob Storage</title>
        <style>""" + COMMON_STYLE + """</style>
    </head>
    <body>
        <div class="box">
            <h1>🔐 Login</h1>
            <p>Each username + password combination creates a unique encrypted storage namespace.</p>
            <form method="POST" action="/_/login?next={{ next_url }}">
                <input type="text" name="username" placeholder="Username" required autofocus>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <div class="note">
                Different username/password combinations access completely separate storage spaces.
                Your credentials are never stored - only a derived session token.
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
    
    NOT_FOUND_WITH_UPLOAD = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Not Found - {{ path }}</title>
        <style>""" + COMMON_STYLE + """
            body { max-width: 700px; }
            h1 { color: #dc3545; }
            form { 
                margin-top: 30px; 
                padding: 30px; 
                background: #f8f9fa; 
                border-radius: 8px;
                border: 2px dashed #dee2e6;
            }
            .logout {
                float: right;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="logout">
            <a href="/_/logout">Logout</a>
        </div>
        <h1>404 - Blob Not Found</h1>
        <p>No blob exists at <code>/{{ path }}</code> in your namespace.</p>
        
        <form id="uploadForm" enctype="multipart/form-data">
            <h2>📤 Upload a new blob here</h2>
            <input type="file" name="file" id="fileInput" required>
            <br>
            <!--
            <button type="submit" id="uploadBtn">Upload to /{{ path }}</button>
            -->
            <input type="text" id="pathInput" value="{{ path }}" required>
            <button type="submit" id="uploadBtn">Upload</button>
            <button type="button" id="deleteBtn">Delete</button>
            <div class="note">The file will be encrypted and stored at this path in your namespace.</div>
        </form>

        Or upload the blob using curl, with
        <pre>
            curl -c cookies.txt -d 'username=alice&password=secret' http://localhost:5000/_/login
            curl -b cookies.txt -X PUT --data-binary @video.mp4 -H 'Content-Type: video/mp4' http://localhost:5000/videos/my-video.mp4
        </pre>
        from the command line.

        <script>
            document.getElementById('uploadForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const fileInput = document.getElementById('fileInput');
                const uploadBtn = document.getElementById('uploadBtn');
                const file = fileInput.files[0];
                
                if (!file) return;
                
                uploadBtn.disabled = true;
                uploadBtn.textContent = 'Uploading...';
                
                try {

                    /*
                    const response = await fetch('/{{ path }}', {
                        method: 'PUT',
                        body: file,
                        headers: {
                            'Content-Type': file.type || 'application/octet-stream'
                        }
                    });
                    */
                    const path = document.getElementById('pathInput').value.trim();
                    const response = await fetch('/' + path, {
                        method: 'PUT',
                        body: file,
                        headers: {
                            'Content-Type': file.type || 'application/octet-stream'
                        }
                    });
                    if (response.ok) {
                        window.location.reload();
                    } else {
                        alert('Upload failed: ' + response.statusText);
                        uploadBtn.disabled = false;
                        uploadBtn.textContent = 'Upload to /{{ path }}';
                    }
                } catch (error) {
                    alert('Upload error: ' + error.message);
                    uploadBtn.disabled = false;
                    uploadBtn.textContent = 'Upload to /{{ path }}';
                }
            });

            document.getElementById('deleteBtn').addEventListener('click', async () => {
                const path = document.getElementById('pathInput').value.trim();
                if (!confirm("Delete /" + path + "?")) return;

                const response = await fetch('/' + path, {
                    method: 'PUT',
                    body: ''
                });

                if (response.status === 204) {
                    alert("Deleted.");
                    window.location.href = '/';
                } else {
                    alert("Not found.");
                }
            });
        </script>
    </body>
    </html>
    """


class CryptoManager:
    """Handles all encryption/decryption operations."""
    
    def __init__(self, session_token: bytes):
        """Initialize with a session token."""
        # Derive encryption key from session token (fast SHA-256)
        self.key = hashlib.sha256(b"encryption:" + session_token).digest()
        self.cipher = ChaCha20Poly1305(self.key)
    
    def encrypt(self, data: bytes) -> tuple[bytes, bytes]:
        """Encrypt data. Returns (nonce, ciphertext)."""
        nonce = secrets.token_bytes(12)
        ciphertext = self.cipher.encrypt(nonce, data, None)
        return nonce, ciphertext
    
    def decrypt(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt data."""
        return self.cipher.decrypt(nonce, ciphertext, None)
    
    def compute_path_hash(self, path: str) -> bytes:
        """Compute unique hash for path in this namespace."""
        combined = f"{path}:{self.key.hex()}"
        return hashlib.sha256(combined.encode()).digest()
    
    @staticmethod
    def derive_session_token(username: str, password: str) -> bytes:
        """Derive session token using PBKDF2 (expensive, done once at login)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=STATIC_SALT,
            iterations=100_000,
        )
        combined = f"{username}:{password}"
        return kdf.derive(combined.encode())


class BlobStorage:
    """Manages encrypted blob storage in SQLite with per-user database support."""
    
    def __init__(self, db_path: str = "blobs.sqlite3"):
        """Initialize blob storage."""
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the SQLite database with the blobs table."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blobs (
                    id INTEGER PRIMARY KEY,
                    path_hash TEXT NOT NULL,
                    mime_nonce BLOB NOT NULL,
                    mime_enc BLOB NOT NULL,
                    content_nonce BLOB NOT NULL,
                    content_enc BLOB NOT NULL,
                    UNIQUE(path_hash)
                )
            """)
            conn.commit()
    
    def get_blob(self, path_hash: str) -> tuple | None:
        """Retrieve encrypted blob data from database."""
        print("GB:",path_hash)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT mime_nonce, mime_enc, content_nonce, content_enc FROM blobs WHERE path_hash = ?",
                (path_hash,)
            )
            return cursor.fetchone()
    
    def store_blob(self, path_hash: str, mime_nonce: bytes, mime_enc: bytes,
                   content_nonce: bytes, content_enc: bytes):
        """Store encrypted blob in database (replaces if exists)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO blobs 
                (path_hash, mime_nonce, mime_enc, content_nonce, content_enc)
                VALUES (?, ?, ?, ?, ?)
            """, (
                path_hash,
                mime_nonce,
                mime_enc,
                content_nonce,
                content_enc
            ))
            conn.commit()
    
    def delete_blob(self, path_hash_b64: str) -> bool:
        """Delete a blob from database. path_hash_b64 is a base64-encoded string."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM blobs WHERE path_hash = ?", (path_hash_b64,))
            conn.commit()
            return cursor.rowcount > 0

class Session:
    """Manages user session with encryption and blob storage."""
    
    def __init__(self, token: bytes):
        """Create session from token."""
        self.token = token
        self.crypto = CryptoManager(token)
        self.storage = BlobStorage("blobs.sqlite3")
    
    @staticmethod
    def from_request() -> 'Session | None':
        """Extract session from Flask request cookie."""
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
        """Set session cookie on Flask response."""
        response.set_cookie(
            COOKIE_NAME,
            b64encode(self.token).decode(),
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite='Lax'
        )
    
    def get_blob(self, path: str) -> tuple[str, bytes] | tuple[None, None]:
        """
        Get and decrypt a blob.
        
        Returns:
            (mime_type, content) if found, (None, None) if not found
        """
        path_hash = self.crypto.compute_path_hash(path)
        path_hash_b64 = b64encode(path_hash).decode()
        cached_row = self.storage.get_blob(path_hash_b64)
        if not cached_row:
            return None, None
        
        mime_nonce, mime_enc, content_nonce, content_enc = cached_row

        try:
            mime_type = self.crypto.decrypt(mime_nonce, mime_enc).decode()
            content = self.crypto.decrypt(content_nonce, content_enc)
            return mime_type, content
        except Exception as e:
            print(f"exception {e}")
            return None, None
    
    def store_blob(self, path: str, content: bytes, mime_type: str):
        """
        Encrypt and store a blob.
        
        Args:
            path: Blob path (e.g., "videos/movie.mp4")
            content: Raw file content
            mime_type: MIME type (e.g., "video/mp4")
        """
        path_hash = self.crypto.compute_path_hash(path)
        path_hash_b64 = b64encode(path_hash).decode()

        # Encrypt MIME type and content
        mime_nonce, mime_enc = self.crypto.encrypt(mime_type.encode())
        content_nonce, content_enc = self.crypto.encrypt(content)
        
        # Store in database
        self.storage.store_blob(path_hash_b64, mime_nonce, mime_enc, content_nonce, content_enc)

    # Ability to lock a namespace
    def is_locked(self) -> bool:
        mime, content = self.get_blob(LOCK_PATH)
        return mime is not None

    @staticmethod
    def _derive_write_key(username: str, write_password: str) -> bytes:
        """Derive a write-access key from username and write password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=STATIC_SALT,
            iterations=100_000,
        )
        return kdf.derive(f"{username}:{write_password}".encode())

    @staticmethod
    def _compute_write_proof(write_key: bytes, lock_secret: bytes) -> bytes:
        """Compute HMAC proof that write_key is authorised for this lock_secret."""
        return hmac.digest(write_key, lock_secret, "sha256")

    def verify_write_password(self, username: str, write_password: str) -> bool:
        mime, content = self.get_blob(LOCK_PATH)
        if not mime:
            return False
        try:
            payload = json.loads(content.decode())
            lock_secret = bytes.fromhex(payload["lock_secret"])
            stored_proof = bytes.fromhex(payload["write_proof"])
            write_key = self._derive_write_key(username, write_password)
            computed = self._compute_write_proof(write_key, lock_secret)
            return hmac.compare_digest(stored_proof, computed)
        except Exception:
            return False

    def create_lock(self, username: str, write_password: str) -> bool:
        if self.is_locked():
            return False
        write_key = self._derive_write_key(username, write_password)
        lock_secret = secrets.token_bytes(32)
        write_proof = self._compute_write_proof(write_key, lock_secret)
        payload = {
            "lock_secret": lock_secret.hex(),
            "write_proof": write_proof.hex(),
        }
        self.store_blob(LOCK_PATH, json.dumps(payload).encode(), "application/json")
        return True

    def remove_lock(self):
        path_hash = self.crypto.compute_path_hash(LOCK_PATH)
        path_hash_b64 = b64encode(path_hash).decode()
        self.storage.delete_blob(path_hash_b64)

    def update_index(self, add_path=None, remove_path=None):
        mime, content = self.get_blob(INDEX_PATH)

        if mime:
            index = json.loads(content.decode())
        else:
            index = {"version": 1, "paths": []}

        paths = set(index["paths"])

        if add_path:
            paths.add(add_path)

        if remove_path:
            paths.discard(remove_path)

        index["paths"] = sorted(paths)

        self.store_blob(
            INDEX_PATH,
            json.dumps(index).encode(),
            "application/json"
        )

## Main app functions

def send_partial_content(content: bytes, mime_type: str):
    """Handle HTTP Range requests for partial content delivery."""
    range_header = request.headers.get('Range')
    
    if not range_header:
        # No range request, send full content
        response = make_response(content)
        response.headers['Content-Type'] = mime_type
        response.headers['Accept-Ranges'] = 'bytes'
        response.headers['Content-Length'] = len(content)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
    
    # Parse range header (e.g., "bytes=0-1023")
    try:
        byte_range = range_header.replace('bytes=', '').strip()
        start, end = byte_range.split('-')
        start = int(start) if start else 0
        end = int(end) if end else len(content) - 1
        
        # Ensure valid range
        if start >= len(content) or start < 0 or end < start:
            response = make_response("Invalid range", 416)
            response.headers['Content-Range'] = f'bytes */{len(content)}'
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response
        
        end = min(end, len(content) - 1)
        chunk = content[start:end + 1]
        
        response = make_response(chunk)
        response.status_code = 206  # Partial Content
        response.headers['Content-Type'] = mime_type
        response.headers['Content-Range'] = f'bytes {start}-{end}/{len(content)}'
        response.headers['Accept-Ranges'] = 'bytes'
        response.headers['Content-Length'] = len(chunk)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
        
    except (ValueError, IndexError):
        response = make_response("Invalid range format", 416)
        response.headers['Content-Range'] = f'bytes */{len(content)}'
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response


@app.route('/_/login', methods=['GET', 'POST'])
def login():
    """Login page to derive and set session token cookie."""
    next_url = request.args.get('next', '/')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if username and password:
            # Derive session token (expensive PBKDF2)
            token = CryptoManager.derive_session_token(username, password)
            sessionobj = Session(token)
            
            # Redirect back to where they came from
            response = redirect(next_url)
            sessionobj.set_cookie(response)
            session["username"] = username
            return response
    
    return render_template_string(HtmlAssets.LOGIN_FORM, next_url=next_url)


@app.route('/_/logout')
def logout():
    """Clear session token cookie."""
    response = make_response(render_template_string(HtmlAssets.LOGOUT_PAGE))
    response.set_cookie(COOKIE_NAME, '', expires=0)
    return response


@app.route('/<path:blob_path>', methods=['GET'])
def get_blob_route(blob_path):
    """Retrieve and decrypt a blob with range request support."""
    session_obj = Session.from_request()
    if not session_obj:
        return redirect(f'/_/login?next=/{blob_path}')

    mime_type, content = session_obj.get_blob(blob_path)

    if not mime_type:
        return render_template_string(HtmlAssets.NOT_FOUND_WITH_UPLOAD, path=blob_path), 404

    return send_partial_content(content, mime_type)


@app.route('/<path:blob_path>', methods=['PUT', 'POST'])
def put_blob_route(blob_path):
    session_obj = Session.from_request()
    if not session_obj:
        return redirect(f'/_/login?next=/{blob_path}')

    # Protect internal reserved paths from direct user writes
    if blob_path.startswith('.meta/'):
        return "Path is reserved", 403

    # Enforce lock
    if session_obj.is_locked() and not session.get("write_enabled"):
        return "Namespace is locked (read-only)", 403

    content = request.get_data()
    mime_type = request.content_type or 'application/octet-stream'

    # Empty body = delete
    if len(content) == 0:
        path_hash = session_obj.crypto.compute_path_hash(blob_path)
        path_hash_b64 = b64encode(path_hash).decode()
        deleted = session_obj.storage.delete_blob(path_hash_b64)

        if deleted:
            session_obj.update_index(remove_path=blob_path)
            return '', 204
        else:
            return "Blob not found", 404

    session_obj.store_blob(blob_path, content, mime_type)
    session_obj.update_index(add_path=blob_path)
    return make_response(f"Blob stored at /{blob_path}", 201)


@app.route('/', methods=['GET'])
def get_root_blob():
    return get_blob_route('index.html')  # Or handle however you want

@app.route('/', methods=['PUT', 'POST'])
def put_root_blob():
    return put_blob_route('index.html')  # Or handle however you want

@app.route('/_/lock', methods=['GET', 'POST'])
def lock_namespace():
    session_obj = Session.from_request()
    if not session_obj:
        return redirect('/_/login')

    if request.method == 'GET':
        return f"""
        <h3>Lock Namespace</h3>
        <form method="POST">
            Username:<br>
            <input name="username" value="{session.get('username', '')}"><br><br>
            Write Password:<br>
            <input type="password" name="write_password"><br><br>
            <button type="submit">Lock</button>
        </form>
        """

    # POST
    write_password = request.form.get("write_password", "")
    username = request.form.get("username", "")

    if not username or not write_password:
        return "Missing credentials", 400

    if session_obj.is_locked():
        return "Already locked", 400

    created = session_obj.create_lock(username, write_password)
    if not created:
        return "Already locked", 400

    session["write_enabled"] = False
    return "Namespace locked"

@app.route('/_/unlock', methods=['GET', 'POST'])
def unlock_namespace():
    session_obj = Session.from_request()
    if not session_obj:
        return redirect('/_/login')

    if request.method == 'GET':
        return f"""
        <h3>Unlock Namespace (Write Access)</h3>
        <form method="POST">
            Username:<br>
            <input name="username" value="{session.get('username', '')}"><br><br>
            Write Password:<br>
            <input type="password" name="write_password"><br><br>
            <button type="submit">Unlock</button>
        </form>
        """

    # POST
    write_password = request.form.get("write_password", "")
    username = request.form.get("username", "")

    if not username or not write_password:
        return "Missing credentials", 400

    if not session_obj.is_locked():
        return "Not locked", 400

    if session_obj.verify_write_password(username, write_password):
        session["write_enabled"] = True
        return "Unlocked for this session"
    else:
        return "Incorrect write password", 403

import json
@app.route('/_/index', methods=['GET'])
def view_index():
    session_obj = Session.from_request()
    if not session_obj:
        return redirect('/_/login')

    mime, content = session_obj.get_blob(INDEX_PATH)

    if not mime:
        return "<h3>No index found.</h3>"

    try:
        index = json.loads(content.decode())
    except:
        return "Corrupted index", 500

    html = "<h3>Namespace Index</h3><ul>"
    for path in index.get("paths", []):
        html += f'<li><a href="/{path}">{path}</a></li>'
    html += "</ul>"

    return html

@app.errorhandler(404)
def not_found(e):
    """Custom 404 handler."""
    session_obj = Session.from_request()
    if not session_obj:
        return redirect(f'/_/login?next={request.path}')

    path = request.path.lstrip('/')
    if not path or path.startswith('_/') or path.startswith('.meta/'):
        return "Not found", 404

    return render_template_string(HtmlAssets.NOT_FOUND_WITH_UPLOAD, path=path), 404
def main():
    print("=" * 60)
    print("🔐 Encrypted Blob Storage Server")
    print("=" * 60)
    print(f"\n🌐 Login at: http://localhost:5000/_/login")
    print(f"👋 Logout at: http://localhost:5000/_/logout")
    print("\n💡 Each username+password creates a unique storage namespace")
    print("   - alice:pass1 and bob:pass1 have separate storage")
    print("   - alice:pass1 and alice:pass2 have separate storage")
    print("\n📝 Example with curl:")
    print("   # Login and save session cookie")
    print("   curl -c cookies.txt -d 'username=alice&password=secret' \\")
    print("        http://localhost:5000/_/login")
    print("\n   # Upload a file")
    print("   curl -b cookies.txt -X PUT --data-binary @video.mp4 \\")
    print("        -H 'Content-Type: video/mp4' \\")
    print("        http://localhost:5000/videos/my-video.mp4")
    print("\n   # Download it back")
    print("   curl -b cookies.txt http://localhost:5000/videos/my-video.mp4 -o video.mp4")
    print("=" * 60)
    print()
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    main()
