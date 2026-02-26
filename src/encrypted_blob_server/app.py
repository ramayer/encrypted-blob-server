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
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

COOKIE_NAME = "blob_session"
COOKIE_MAX_AGE = 3600 * 24  # 24 hours
STATIC_SALT = b"encrypted-blob-storage-v1-salt-change-in-production"


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
            <button type="submit" id="uploadBtn">Upload to /{{ path }}</button>
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
                    const response = await fetch('/{{ path }}', {
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
                    created_at TEXT NOT NULL,
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
                (path_hash, mime_nonce, mime_enc, content_nonce, content_enc, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                path_hash,
                mime_nonce,
                mime_enc,
                content_nonce,
                content_enc,
                datetime.utcnow().isoformat()
            ))
            conn.commit()
    
    def delete_blob(self, path_hash: bytes) -> bool:
        """Delete a blob from database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM blobs WHERE path_hash = ?", (path_hash,))
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
            return Session(token)
        except:
            return None
    
    @functools.lru_cache(maxsize=128)
    @staticmethod
    def get_cached_blob(token: bytes, path: str, db_path: str):
        s = Session(token)
        mime_type,content = s.get_blob(path)
        return mime_type,content
    
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
        
        # Clear cache
        Session.get_cached_blob.cache_clear()


def send_partial_content(content: bytes, mime_type: str):
    """Handle HTTP Range requests for partial content delivery."""
    range_header = request.headers.get('Range')
    
    if not range_header:
        # No range request, send full content
        response = make_response(content)
        response.headers['Content-Type'] = mime_type
        response.headers['Accept-Ranges'] = 'bytes'
        response.headers['Content-Length'] = len(content)
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
            return response
        
        end = min(end, len(content) - 1)
        chunk = content[start:end + 1]
        
        response = make_response(chunk)
        response.status_code = 206  # Partial Content
        response.headers['Content-Type'] = mime_type
        response.headers['Content-Range'] = f'bytes {start}-{end}/{len(content)}'
        response.headers['Accept-Ranges'] = 'bytes'
        response.headers['Content-Length'] = len(chunk)
        return response
        
    except (ValueError, IndexError):
        response = make_response("Invalid range format", 416)
        response.headers['Content-Range'] = f'bytes */{len(content)}'
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
            session = Session(token)
            
            # Redirect back to where they came from
            response = redirect(next_url)
            session.set_cookie(response)
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
    session = Session.from_request()
    if not session:
        return redirect(f'/_/login?next=/{blob_path}')
    
    #mime_type, content = session.get_blob(blob_path)
    mime_type, content = Session.get_cached_blob(session.token, blob_path, None)
    
    if not mime_type:
        return render_template_string(HtmlAssets.NOT_FOUND_WITH_UPLOAD, path=blob_path), 404
    
    return send_partial_content(content, mime_type)


@app.route('/<path:blob_path>', methods=['PUT', 'POST'])
def put_blob_route(blob_path):
    """Encrypt and store a blob."""
    session = Session.from_request()
    if not session:
        return redirect(f'/_/login?next=/{blob_path}')
    
    # Get content and MIME type
    content = request.get_data()
    mime_type = request.content_type or 'application/octet-stream'
    
    if not content:
        return "No content provided", 400
    
    session.store_blob(blob_path, content, mime_type)
    
    return make_response(f"Blob stored at /{blob_path}", 201)

@app.route('/', methods=['GET'])
def get_root_blob():
    return get_blob_route('index.html')  # Or handle however you want

@app.route('/', methods=['PUT', 'POST'])
def put_root_blob():
    return put_blob_route('index.html')  # Or handle however you want

@app.errorhandler(404)
def not_found(e):
    """Custom 404 handler."""
    session = Session.from_request()
    if not session:
        return redirect(f'/_/login?next={request.path}')
    
    path = request.path.lstrip('/')
    if path.startswith('_/'):
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
