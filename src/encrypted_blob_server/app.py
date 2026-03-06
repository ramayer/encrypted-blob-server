#!/usr/bin/env python3
"""
Encrypted Blob Storage Server

Each username+password derives a unique encryption key via PBKDF2.
Blobs are stored encrypted in SQLite; credentials are never stored.
Different credentials = completely isolated, indistinguishable namespaces.

Reserved paths (blocked from user PUT):
  _/index   — file listing + metadata (JSON)
  _/locked  — write-lock marker (JSON)

UI routes:
  /_/login
  /_/logout
  /_/admin    — file index, upload, and lock toggle in one page

Optional:
  INVITE_TOKEN   — if set, new namespaces require this token at login
"""

import os, sqlite3, hashlib, secrets, hmac, json
from base64 import b64encode, b64decode
from datetime import datetime, timezone
from functools import lru_cache
from flask import Flask, request, make_response, redirect, Response
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_DEFAULT_SALT  = b"encrypted-blob-storage-v1-salt-change-in-production"
# BLOB_SALT salts every derived key. Two deployments sharing a salt and the
# same credentials would produce the same encryption keys. Set it in production.
STATIC_SALT    = os.environb.get(b"BLOB_SALT", _DEFAULT_SALT)

SESSION_COOKIE = "bs_session"
COOKIE_AGE     = 86400          # 24 h
LOCK_PATH      = "_/locked"
INDEX_PATH     = "_/index"
RESERVED       = {LOCK_PATH, INDEX_PATH}
INVITE_TOKEN   = os.environ.get("BLOB_INVITE_TOKEN", None)

# ── Crypto ────────────────────────────────────────────────────────────────────

def derive_session_token(username: str, password: str) -> bytes:
    """Expensive (PBKDF2, 100k rounds). Called once at login."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=STATIC_SALT, iterations=100_000)
    return kdf.derive(f"{username}:{password}".encode())

def derive_write_key(username: str, write_password: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=STATIC_SALT, iterations=100_000)
    return kdf.derive(f"write:{username}:{write_password}".encode())

def enc_key(token: bytes) -> bytes:
    return hashlib.sha256(b"enc:" + token).digest()

def path_hash(key: bytes, path: str) -> str:
    """Namespace-scoped path identifier used as the DB primary key."""
    return b64encode(hashlib.sha256(f"{path}:{key.hex()}".encode()).digest()).decode()

def encrypt(key: bytes, data: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, data, aad or None)

def decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad or None)

# ── Storage ───────────────────────────────────────────────────────────────────
# SQLite with check_same_thread=False is safe here because Flask's dev server
# is single-threaded, and in production (gunicorn/uwsgi) each worker has its
# own process with its own connection. For a multi-threaded single-process
# deployment, wrap db() calls in a threading.Lock.

DB_PATH = "blobs.sqlite3"

def _init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS blobs (
            path_hash  TEXT PRIMARY KEY,
            mime_nonce BLOB, mime_enc BLOB,
            data_nonce BLOB, data_enc BLOB
        )""")

def db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def db_get(phash: str):
    with db() as c:
        return c.execute("SELECT mime_nonce,mime_enc,data_nonce,data_enc "
                         "FROM blobs WHERE path_hash=?", (phash,)).fetchone()

def db_put(phash, mn, me, dn, de):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO blobs VALUES (?,?,?,?,?)",
                  (phash, mn, me, dn, de))

def db_del(phash: str) -> bool:
    with db() as c:
        return c.execute("DELETE FROM blobs WHERE path_hash=?",
                         (phash,)).rowcount > 0

# ── Blob cache ────────────────────────────────────────────────────────────────
# Keyed on path_hash (already namespace-scoped), never on the raw token.
# lru_cache is thread-safe for reads. Writes call cache_clear(), which is
# acceptable since writes are rare relative to reads.
# Note: lru_cache also caches None (cache misses). This is fine — any write
# to a previously-missing path calls cache_clear(), so stale misses can't
# persist across a PUT. Do not remove cache_clear() from blob_put/blob_del.

@lru_cache(maxsize=64)
def cached_db_get(phash: str):
    """Cached wrapper around db_get. Returns raw DB row or None."""
    return db_get(phash)

def cache_clear():
    cached_db_get.cache_clear()

# ── Blob get / put / del ──────────────────────────────────────────────────────
# Each blob's ciphertext is bound to its path hash via AEAD additional data
# (AAD). This means a ciphertext transplanted to a different path_hash row
# will fail authentication on decryption — the DB cannot be rearranged to
# swap or move blobs, even by someone with full DB access.
#
# Critically, this also means that blobs removed from the index are
# unlocatable even to someone who knows the credentials — they must also
# know the exact path. Credentials alone are not sufficient. See README.

def blob_get(token: bytes, path: str) -> tuple:
    """Returns (mime, data) or (None, None)."""
    key   = enc_key(token)
    phash = path_hash(key, path)
    row   = cached_db_get(phash)
    if not row: return None, None
    aad = phash.encode()
    try:
        return decrypt(key, row[0], row[1], aad).decode(), \
               decrypt(key, row[2], row[3], aad)
    except Exception:
        return None, None

def blob_put(token: bytes, path: str, data: bytes, mime: str):
    key   = enc_key(token)
    phash = path_hash(key, path)
    aad   = phash.encode()
    mn, me = encrypt(key, mime.encode(), aad)
    dn, de = encrypt(key, data,          aad)
    db_put(phash, mn, me, dn, de)
    _maybe_insert_noise_row()
    cache_clear()

def _maybe_insert_noise_row():
    """With ~1% probability, insert a row of random bytes into the DB.
    Noise rows are indistinguishable from real blobs without a valid key —
    same structure, and sized by sampling a random real row then choosing
    a uniform random size from 0 to 110% of that size. This ensures even
    the largest real rows are not identifiable as real by their size.
    Noise rows accumulate slowly and are never deleted."""
    if secrets.randbelow(100) != 0:
        return
    # Sample a random real row to get a realistic size reference
    with db() as c:
        row = c.execute(
            "SELECT length(data_enc) FROM blobs ORDER BY RANDOM() LIMIT 1"
        ).fetchone()
    ref_size = row[0] if row else 256
    noise_size = secrets.randbelow(int(ref_size * 1.1) + 1)
    fake_phash = b64encode(secrets.token_bytes(32)).decode()
    db_put(fake_phash,
           secrets.token_bytes(12), secrets.token_bytes(32 + 16),  # mime: small fixed
           secrets.token_bytes(12), secrets.token_bytes(noise_size + 16))  # data: random size

def blob_del(token: bytes, path: str) -> bool:
    phash = path_hash(enc_key(token), path)
    ok    = db_del(phash)
    if ok: cache_clear()
    return ok

# ── Index ─────────────────────────────────────────────────────────────────────
# Note: index_update is not atomic with blob_put/blob_del. A crash between
# the two leaves a blob that exists in storage but is absent from the index.
# This is recoverable — the blob is still accessible by direct URL. The index
# is advisory, not authoritative.

def index_get(token: bytes) -> dict:
    _, content = blob_get(token, INDEX_PATH)
    if content:
        try: return json.loads(content)
        except Exception: pass
    return {"v": 2, "files": {}}

def index_update(token: bytes, add=None, remove=None, size=None):
    idx = index_get(token)
    if add:
        idx["files"][add] = {
            "uploaded": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "size": size or 0,
        }
    if remove:
        idx["files"].pop(remove, None)
    blob_put(token, INDEX_PATH, json.dumps(idx).encode(), "application/json")

# ── Lock ──────────────────────────────────────────────────────────────────────
# The lock blob stores an HMAC proof. Knowing the write password lets you
# remove the lock. Locked means locked — there is no "temporarily unlocked"
# state. To make writes, remove the lock, write, then re-lock.

def lock_exists(token: bytes) -> bool:
    mime, _ = blob_get(token, LOCK_PATH)
    return mime is not None

def lock_create(token: bytes, username: str, write_password: str):
    wk          = derive_write_key(username, write_password)
    lock_secret = secrets.token_bytes(32)
    proof       = hmac.digest(wk, lock_secret, "sha256")
    payload     = {"secret": lock_secret.hex(), "proof": proof.hex()}
    blob_put(token, LOCK_PATH, json.dumps(payload).encode(), "application/json")

def lock_verify(token: bytes, username: str, write_password: str) -> bool:
    _, content = blob_get(token, LOCK_PATH)
    if not content: return False
    try:
        p        = json.loads(content)
        wk       = derive_write_key(username, write_password)
        computed = hmac.digest(wk, bytes.fromhex(p["secret"]), "sha256")
        return hmac.compare_digest(computed, bytes.fromhex(p["proof"]))
    except Exception:
        return False

def lock_remove(token: bytes):
    blob_del(token, LOCK_PATH)

# ── Request helpers ───────────────────────────────────────────────────────────

def get_token() -> bytes | None:
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie: return None
    try:
        token = b64decode(cookie)
        return token if len(token) == 32 else None
    except Exception:
        return None

def get_username() -> str:
    return request.cookies.get("bs_user", "")

def fmt_size(n) -> str:
    n = int(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n} {u}"
        n //= 1024
    return f"{n} TB"

def serve(content: bytes, mime: str) -> Response:
    """Serve bytes with HTTP Range support."""
    # Declare charset for text types — without it browsers may guess Latin-1,
    # mangling any UTF-8 content (emoji, curly quotes, etc.)
    if mime.startswith("text/") or mime == "application/json":
        mime = mime + "; charset=utf-8"
    total = len(content)
    rh    = request.headers.get("Range")
    if rh:
        try:
            s, e = rh.replace("bytes=", "").split("-")
            s = int(s) if s else 0
            e = int(e) if e else total - 1
            if not (0 <= s <= e < total):
                r = make_response("Range Not Satisfiable", 416)
                r.headers["Content-Range"] = f"bytes */{total}"
                return r
            chunk = content[s:e+1]
            r = make_response(chunk, 206)
            r.headers["Content-Range"]  = f"bytes {s}-{e}/{total}"
            r.headers["Content-Length"] = len(chunk)
        except (ValueError, IndexError):
            return make_response("Bad Range", 416)
    else:
        r = make_response(content)
        r.headers["Content-Length"] = total
    r.headers.update({
        "Content-Type":  mime,
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    })
    return r

# ── HTML ──────────────────────────────────────────────────────────────────────

CSS = """
body{font-family:system-ui,sans-serif;max-width:600px;margin:60px auto;padding:16px;background:#f5f5f5}
.box{background:#fff;padding:28px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h1{margin-top:0;font-size:20px}h2{font-size:15px;margin-top:20px;color:#444}
p{color:#555;line-height:1.5;font-size:14px}
input{width:100%;padding:9px;margin:5px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px;font-size:14px}
input:focus{outline:none;border-color:#07c}
button{width:100%;padding:9px;margin-top:5px;background:#07c;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}
button:hover{background:#005fa3}button.d{background:#c00}button.d:hover{background:#900}
button.sm{width:auto;padding:3px 10px;font-size:12px;margin:0}
a{color:#07c}code{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:12px}
pre{background:#f4f4f4;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:7px 5px;border-bottom:1px solid #eee;text-align:left}th{font-size:11px;color:#999}
.nav{margin-bottom:16px;font-size:13px}.nav a{margin-right:14px}
.ok{color:#1a6b2a;background:#e6f4ea;padding:7px 10px;border-radius:4px;font-size:13px;margin-top:8px}
.err{color:#8b1a1a;background:#fdecea;padding:7px 10px;border-radius:4px;font-size:13px;margin-top:8px}
"""

def page(title, body, nav=True):
    nav_html = '<div class="nav"><a href="/_/admin">⚙ Admin</a><a href="/_/logout">Logout</a></div>' if nav else ""
    return (f'<!DOCTYPE html><html><head><title>{title}</title><style>{CSS}</style></head>'
            f'<body>{nav_html}<div class="box">{body}</div></body></html>')

# ── Routes: auth ──────────────────────────────────────────────────────────────

@app.route("/_/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next", "/_/admin")
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        invite   = request.form.get("invite",   "").strip()
        if username and password:
            token = derive_session_token(username, password)
            if INVITE_TOKEN:
                _, existing = blob_get(token, INDEX_PATH)
                if existing is None and invite != INVITE_TOKEN:
                    error = "Invalid invite token."
            if not error:
                resp = redirect(next_url)
                resp.set_cookie(SESSION_COOKIE, b64encode(token).decode(),
                                max_age=COOKIE_AGE, httponly=True, samesite="Lax",
                                secure=False)  # ⚠ set secure=True in production — cookie IS the enc key
                # bs_user is not secret — it's only used to derive the write key
                # at lock/unlock time. httponly=False is intentional.
                resp.set_cookie("bs_user", username, max_age=COOKIE_AGE, samesite="Lax")
                return resp
        else:
            error = "Username and password required."

    invite_field = '<input name="invite" placeholder="Invite token">' if INVITE_TOKEN else ""
    err_html     = f'<p class="err">{error}</p>' if error else ""
    body = f"""<h1>🔐 Login</h1>
<p>Each username+password opens a unique encrypted namespace.</p>
{err_html}
<form method="POST" action="/_/login?next={next_url}">
  <input name="username" placeholder="Username" required autofocus>
  <input type="password" name="password" placeholder="Password" required>
  {invite_field}
  <button onclick="this.disabled=true;this.textContent='Logging in…';this.form.submit()">Login</button>
</form>
<p style="font-size:12px;color:#999;margin-top:12px">
  Different credentials = completely separate, indistinguishable namespaces.
</p>"""
    return page("Login", body, nav=False)


@app.route("/_/logout")
def logout():
    resp = redirect("/_/login")
    resp.set_cookie(SESSION_COOKIE, "", expires=0)
    resp.set_cookie("bs_user",      "", expires=0)
    return resp

# ── Routes: admin ─────────────────────────────────────────────────────────────

@app.route("/_/admin", methods=["GET", "POST"])
def admin():
    token = get_token()
    if not token: return redirect("/_/login?next=/_/admin")

    msg = ""; msg_cls = "ok"

    if request.method == "POST":
        action   = request.form.get("action", "")
        username = get_username()
        wp       = request.form.get("wp", "")

        if action == "lock":
            wp2 = request.form.get("wp2", "")
            if not wp:               msg, msg_cls = "Write password cannot be empty.", "err"
            elif wp != wp2:          msg, msg_cls = "Passwords do not match.", "err"
            elif lock_exists(token): msg, msg_cls = "Already locked.", "err"
            else:
                lock_create(token, username, wp)
                msg = "Namespace locked."

        elif action == "remove_lock":
            if lock_verify(token, username, wp):
                lock_remove(token)
                msg = "Lock removed. Namespace is now writable."
            else:
                msg, msg_cls = "Incorrect write password.", "err"

    locked = lock_exists(token)
    idx    = index_get(token)
    files  = sorted(idx.get("files", {}).items())

    if files:
        rows = "".join(
            f'<tr id="r{i}"><td><a href="/{p}">{p}</a></td>'
            f'<td>{fmt_size(m.get("size", 0))}</td>'
            f'<td>{m.get("uploaded", "")}</td>'
            f'<td><button class="sm d" data-path="{p}" data-row="r{i}">✕</button></td></tr>'
            for i, (p, m) in enumerate(files)
        )
        file_table = (f"<table><tr><th>Path</th><th>Size</th><th>Uploaded</th><th></th></tr>"
                      f"{rows}</table>")
    else:
        file_table = "<p><em>No files yet.</em></p>"

    if locked:
        lock_html = """<p>🔒 Locked — enter the write password to remove the lock.</p>
            <form method="POST"><input type="hidden" name="action" value="remove_lock">
            <input type="password" name="wp" placeholder="Write password" required>
            <button class="d">Remove lock</button></form>"""
    else:
        lock_html = """<p>✏️ Unlocked — set a write password to make this namespace read-only.</p>
            <form method="POST"><input type="hidden" name="action" value="lock">
            <input type="password" name="wp"  placeholder="Write password" required>
            <input type="password" name="wp2" placeholder="Confirm write password" required>
            <button>Lock namespace</button></form>"""

    msg_html = f'<p class="{msg_cls}">{msg}</p>' if msg else ""

    body = f"""<h1>Admin <small style="font-weight:normal;font-size:14px;color:#888">{get_username()}</small></h1>
{msg_html}
<h2>Files</h2>{file_table}
<h2>Upload</h2>
<input type="file" id="fi">
<input id="pi" placeholder="Path (defaults to filename)">
<button onclick="upload()">Upload</button>
<h2>Access control</h2>
{lock_html}
<script>
document.addEventListener('click', async e => {{
  const btn = e.target.closest('button[data-path]');
  if (!btn) return;
  const path = btn.dataset.path, rowId = btn.dataset.row;
  //if (!confirm("Delete /" + path + "?")) return;
  const r = await fetch("/" + path, {{method: "PUT", body: ""}});
  if (r.status === 204) document.getElementById(rowId)?.remove();
  else alert("Failed: " + r.statusText);
}});
async function upload() {{
  const f = document.getElementById("fi").files[0];
  if (!f) return alert("Choose a file.");
  const path = (document.getElementById("pi").value.trim() || f.name).replace(/^\\/+/, "");
  const r = await fetch("/" + path, {{method: "PUT", body: f,
      headers: {{"Content-Type": f.type || "application/octet-stream"}}}});
  if (r.ok) location.reload();
  else alert("Upload failed: " + (await r.text()));
}}
</script>"""

    return page("Admin", body)

# ── Routes: blobs ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def root_get(): return blob_get_route("index.html")

@app.route("/", methods=["PUT", "POST"])
def root_put(): return blob_put_route("index.html")

@app.route("/<path:p>", methods=["GET"])
def blob_get_route(p):
    token = get_token()
    if not token: return redirect(f"/_/login?next=/{p}")
    mime, data = blob_get(token, p)
    if not mime:
        body = (f"<h1>404 — Not Found</h1><p>No blob at <code>/{p}</code>.</p>"
                f'<input type="file" id="fi">'
                f'<button onclick="upload()">Upload to /{p}</button>'
                f"<script>async function upload(){{"
                f'const f=document.getElementById("fi").files[0];if(!f)return;'
                f'const r=await fetch("/{p}",{{method:"PUT",body:f,'
                f'headers:{{"Content-Type":f.type||"application/octet-stream"}}}});'
                f"if(r.ok)location.reload();else alert(\"Failed: \"+(await r.text()));}}</script>")
        return page(f"404 — {p}", body), 404
    return serve(data, mime)

@app.route("/<path:p>", methods=["PUT", "POST"])
def blob_put_route(p):
    token = get_token()
    if not token: return redirect(f"/_/login?next=/{p}")
    if p in RESERVED:      return "Reserved path", 403
    if lock_exists(token): return "Locked. Visit /_/admin to remove the lock first.", 403
    data = request.get_data()
    if not data:
        ok = blob_del(token, p)
        if ok: index_update(token, remove=p)
        return ("", 204) if ok else ("Not found", 404)
    blob_put(token, p, data, request.content_type or "application/octet-stream")
    index_update(token, add=p, size=len(data))
    return f"Stored /{p}", 201

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    _init_db()
    if STATIC_SALT == _DEFAULT_SALT:
        print("⚠  WARNING: using default BLOB_SALT. Set the BLOB_SALT environment")
        print("   variable to a unique secret before exposing this to the internet.")
    print("Encrypted Blob Storage  —  http://localhost:5000/_/admin")
    if INVITE_TOKEN:
        print(f"Invite token required for new namespaces: {INVITE_TOKEN}")
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    main()
