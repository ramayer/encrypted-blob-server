#!/usr/bin/env python3
"""
Docker entrypoint: runs the blob server behind mitmproxy for HTTPS.

mitmproxy acts as a reverse proxy, terminating TLS and forwarding plain HTTP
to the Flask server on localhost:5000. On first boot mitmproxy generates a
self-signed CA certificate. The bootstrap step uploads that cert and setup
instructions into a locked 'setup/setup' namespace so users have a guided
path to trusting the CA.

The setup namespace is locked with a random write password printed once to
the logs at startup. After that, the setup page is read-only permanently.
"""

import os, sys, time, signal, socket, subprocess, threading, secrets
from pathlib import Path

# All crypto/storage primitives from the blob server
from encrypted_blob_server.app import derive_session_token, blob_put, blob_del, index_update, \
                   lock_create, lock_exists, _init_db

UPSTREAM_HOST        = "127.0.0.1"
UPSTREAM_PORT        = 5000
MITMPROXY_PORT       = 5443
CERT_DIR             = Path.home() / ".mitmproxy"
SERVER_HOSTNAME      = os.environ.get("SERVER_HOSTNAME", "localhost")
SERVER_PORT          = os.environ.get("SERVER_PORT", str(MITMPROXY_PORT))


# ── Readiness checks ──────────────────────────────────────────────────────────

def wait_for_port(host: str, port: int, timeout: float = 15.0, label: str = ""):
    """Block until a TCP port is accepting connections, or raise on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {label or f'{host}:{port}'} after {timeout}s")

def wait_for_certs(timeout: float = 15.0):
    """Block until mitmproxy has written its CA certificate files."""
    ca_cer = CERT_DIR / "mitmproxy-ca-cert.cer"
    ca_pem = CERT_DIR / "mitmproxy-ca-cert.pem"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ca_cer.exists() and ca_pem.exists():
            return
        time.sleep(0.25)
    raise RuntimeError(f"CA certificates not found in {CERT_DIR} after {timeout}s")


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def bootstrap_setup_namespace():
    """
    Upload CA cert and setup instructions into the 'setup/setup' namespace,
    then lock it so the page cannot be overwritten.

    If the namespace is already locked (server restart), skip silently —
    the content is already in place.
    """
    _init_db()
    token = derive_session_token("setup", "setup")

    if lock_exists(token):
        print("Bootstrap: setup namespace already locked, skipping.")
        return

    wait_for_certs()

    ca_cer_path = CERT_DIR / "mitmproxy-ca-cert.cer"
    ca_pem_path = CERT_DIR / "mitmproxy-ca-cert.pem"

    blob_put(token, "ca-cert.cer", ca_cer_path.read_bytes(),
             "application/x-x509-ca-cert")
    print("  ✓ Uploaded ca-cert.cer")

    blob_put(token, "ca-cert.pem", ca_pem_path.read_bytes(),
             "application/x-pem-file")
    print("  ✓ Uploaded ca-cert.pem")

    blob_put(token, "index.html", _setup_html().encode(), "text/html")
    print("  ✓ Uploaded index.html")

    # Update index so the admin page shows the files (advisory only)
    index_update(token, add="ca-cert.cer", size=ca_cer_path.stat().st_size)
    index_update(token, add="ca-cert.pem", size=ca_pem_path.stat().st_size)
    index_update(token, add="index.html",  size=len(_setup_html().encode()))

    # Lock the namespace with a random write password.
    # Print it once so the operator has it if they ever need to update the page.
    write_password = secrets.token_hex(16)
    lock_create(token, "setup", write_password)
    print(f"  ✓ Setup namespace locked")
    print(f"  ⚠  Write password (printed once): {write_password}")


def _setup_html() -> str:
    base = f"https://{SERVER_HOSTNAME}:{SERVER_PORT}"
    return f"""<!DOCTYPE html>
<html>
<head>
<title>HTTPS Setup</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:740px;margin:40px auto;padding:20px;background:#f5f5f5;line-height:1.6}}
.box{{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}}
h1{{margin-top:0;border-bottom:3px solid #07c;padding-bottom:10px}}
h2{{margin-top:28px;color:#444}}
.warn{{background:#fff3cd;border-left:4px solid #ffc107;padding:12px 16px;margin:16px 0}}
.ok  {{background:#d4edda;border-left:4px solid #28a745;padding:12px 16px;margin:16px 0}}
.dl  {{background:#e7f3ff;border:2px solid #07c;border-radius:8px;padding:20px;margin:16px 0;text-align:center}}
.btn {{display:inline-block;background:#07c;color:#fff;padding:10px 24px;border-radius:4px;text-decoration:none;font-weight:600;margin:6px}}
.btn:hover{{background:#005fa3}}
.step{{background:#f8f9fa;border-left:4px solid #07c;padding:12px 16px;margin:10px 0}}
code{{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:13px}}
pre{{background:#2d2d2d;color:#f8f8f2;padding:14px;border-radius:4px;overflow-x:auto;font-size:13px}}
</style>
</head>
<body><div class="box">
<h1>🔐 HTTPS Certificate Setup</h1>

<div class="warn">
<strong>⚠️ Security notice:</strong> Your browser doesn't trust this server's certificate yet.
Follow the steps below to install the CA certificate. This is a one-time setup.
</div>

<div class="ok">
<strong>✓ You're connected.</strong> You logged in as <code>setup / setup</code> —
a read-only account containing only these setup files.
</div>

<h2>📥 Download certificate</h2>
<div class="dl">
  <a class="btn" href="/ca-cert.cer" download>📄 Browser (.cer)</a>
  <a class="btn" href="/ca-cert.pem" download>📄 Command line (.pem)</a>
</div>

<h2>Chrome / Edge / Brave</h2>
<div class="step">1. Download <code>ca-cert.cer</code> above</div>
<div class="step">2. Settings → Privacy and security → Security → Manage certificates</div>
<div class="step">3. Trusted Root Certification Authorities → Import → select the file</div>
<div class="step">4. <strong>Restart browser</strong>, then visit <a href="{base}/_/login">{base}/_/login</a></div>

<h2>Firefox</h2>
<div class="step">1. Download <code>ca-cert.cer</code> above</div>
<div class="step">2. Settings → Privacy &amp; Security → Certificates → View Certificates</div>
<div class="step">3. Authorities tab → Import → select the file → trust to identify websites</div>
<div class="step">4. Reload the page</div>

<h2>Safari (macOS)</h2>
<div class="step">1. Download <code>ca-cert.cer</code> above</div>
<div class="step">2. Double-click to add to Keychain Access</div>
<div class="step">3. Double-click the cert in Keychain → Trust → Always Trust → close (enter password)</div>
<div class="step">4. Reload the page</div>

<h2>curl / command line</h2>
<pre>
# Download cert and use it
curl -k {base}/ca-cert.pem -o ca-cert.pem
curl --cacert ca-cert.pem {base}/_/login

# Install system-wide (Ubuntu/Debian)
sudo cp ca-cert.pem /usr/local/share/ca-certificates/blob-server.crt
sudo update-ca-certificates
</pre>

<h2>✅ After installation</h2>
<div class="step">
Visit <strong><a href="{base}/_/login">{base}/_/login</a></strong> —
you should see a padlock 🔒 with no warnings.
Log in with any username and password to create your own isolated namespace.
</div>

</div></body></html>"""


# ── Process management ────────────────────────────────────────────────────────

def start_mitmproxy() -> subprocess.Popen:
    CERT_DIR.mkdir(exist_ok=True)
    cmd = [
        "mitmdump",
        "--mode",         f"reverse:http://{UPSTREAM_HOST}:{UPSTREAM_PORT}",
        "--listen-host",  "0.0.0.0",
        "--listen-port",  str(MITMPROXY_PORT),
        "--set",          "block_global=false",
        "--set",          f"confdir={CERT_DIR}",
    ]
    print(f"Starting mitmproxy on :{MITMPROXY_PORT} → http://{UPSTREAM_HOST}:{UPSTREAM_PORT}")
    # stderr to DEVNULL suppresses per-request logs; errors go to stdout
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def start_flask():
    """Run Flask in a daemon thread. Logs suppressed to reduce noise."""
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    from encrypted_blob_server import app
    print(f"Starting Flask on http://{UPSTREAM_HOST}:{UPSTREAM_PORT}")
    app.run(host=UPSTREAM_HOST, port=UPSTREAM_PORT, debug=False, use_reloader=False)


def drain_mitmproxy(proc: subprocess.Popen):
    """Read mitmproxy stdout in a thread to prevent pipe-buffer stalls.
    Only print lines that look like errors."""
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="ignore").strip()
        if line and ("error" in line.lower() or "warning" in line.lower()):
            print(f"[mitmproxy] {line}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    mitm_proc = start_mitmproxy()

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    # Wait for both services to be genuinely ready before bootstrapping
    wait_for_port(UPSTREAM_HOST, UPSTREAM_PORT, label="Flask")
    wait_for_port("0.0.0.0",    MITMPROXY_PORT, label="mitmproxy")

    print("Bootstrap: uploading setup namespace...")
    bootstrap_setup_namespace()

    base = f"https://{SERVER_HOSTNAME}:{SERVER_PORT}"
    print()
    print("=" * 56)
    print("🔐 Encrypted Blob Storage (HTTPS)")
    print(f"   Setup:  {base}/  (login: setup / setup)")
    print(f"   Login:  {base}/_/login")
    print("=" * 56)
    print()

    # Drain mitmproxy output in background to prevent pipe stall
    threading.Thread(target=drain_mitmproxy, args=(mitm_proc,), daemon=True).start()

    def shutdown(sig, frame):
        print("Shutting down...")
        mitm_proc.terminate()
        mitm_proc.wait()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    mitm_proc.wait()


if __name__ == "__main__":
    main()