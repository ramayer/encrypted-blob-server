# Encrypted Blob Server

A tiny, minimal HTTP server that stores **encrypted blobs** in SQLite and decrypts them on the fly.

**Main benefits**

* **Encrypted storage** — Blobs are encrypted using a key derived from the password supplied by the client. If a disk is stolen, data at rest remains encrypted.
* **No persisted server-side secrets, including usernames or passwords** — All encrypted blobs look the same to the server admin - and they are unable to tell what accounts exists, how many accounts exist, or what blobs belong to what accounts.   There may be 30 different users with "/img/cat.jpg" in the system and the admin will have no way of knowing anything about who owns which ones, or at what paths they exist.
* **Password‑scoped content** — the same URL path can map to different decrypted content for different passwords. This lets multiple users share the same URLs but see different content (or lets a single user host multiple sites from the same server by switching passwords).  If two users want "username: john", that's fine as long as they're using strong passwords.  (of course if they both pick password 12345 their accounts/hashes will have collisions)
* **No complex signup** — the password itself is the namespace.  If you log in with a new username/password 

---

## Quick summary

* Login: `POST /_/login` with `username` and `password` form fields. The server derives a session token and sets a secure session cookie.
* Upload: `PUT /path/to/blob` with `Content-Type` and the body. Requires an active session (login first). The blob is encrypted and stored in SQLite.
* Download: `GET /path/to/blob` with the same session decrypts and returns the blob. Supports `Range` requests so `<video>` elements and seeking work.
* Logout: `GET /_/logout` clears the session cookie.

---

## Files in this repo

* `app.py` — the minimal Flask application (main server).
* `start.sh` — entrypoint used by the Docker image to start the app, generate the mitmproxy CA, seed the CA and setup HTML as blobs, and launch mitmproxy as TLS reverse proxy.
* `Dockerfile` — builds an image that installs the package from GitHub and `mitmproxy`, and runs the `start.sh`.
* `pyproject.toml` — packaging config (Hatch + minimal deps).

---

## License

## ⚖️ License -- likely no traditional license or copyright applies

This project was created almost entirely by a handful of large language models.
The human contribution was minimal and mostly evaluative: initiating the idea, requesting papers, and describing qualitative behavior of the software.

As a result, there may be **no copyright ownership** in the traditional legal sense — most jurisdictions require meaningful human authorship to grant copyright.

Accordingly:

* ⚠️ No copyright is claimed.
* ✅ To the fullest extent allowed by law, this work is **dedicated to the public domain**.
* 🌍 Where a legal dedication is required, this repository is released under [CC0 1.0 Universal (Public Domain Dedication)](https://creativecommons.org/publicdomain/zero/1.0/).

You are free to **use, modify, copy, and redistribute** this project for any purpose, without restriction.

---

## Running locally from `pip install` (without HTTPS)

> This mode runs the Flask app on HTTP only (no TLS). It's useful for local dev and quick tests.

1. Install the package (if published) or run from local source. If your package is already on GitHub as the example, you can install it like:

```bash
pip install git+https://github.com/ramayer/encrypted-blob-server@v0.9.0-rc1
```

2. Run the app (it exposes port `5000` by default):

```bash
encrypted-blob-server
# or
python -m blobserver.app
# or 
uv run encrypted-blob-server
```

3. Use the server with `curl`:

* Login first:

```bash
curl -c cookies.txt -d 'username=alice&password=mysecret' http://127.0.0.1:5000/_/login
```

* Upload a file (example: small HTML page):

```bash
curl -b cookies.txt -X PUT -H "Content-Type: text/html" --data-binary @my-page.html http://127.0.0.1:5000/
```

* Download the file (same session):

```bash
curl -b cookies.txt http://127.0.0.1:5000/ -o index.html
```

* Upload a binary (image):

```bash
curl -c cookies1.txt -d 'username=alice&password=pass1' http://127.0.0.1:5000/_/login
curl -b cookies1.txt -X PUT -H "Content-Type: image/jpeg" --data-binary @cat1.jpg http://127.0.0.1:5000/img/cat.jpg
```

* Upload a second image to the *same* path but under a *different* password:

```bash
curl -c cookies2.txt -d 'username=alice&password=pass2' http://127.0.0.1:5000/_/login
curl -b cookies2.txt -X PUT -H "Content-Type: image/jpeg" --data-binary @cat2.jpg http://127.0.0.1:5000/img/cat.jpg
```

Now, fetching `/img/cat.jpg` with the `pass1` session will return `cat1.jpg` and fetching it with the `pass2` session will return `cat2.jpg` — same URL, different content.

---

## Running with Docker (HTTPS via mitmproxy)

The Docker image in this repo runs the Flask app behind **mitmproxy** which generates a local CA and serves HTTPS (reverse proxy) on port `8443`. The container's `start.sh` seeds two blobs on first run:

* `/` — a small HTML page explaining installation of the CA
* `/encrypted-blob-server-ca-cert.pem` — the mitmproxy CA PEM

Both of these are uploaded into the server under the special password `setup`.

**Run the container**

```bash
mkdir -p ~/encblob-mitm
docker build -t encblob:mitm .
docker run --rm -it -v ~/encblob-mitm:/root/.mitmproxy -p 8443:8443 --name encblob-dev encblob:mitm
```

**Install the CA into your browser**

Once the container has generated the CA, the file will be available on the host at `~/encblob-mitm/mitmproxy-ca-cert.pem`.

* For **Firefox**: Preferences → Privacy & Security → View Certificates → Authorities → Import → choose `mitmproxy-ca-cert.pem` and trust it for website identification.
* For **Chrome on macOS**: open Keychain Access → Import the PEM → find the cert → set "Always Trust" for SSL → restart Chrome.

You can also download the CA from the server (it's stored as a normal blob) after logging in with the `setup` password:

```bash
curl -c cookies.txt -d 'username=setup&password=setup' http://127.0.0.1:5000/_/login
curl -b cookies.txt --cacert ~/encblob-mitm/mitmproxy-ca-cert.pem https://localhost:8443/encrypted-blob-server-ca-cert.pem -o mitmproxy-ca-cert.pem
```

**Open the setup page in your browser**

After installing the CA into your browser trust store, you can open:

```
https://localhost:8443/_/login
```

and log in with username `setup` and password `setup` to access the setup page.

> Security reminder: only install the generated development CA on machines you control. Remove it when you're done.

---

## Example: Upload an HTML page and two different cat images (same path, different passwords)

This demonstrates the password-scoped nature of the store.

1. **Generate or download example images**

You can use an image placeholder service or grab local images. Example using `placekitten.com` (or replace with your own images):

```bash
curl -o cat1.jpg https://cataas.com/cat
curl -o cat2.jpg https://cataas.com/cat
```

2. **Upload cat1.jpg under password `pass1`**

```bash
curl -c cookies1.txt -d 'username=alice&password=pass1' http://127.0.0.1:5000/_/login
curl -b cookies1.txt -X PUT -H "Content-Type: image/jpeg" --data-binary @cat1.jpg http://127.0.0.1:5000/img/cat.jpg
```

3. **Upload cat2.jpg under password `pass2`**

```bash
curl -c cookies2.txt -d 'username=alice&password=pass2' http://127.0.0.1:5000/_/login
curl -b cookies2.txt -X PUT -H "Content-Type: image/jpeg" --data-binary @cat2.jpg http://127.0.0.1:5000/img/cat.jpg
```

4. **Fetch with `pass1` and `pass2` to confirm different content**

```bash
curl -b cookies1.txt http://127.0.0.1:5000/img/cat.jpg -o seen-by-pass1.jpg
curl -b cookies2.txt http://127.0.0.1:5000/img/cat.jpg -o seen-by-pass2.jpg
# compare file sizes or visually open them
ls -l seen-by-pass1.jpg seen-by-pass2.jpg
```

If you run the same steps against the Docker HTTPS server, use `https://localhost:8443/` and `--cacert ~/encblob-mitm/mitmproxy-ca-cert.pem` for curl verification.

5. ** Delete **

```bash
curl -b cookies.txt -X DELETE http://localhost:5000/videos/my-video.mp4
```

---

## Notes & operational tips

* **Persistence**: mount a host dir for the mitmproxy CA: `-v ~/encblob-mitm:/root/.mitmproxy` and optionally mount a host dir for the SQLite DB if you want data to survive container recreation.
* **Cache behaviour**: the server caches decrypted blobs in an LRU cache to speed repeated reads. The cache is cleared globally on writes.
* **Large files**: the server decrypts the entire blob and then slices ranges. This is simple and works for typical media sizes — if you need streaming multi-GB files you should switch to chunked storage.
* **Production**: don't use mitmproxy or generated CAs in production. Use a proper TLS certificate from a trusted CA or an internal PKI you control.

---

## Contributing

Patches and improvements welcome. If you make changes, please include tests for any crypto or storage changes — accidental incompatibilities will make old blobs undecryptable.

If you choose to use a LLM to help code, please consider configuring it to generate code in a simiilar style, focused on clarity and auditability.  I find this prompt to work well.

```
We're working on a small Python server project. Please write in a style optimised for clarity, auditability, and simplicity — the kind of code a security-conscious reader should be able to understand in one sitting. Specific guidance:
- Functions over classes when there's no genuine persistent state to encapsulate. Free functions with explicit parameters are easier to audit than methods with implicit self.
- Flat over nested. Avoid deep call hierarchies. A reader should be able to trace a request path without jumping through many layers of abstraction.
- Comments explain why, not what. Don't restate the code. Do comment on non-obvious security decisions, subtle invariants, and anything a future reader might be tempted to "fix" incorrectly.
- Short functions are good; trivial wrapper functions are not. A two-line function is fine if it has a meaningful name. A one-line function that just renames another function adds noise.
- Inline HTML and CSS in a single file rather than templates or asset files, for a project this size. Minify CSS. Keep JavaScript minimal and inline.
- No unnecessary abstraction. Don't create a class, module, or layer of indirection in anticipation of future needs. Write for the current requirements.
- Prefer the standard library. Reach for a third-party library only when it provides something cryptographically necessary or genuinely hard to replicate correctly.
- Line count is a proxy for audit burden. Prefer fewer lines. When two approaches are otherwise equal, choose the shorter one.
- When uncertain between simple-and-slightly-wrong vs complex-and-correct, flag the tradeoff explicitly rather than silently choosing complexity.
Before suggesting a major architectural direction, think out loud about the tradeoffs. Prefer to brainstorm before writing code when the design is still open.
```


---

## Contact

If you fork or maintain your own version of this, please update the README and license block to reflect your changes.

Enjoy!



# encrypted-blob-storage

Encrypted file storage where **possession of credentials is not sufficient to enumerate stored files**.

Each blob requires both valid credentials *and* knowledge of its exact path to retrieve. Blobs not listed in the index are cryptographically indistinguishable from non-existent paths — even to an authenticated user, even to the server operator, even to someone with a full copy of the database.

This provides per-blob plausible deniability: a property that, to our knowledge, no prior self-hostable storage system has offered at this granularity.

---

## The core idea

Most encrypted storage systems have a single threshold: get the password, get everything. Decrypt the volume and all its contents are visible.

This system has two independent thresholds:

1. **Credentials** — username + password, used to derive the encryption key
2. **Path** — the exact URL of the blob

Neither alone is sufficient. A user who knows only the credentials can retrieve only the blobs whose paths they already know. Blobs removed from the index become unlocatable to anyone without foreknowledge of their path — including people holding the credentials under coercion.

**How it works cryptographically:**

At login, username+password are combined through PBKDF2-SHA256 (100,000 rounds) to derive a 32-byte session token. All encryption keys and path identifiers are derived from this token.

Each blob is encrypted with ChaCha20-Poly1305. The path hash — a SHA-256 of the path and encryption key — is passed as AEAD additional authenticated data (AAD). This cryptographically binds each ciphertext to its path:

- Presenting the wrong path during decryption produces an authentication failure, indistinguishable from "blob does not exist"
- The database cannot be rearranged to move or expose blobs, even by someone with full DB access
- Database rows are opaque: path hashes are one-way, so rows cannot be grouped by namespace or linked to credentials without already knowing those credentials

Additionally, each write has a ~1% chance of inserting a row of random noise bytes into the database, structured identically to real rows. This means row count leaks nothing — an observer with a DB copy cannot determine how many real blobs exist, how many namespaces exist, or whether any given row is real or noise.

**The result:** even under full credential disclosure (keylogger, coercion, legal compulsion), an adversary cannot enumerate blobs whose paths they do not already know.

---

## Prior art

This property has not, to our knowledge, been achieved by any prior self-hostable system at the per-blob level.

**Volume-level deniability (VeraCrypt, TrueCrypt, Shufflecake, Rubberhose):** these tools allow a user to maintain a hidden encrypted volume inside a visible one. The outer volume contains plausible decoy content; the inner volume is only accessible with a second password. Once either volume is unlocked, all its contents are visible. Deniability is at the container level, not the file level. Shufflecake (2022) is the most recent serious academic work in this space and describes itself as a spiritual successor to TrueCrypt — but it too operates at the filesystem/volume level.

**Cryptee Ghost Folders:** Cryptee, a commercial end-to-end encrypted document storage service, offers "Ghost Folders" — folders hidden from the listing that can only be found if you know their exact name. This is the closest prior analogue to the property described here. However: Cryptee is a closed-source cloud service; the path hash security depends on implementation details not publicly auditable; and the ghost folder names are hashed against a user identifier that may be more guessable than a full PBKDF2-derived key. In this system, brute-forcing a hidden path requires simultaneously guessing both the path *and* the full credentials, since the path hash is `SHA256(path + enc_key)` where `enc_key` is a 32-byte PBKDF2 secret.

**ORAM (Oblivious RAM):** academic work on oblivious storage goes further, hiding even access patterns from the server. This system makes no such claim — the server operator can observe which path hashes are accessed and when. ORAM schemes are also significantly more complex and slower.

**What appears to be novel here:**

- Per-blob deniability (not per-volume, not per-folder)
- Enforced within an authenticated session — the adversary can be fully logged in
- Cryptographically enforced via AAD binding, not merely UI-level omission from a listing
- No decoy content required — the indexed files naturally serve as the visible layer
- Self-hostable, auditable, ~500 lines

---

## Quickstart

```bash
pip install flask cryptography
python server.py
```

Open `http://localhost:5000/_/admin` and log in with any username and password. A new namespace is created automatically on first login.

### curl

```bash
# Login and save session cookie
curl -c cookies.txt -d 'username=alice&password=secret' \
     http://localhost:5000/_/login

# Upload a file (appears in index)
curl -b cookies.txt -X PUT --data-binary @photo.jpg \
     -H 'Content-Type: image/jpeg' \
     http://localhost:5000/photos/photo.jpg

# Upload a file at an unguessable path (will not appear in index by default)
UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
curl -b cookies.txt -X PUT --data-binary @diary.txt \
     -H 'Content-Type: text/plain' \
     http://localhost:5000/$UUID/diary.txt
# Store $UUID somewhere safe — losing it means losing the file

# Download
curl -b cookies.txt http://localhost:5000/photos/photo.jpg -o photo.jpg

# Delete (empty body)
curl -b cookies.txt -X PUT --data-binary '' \
     http://localhost:5000/photos/photo.jpg
```

---

## Using per-blob deniability

Any blob can be hidden from the index without being deleted. After hiding, it remains accessible at its URL to anyone with credentials, but is undetectable to anyone who does not know its path.

```python
import requests, json

s = requests.Session()
s.post("http://localhost:5000/_/login",
       data={"username": "alice", "password": "secret"})

# Remove a file from the index without deleting it
idx = s.get("http://localhost:5000/_/index").json()
idx["files"].pop("private/diary.txt", None)
s.put("http://localhost:5000/_/index",
      data=json.dumps(idx).encode(),
      headers={"Content-Type": "application/json"})

# The blob still exists and is retrievable:
r = s.get("http://localhost:5000/private/diary.txt")   # 200 OK
# But is undetectable without knowing the path:
idx = s.get("http://localhost:5000/_/index").json()    # no mention of diary.txt
```

**For strongest protection, use unguessable paths.** If a path is guessable (`secret.txt`, `diary.txt`), an authenticated adversary can retrieve it by trying paths directly. Unguessable paths make the path itself a second factor:

```bash
# Generate an unguessable path
python3 -c "import uuid; print(uuid.uuid4())"
# e.g. 7f3a9c2e-1b4d-4e8a-9f0c-2d5e7a8b3c1f
```

Store the UUID in a password manager alongside the credentials. The blob is then protected by two independent secrets.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `BLOB_SALT` | *(insecure default)* | Salts all PBKDF2 key derivations. **Set this in production.** Two deployments sharing a salt and the same credentials produce the same encryption keys. |
| `BLOB_INVITE_TOKEN` | *(unset)* | If set, new namespaces require this token at first login. Existing namespaces are unaffected. |

```bash
export BLOB_SALT="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export BLOB_INVITE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
python server.py
```

The server prints a warning at startup if `BLOB_SALT` is not set.

---

## Write locking

A namespace can be locked to prevent writes. When locked, all PUT requests are rejected with 403. To unlock, the write password must be provided at `/_/admin` — this removes the lock blob, making the namespace writable again. There is no "temporarily unlocked" session state: locked means locked until the lock is explicitly removed.

The lock blob stores a random secret and an HMAC proof derived from the write password. The write password itself is never stored.

**Workflow for a read-mostly namespace:**

1. Upload your files
2. Visit `/_/admin`, set a write password, lock the namespace
3. Share credentials freely — readers can access all blobs by URL
4. To update: visit `/_/admin`, remove the lock, make changes, re-lock

---

## Production deployment

1. **Set `BLOB_SALT`** to a unique secret (see above)
2. **Use HTTPS.** The session cookie is the encryption key. Set `secure=True` on the cookie in `server.py` once HTTPS is in place. See the Docker/mitmproxy setup for a self-contained HTTPS option
3. **Use a production WSGI server:**
   ```bash
   gunicorn -w 1 -b 0.0.0.0:5000 server:app
   ```
   Use `-w 1` (single worker) unless you add a threading lock around SQLite. Multiple workers have independent caches, which is safe but wasteful
4. **Set `BLOB_INVITE_TOKEN`** to prevent arbitrary namespace creation
5. **Back up `blobs.sqlite3`** — it is the only file that matters. Losing it means losing all data permanently (no recovery without both the database and the credentials)

---

## Threat model

**What this protects against:**

- An attacker with a copy of the database learns nothing about contents, paths, number of namespaces, or number of blobs (noise rows make even row counts uninformative)
- The server operator cannot read stored data or determine which credentials map to which namespace
- Two users with different credentials have cryptographically isolated namespaces even if they choose the same paths
- An attacker with valid credentials cannot enumerate blobs whose paths they do not already know
- An attacker with valid credentials and DB access cannot move or swap blob ciphertexts (AAD binding)
- Credential disclosure (keylogger, coercion) does not expose off-index blobs whose paths are unknown to the attacker

**What this does not protect against:**

- An attacker with the session cookie has full read access to that namespace (and write access if unlocked). The cookie is the encryption key — treat it accordingly
- The server operator can observe access patterns: which path hashes are requested, response sizes, and timing. Path hashes are not reversible, but frequency analysis on a small namespace may be informative
- If a path is guessable, an authenticated attacker can retrieve the blob by trying paths. Use unguessable paths for sensitive material
- A malicious server operator who modifies the server code
- Blob sizes are not padded — encrypted sizes are visible in the DB
- PBKDF2 at 100,000 rounds provides moderate resistance to offline password guessing. Weak passwords remain weak
- **HTTPS is required in production.** Without it the session cookie is transmitted in plaintext

---

## Notes on design

The index (`_/index`) is advisory, not authoritative. The index can be overwritten directly with a `PUT` to `/_/index` to curate what appears in the listing. Blobs not in the index remain fully accessible by URL.

The blob cache holds up to 64 decrypted blobs in memory, keyed by path hash. This is primarily useful for video and audio served with HTTP Range requests. The cache is cleared on every write and does not persist across restarts.

**Database schema:** the path-hash-as-AAD binding introduced in v1.0 is a breaking change from earlier versions. Blobs written by pre-v1.0 instances cannot be decrypted by v1.0. Use `encrypted-blob-migrate` to copy blobs from an old instance to a new one before upgrading.

---

## ⚖️ License — likely no traditional license or copyright applies

This project was created almost entirely by a handful of large language models, with the primary implementation and architectural work done by [Claude](https://claude.ai) (Anthropic).

The human contribution was minimal and mostly evaluative: initiating the idea, requesting iterations, and describing qualitative behavior of the software.

As a result, there may be **no copyright ownership** in the traditional legal sense — most jurisdictions require meaningful human authorship to grant copyright.

Accordingly:

- ⚠️ No copyright is claimed.
- ✅ To the fullest extent allowed by law, this work is **dedicated to the public domain**.
- 🌍 Where a legal dedication is required, this repository is released under [CC0 1.0 Universal (Public Domain Dedication)](https://creativecommons.org/publicdomain/zero/1.0/).

You are free to **use, modify, copy, and redistribute** this project for any purpose, without restriction.