# Encrypted Blob Server

A tiny, minimal HTTP server providing encrypted file storage with unusually strong privacy properties, where **possession of credentials is not sufficient to enumerate stored files**.

Each blob requires both valid credentials *and* knowledge of its exact path to retrieve. Blobs not listed in the index are cryptographically indistinguishable from non-existent paths — even to an authenticated user, even to the server operator, even to someone with a full copy of the database.
This provides per-blob plausible deniability: a property that, to our knowledge, no prior self-hostable storage system has offered at this granularity.

**Main benefits**

* **No persisted server-side secrets, including usernames or passwords or encryption keys** — All encrypted blobs look the same to the server admin - and they are unable to tell what accounts exists, how many accounts exist, or what blobs belong to what accounts.
* **Per-blob plausible deniability** — Even rubber-hose cryptanalysis that gives an attacker the complete database and every single username/password will not enable them to enumerate which blobs belong to which user. Each blob requires both valid credentials *and* knowledge of its exact path to retrieve. The database rows are opaque without the key derived from the complete (username,password,path) combination, and keys are never stored. Blobs are cryptographically indistinguishable from randomly inserted non-existent paths — even to an authenticated user, even to the server operator, even to someone with a full copy of the database.  This provides per-blob plausible deniability: a property that, to our knowledge, no prior self-hostable storage system has offered at this granularity.
* **The server admin cannot determine what accounts exist** — usernames and passwords are never stored anywhere, not even encrypted.  A malicious operator who modifies the running code going forward still cannot retroactively decrypt previously stored blobs, because keys were never stored.
* **Credentials alone are not sufficient to decrypt stored files** — an attacker needs both valid credentials *and* the exact path of each blob.   Even if a hacker or server admin has the database and all user's username and password, they will not be able to decript, or even be aware of, blobs that were created before their hack, unless they observe an authorized user access the blob later.
* **The server admin cannot determine which blobs belong to which account** — all rows in the database are cryptographically indistinguishable even to someone who holds credentials for every account on the server and knows every path those accounts have ever used — and even then, noise rows mean they still cannot be certain they have found everything
* **Encrypted storage** — blobs are encrypted with ChaCha20-Poly1305 using a key derived from username and password. If the database is stolen, data at rest remains encrypted and unreadable.
* **Password‑scoped namespaces** — the same URL serves different content to different credentials. /img/cat.jpg decrypts to a completely different file for alice:pass1 and alice:pass2, with no way to correlate them.  If two users want "username: john", that's fine as long as they're using strong passwords (but of course if they both pick password: 12345 their accounts/hashes will have collisions).
* **No complex signup** — the username/password itself is the namespace.  If you log in with a new username/password you get a new namespace. Password change is handled by migrating accounts.

---

## Quickstart


### Running dev mode locally

```bash
pip install git+https://github.com/ramayer/encrypted-blob-server@v0.9.0-rc1
encrypted-blob-server
```

Visit http://localhost:5000/_/admin, log in with any username and password, and start uploading. Visiting any URL that has no content gives you an inline form to upload to that exact path. Visiting it again retrieves the content.

For HTTPS, see Running with Docker.


### Curl/Scripted Usage Example

**Generate or downnload some example images**

You can use an image placeholder service or grab local images:

```bash
curl -o cat1.jpg https://cataas.com/cat
curl -o cat2.jpg https://cataas.com/cat
```

**Upload cat1.jpg under password `pass1`**

```bash
curl -c cookies1.txt -d 'username=alice&password=pass1' http://127.0.0.1:5000/_/login
curl -b cookies1.txt -X PUT -H "Content-Type: image/jpeg" --data-binary @cat1.jpg http://127.0.0.1:5000/img/cat.jpg
```

**Upload cat2.jpg under password `pass2`**

```bash
curl -c cookies2.txt -d 'username=alice&password=pass2' http://127.0.0.1:5000/_/login
curl -b cookies2.txt -X PUT -H "Content-Type: image/jpeg" --data-binary @cat2.jpg http://127.0.0.1:5000/img/cat.jpg
```

**Fetch with `pass1` and `pass2` to confirm different content**

```bash
curl -b cookies1.txt http://127.0.0.1:5000/img/cat.jpg -o seen-by-pass1.jpg
curl -b cookies2.txt http://127.0.0.1:5000/img/cat.jpg -o seen-by-pass2.jpg
# compare file sizes or visually open them
ls -l seen-by-pass1.jpg seen-by-pass2.jpg
```



## Running with Docker (HTTPS via mitmproxy)
## Running with Docker (HTTPS via mitmproxy)

The Docker image runs the server behind mitmproxy, which generates a local CA and serves HTTPS on port 5443. On first run it seeds a `setup/setup` namespace with the CA certificate and browser installation instructions.

```bash
# Build directly from GitHub — no local directory needed
docker buildx build \
  "https://github.com/ramayer/encrypted-blob-server.git#main" \
  -t encrypted-blob-server

# Run with persistent storage
docker run --rm -it \
  -v /tmp/ebs-certs:/root/.mitmproxy \
  -v /tmp/ebs-data:/data \
  -p 5443:5443 \
  --name ebs \
  encrypted-blob-server:latest
```

Then visit `https://localhost:5443/` and log in with username `setup`, password `setup` for certificate installation instructions. Once you've trusted the CA in your browser, log in with any other credentials to create your own namespace.

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `SERVER_HOSTNAME` | `localhost` | Hostname shown in setup instructions |
| `SERVER_PORT` | `5443` | Port shown in setup instructions |
| `BLOB_SALT` | *(insecure default)* | Set this in production — see [Configuration](#configuration) |
| `BLOB_DB_PATH` | `/data/blobs.sqlite3` | Path to the SQLite database |

> The mitmproxy CA is a self-signed development certificate. Only install it on machines you control, and remove it when done.

# Encrypted Blob Storage — Security

Encrypted Blob Storage is built around the principles of **breach resilience** and **graceful degradation of security**. The system is architected so that breaches — of the database, of server secrets, of usernames and passwords, even of several of these simultaneously — each reveal as little as possible.  The **minimal trust surface** means no account records, usernames, or keys are ever stored server-side. The result is **partial compromise security** with genuine **defense in depth**: no realistic subset of leaked components is sufficient to decrypt stored data or even confirm that any particular account exists.   Security degrades gracefully even under partial compromise.

---

## Security Properties

- **No server-side account records.** Usernames, passwords, and encryption keys are never stored anywhere on the server. There is nothing to steal, subpoena, or leak.

- **No account enumeration, even with full database access.** Every stored record is identified only by a keyed hash. Without credentials, an attacker with a complete database backup cannot determine how many accounts exist, who they belong to, or whether any particular account exists at all.

- **Credentials alone are not sufficient to locate blobs.** Each blob's database key is derived from a combination of the encryption key *and* the file path. Even knowing a valid username and password, an attacker cannot retrieve any blob without also knowing its exact path. There is no way to enumerate files without an explicitly opted-in index.

- **Different passwords mean completely separate namespaces.** `alice:password1` and `alice:password2` produce cryptographically unrelated keys and unrelated storage namespaces. Knowing a username leaks nothing about any account's contents.

- **Ciphertexts are bound to their location.** Each blob is authenticated against its own path hash (AEAD additional data). A database-level attacker cannot rearrange, transplant, or swap blobs between accounts or paths — doing so causes authentication failure on decryption.

- **Database theft is not sufficient for decryption.** Blobs are encrypted with a key derived from credentials *and* a server-side salt (`BLOB_SALT`). A stolen database without the salt is undecryptable. A stolen salt without the database is useless.

- **Retroactive keylogging is impossible.** A malicious operator who modifies the server to log future credentials learns nothing about data stored before the hack. Past ciphertexts can only be decrypted by someone who knew the credentials at the time of storage.

- **Session cookies expire and are tamper-proof.** The session cookie is HMAC-signed with a key derived from `BLOB_SALT` and carries an embedded expiry timestamp. A stolen cookie becomes useless after expiry, and cannot be forged or extended without the server secret.

- **Noise rows resist traffic analysis.** Approximately 1% of writes insert indistinguishable random rows into the database, sized by sampling real rows. This prevents an attacker from inferring account activity or file counts from database size or row distribution.

- **Write-locking is cryptographically enforced.** A locked namespace requires a separate write password to unlock. The lock proof is stored encrypted; there is no server-side bypass.

---

## How the Security Elements Work Together

The system's resilience comes not from any single mechanism but from the way several layers compose.

**Key derivation** is the foundation. When a user logs in, their username and password are fed into Argon2id (with a server-side salt) to produce a 32-byte token. This token never touches the database — it lives only in the session cookie and in memory during a request. The encryption key is then derived from this token via a second SHA-256 pass, further separating the session credential from the storage credential.

**Path-scoped storage** is the most unusual property. Rather than storing blobs under a user ID, each blob is stored under `SHA256(path + ":" + encryption_key)`. This means the database contains no user identifiers at all — not even pseudonymous ones. Two consequences follow: first, there is no way to group records by account without the key; second, even a valid key is insufficient to find blobs without also knowing their paths. The file index (a blob at the reserved path `_/index`) is opt-in precisely because creating it trades this path-secrecy property for convenience.

**AEAD binding** closes a subtle gap. Each blob's ciphertext is authenticated with its own path hash as additional data. This means a ciphertext cannot be moved to a different row in the database and successfully decrypted — the authentication tag will fail. An attacker with full read/write database access cannot reassign blobs between accounts or paths, even without knowing the key.

**The two-component decryption requirement** (database + `BLOB_SALT`) means that stealing either component alone yields nothing. The database is uninterpretable without the salt; the salt is useless without the database. This is structurally similar to two-factor possession, applied to the storage layer rather than authentication.

**Cookie signing** adds a time-bound layer over the derived key. The cookie contains the token, an expiry timestamp, and an HMAC over both, keyed by a derivative of `BLOB_SALT`. A stolen cookie expires naturally and cannot be extended without the server secret. Notably, this does not change the encryption model at all — it is a wrapper that addresses the distinct threat of cookie theft without introducing server-side session state.

Together, these properties mean that an attacker must simultaneously possess the database, the server salt, valid credentials, *and* knowledge of at least one file path to decrypt even a single blob. No subset of these is sufficient.

---

## Threat Model

The table below assumes an attacker has obtained the components listed and asks what remains protected.

| Attacker possesses | Can decrypt blobs? | Can enumerate accounts? | Can enumerate file paths? | Notes |
|---|---|---|---|---|
| Database only | ✅ No | ✅ No | ✅ No | All records are opaque without `BLOB_SALT` |
| `BLOB_SALT` only | ✅ No | ✅ No | ✅ No | No database, nothing to decrypt |
| Database + `BLOB_SALT` | ✅ No | ✅ No | ✅ No | Still need credentials to derive keys |
| Database + all usernames | ✅ No | ✅ No | ✅ No | Username alone doesn't determine key; password required |
| Database + all username/password pairs | ✅ No | ⚠️ Partial | ✅ No | Can attempt decryption per account, but still need paths to locate blobs; index-enabled accounts expose paths |
| Database + `BLOB_SALT` + all username/password pairs | ⚠️ Partial | ✅ Yes | ⚠️ Partial | Can decrypt blobs only if paths are also known; path enumeration still requires index or prior knowledge |
| Database + `BLOB_SALT` + credentials + all file paths | ❌ Yes | ❌ Yes | ❌ Yes | Full compromise; no further protection |
| Expired session cookie only | ✅ No | ✅ No | ✅ No | Cookie is signed and time-limited; rejected by server after expiry |
| Valid session cookie (within expiry) | ❌ Yes (live server) | ❌ Yes (live server) | ⚠️ Only if index enabled | Can access server normally; offline decryption still requires `BLOB_SALT` |
| Valid session cookie + database (no `BLOB_SALT`) | ✅ No | ✅ No | ✅ No | `BLOB_SALT` required to map cookie token to encryption key |
| Future server keylog (credentials going forward) | ⚠️ Future only | ⚠️ Future only | ⚠️ Future only | Past data inaccessible; retroactive compromise impossible |
| Web server access logs (URLs + timestamps) | ✅ No | ✅ No | ⚠️ Partial | URLs visible in logs; contents and account associations still protected. **Disable access logging in production.** |

### Key to symbols
- ✅ **Protected** — the attacker cannot achieve this goal with the listed components
- ⚠️ **Partial** — some information may be inferred under specific conditions (noted)
- ❌ **Compromised** — the attacker can achieve this goal


### Additional nodes from Claude:

> A few notes on choices made:
>
>The term I landed on in the intro is "security degrades gracefully under partial compromise" — I think that phrase is clear to a non-academic reader and accurately describes the system's standout property. If you want a single memorable term for the bullet list or a tagline, "breach-resilient" is the most concise accurate label.
>
>The threat table has one row you might want to revisit: "Database + BLOB_SALT + all username/password pairs" is marked partial for decryption because paths are still needed. That's the system's most unusual property and arguably the one most worth highlighting to sophisticated users.

### Important caveats

**The file index trades security for convenience.** Users who opt in to the index at `_/index` expose their full list of file paths to anyone with their credentials. For maximum security, do not enable the index, and access files by direct URL only.

**Web server access logs are outside this system's control.** By default, reverse proxies (nginx, caddy) and application servers (gunicorn) log request URLs, timestamps, and IP addresses. These logs can associate IPs with file paths and login events. For strong operational security, disable access logging or ensure logs are not retained.

**Password strength is the weakest link.** The entire model depends on credentials being unguessable. Argon2id makes brute-force expensive but not impossible against weak passwords. Use strong, unique passwords.

**`BLOB_SALT` must be kept secret.** It is the server's only secret. If it is lost, all data becomes permanently inaccessible. If it is stolen alongside the database, the attacker's work reduces to credential and URL guessing. Store it securely (environment variable, secrets manager) and back it up offline.

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

**How it works cryptographically:**

At login, username+password are combined through PBKDF2-SHA256 (100,000 rounds) to derive a 32-byte session token. All encryption keys and path identifiers are derived from this token.

Each blob is encrypted with ChaCha20-Poly1305. The path hash — a SHA-256 of the path and encryption key — is passed as AEAD additional authenticated data (AAD). This cryptographically binds each ciphertext to its path:

- Presenting the wrong path during decryption produces an authentication failure, indistinguishable from "blob does not exist"
- The database cannot be rearranged to move or expose blobs, even by someone with full DB access
- Database rows are opaque: path hashes are one-way, so rows cannot be grouped by namespace or linked to credentials without already knowing those credentials

Additionally, each write has a ~1% chance of inserting a row of random noise bytes into the database, structured identically to real rows. This means row count leaks nothing — an observer with a DB copy cannot determine how many real blobs exist, how many namespaces exist, or whether any given row is real or noise.

**The result:** even under full credential disclosure (keylogger, coercion, legal compulsion), an adversary cannot enumerate blobs whose paths they do not already know.


## Prior art

Most encrypted storage systems have a single threshold: get the password, get everything. Decrypt the volume and all its contents are visible.

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

### Additional Features

## Write locking

A namespace can be locked to prevent writes. When locked, all PUT requests are rejected with 403. To unlock, the write password must be provided at `/_/admin` — this removes the lock blob, making the namespace writable again. There is no "temporarily unlocked" session state: locked means locked until the lock is explicitly removed.

The lock blob stores a random secret and an HMAC proof derived from the write password. The write password itself is never stored.

**Workflow for a read-mostly namespace:**

1. Upload your files
2. Visit `/_/admin`, set a write password, lock the namespace
3. Share credentials freely — readers can access all blobs by URL
4. To update: visit `/_/admin`, remove the lock, make changes, re-lock

## Index generation

For namespaces that care less about security, it can be inconvenient that a forgotten URL results in a blob that is lost/orphaned forever.  For such less secure namespaces, a user can upload an empty json file (`{}`) to `/_/index` and the server will start adding newly inserted blobs for that namespace into the index.  Note that this weakens security because then an admin with a username/password can find all blobs owned by that user.  


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