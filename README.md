# Encrypted Blob Server

A tiny, minimal HTTP server that stores **encrypted blobs** in SQLite and decrypts them on the fly.

**Main benefits**

* **Encrypted storage** — no password or global key is stored server-side. Blobs are encrypted using a key derived from the password supplied by the client. If disk is stolen, data at rest remains encrypted.
* **Password‑scoped content** — the same URL path can map to different decrypted content for different passwords. This lets multiple users share the same URLs but see different content (or lets a single user host multiple sites from the same server by switching passwords).
* **No complex signup** — the password itself is the namespace: set the password via the `/_/login` endpoint and the server uses that to encrypt/decrypt.

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
curl -o cat1.jpg https://placekitten.com/800/600
curl -o cat2.jpg https://placekitten.com/801/600
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

---

## Notes & operational tips

* **Persistence**: mount a host dir for the mitmproxy CA: `-v ~/encblob-mitm:/root/.mitmproxy` and optionally mount a host dir for the SQLite DB if you want data to survive container recreation.
* **Cache behaviour**: the server caches decrypted blobs in an LRU cache to speed repeated reads. The cache is cleared globally on writes.
* **Large files**: the server decrypts the entire blob and then slices ranges. This is simple and works for typical media sizes — if you need streaming multi-GB files you should switch to chunked storage.
* **Production**: don't use mitmproxy or generated CAs in production. Use a proper TLS certificate from a trusted CA or an internal PKI you control.

---

## Contributing

Patches and improvements welcome. If you make changes, please include tests for any crypto or storage changes — accidental incompatibilities will make old blobs undecryptable.

---

## Contact

If you fork or maintain your own version of this, please update the README and license block to reflect your changes.

Enjoy!

