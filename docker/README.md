# Encrypted Blob Server - Docker Deployments

This directory contains multiple Docker configurations for different deployment scenarios.

## 🎯 Quick Start - Choose Your Setup

### 1. Self-Signed Certificate (Development/Local)
**Best for:** Local development, testing, internal networks

Uses mitmproxy to generate self-signed certificates with automatic bootstrapping.

```bash
cd docker
docker-compose up -d
```

Access at `https://localhost:5443/` with username: `setup`, password: `setup` to download and install the CA certificate.

📖 **[Full documentation below](#option-1-self-signed-with-mitmproxy)**

---

### 2. Let's Encrypt (Production)
**Best for:** Public servers with a domain name

Automatically obtains and renews real SSL certificates from Let's Encrypt.

```bash
cd docker
# Edit docker-compose.letsencrypt.yml to set your domain and email
docker-compose -f docker-compose.letsencrypt.yml up -d
```

⚠️ **Requirements:**
- Public domain pointing to your server
- Ports 80 and 443 accessible from internet

📖 **[Full documentation below](#option-2-lets-encrypt-production)**

---

### 3. Custom Certificate (Enterprise)
**Best for:** Corporate environments with existing PKI

Bring your own certificate and private key.

```bash
cd docker
mkdir certs
# Copy your cert.pem and key.pem to certs/
docker-compose -f docker-compose.custom-cert.yml up -d
```

📖 **[Full documentation below](#option-3-custom-certificates)**

---

## Option 1: Self-Signed with mitmproxy

### Setup

1. **Start the server:**
   ```bash
   cd docker
   docker-compose up -d
   ```

2. **Access the setup page** (your browser will show a security warning - this is expected):
   ```
   https://localhost:5443/
   ```
   
   Login with:
   - Username: `setup`
   - Password: `setup`

3. **Download and install the CA certificate** following the detailed instructions on the setup page

4. **Restart your browser** and access `https://localhost:5443/_/login` - no more warnings!

5. **Create your own account** with a unique username/password

### Custom Hostname

To access from other machines on your network:

Edit `docker-compose.yml`:
```yaml
environment:
  - SERVER_HOSTNAME=blob-server.local
  - SERVER_PORT=5443
```

Add to `/etc/hosts` on client machines:
```
192.168.1.100  blob-server.local
```

Rebuild:
```bash
docker-compose down
docker-compose up -d
```

### Files
- `Dockerfile` - Main build configuration
- `docker-compose.yml` - Orchestration for self-signed setup
- `../encrypted_blob_server/docker_entrypoint.py` - HTTPS wrapper with mitmproxy

---

## Option 2: Let's Encrypt (Production)

### Prerequisites

1. **Public domain** pointing to your server's IP
2. **Ports 80 and 443** open and accessible from the internet
3. **Email address** for Let's Encrypt notifications

### Setup

1. **Configure your domain and email:**

   Edit `docker-compose.letsencrypt.yml`:
   ```yaml
   environment:
     - CERTBOT_DOMAIN=yourdomain.com
     - CERTBOT_EMAIL=you@example.com
   ```

2. **Start the server:**
   ```bash
   cd docker
   docker-compose -f docker-compose.letsencrypt.yml up -d
   ```

3. **Certificate acquisition:**
   - On first run, certbot will obtain a certificate (takes ~30 seconds)
   - Let's Encrypt will verify your domain via HTTP-01 challenge on port 80
   - Certificate is automatically stored in the `letsencrypt` volume

4. **Access your server:**
   ```
   https://yourdomain.com/
   ```
   
   No certificate installation needed - browsers trust Let's Encrypt!

### Automatic Renewal

- Certificates auto-renew via cron job (checks daily)
- Renewal happens ~30 days before expiration
- Server automatically reloads after renewal

### Troubleshooting

**Certificate acquisition fails:**
- Verify your domain DNS points to your server: `nslookup yourdomain.com`
- Ensure port 80 is accessible: `curl http://yourdomain.com`
- Check logs: `docker-compose -f docker-compose.letsencrypt.yml logs`

**Rate limits:**
- Let's Encrypt has rate limits (5 certificates per domain per week)
- Use staging for testing: Add `--staging` flag in `letsencrypt-entrypoint.sh`

### Files
- `Dockerfile.letsencrypt` - Build with certbot
- `docker-compose.letsencrypt.yml` - Let's Encrypt orchestration
- `letsencrypt-entrypoint.sh` - Certificate management script

---

## Option 3: Custom Certificates

### Setup

1. **Prepare your certificates:**
   ```bash
   cd docker
   mkdir certs
   ```

2. **Copy your certificate files:**
   ```bash
   # Your certificate (can be a chain)
   cp /path/to/your/cert.pem certs/
   
   # Your private key
   cp /path/to/your/key.pem certs/
   
   # Ensure correct permissions
   chmod 644 certs/cert.pem
   chmod 600 certs/key.pem
   ```

3. **Start the server:**
   ```bash
   docker-compose -f docker-compose.custom-cert.yml up -d
   ```

4. **Access your server:**
   ```
   https://your-domain.com/
   ```

### Certificate Format

- **cert.pem:** PEM-encoded certificate (or certificate chain)
- **key.pem:** PEM-encoded private key (unencrypted)

To convert from other formats:

```bash
# From .crt and .key
cat cert.crt > certs/cert.pem
cat private.key > certs/key.pem

# From .pfx/.p12
openssl pkcs12 -in cert.pfx -out certs/cert.pem -clcerts -nokeys
openssl pkcs12 -in cert.pfx -out certs/key.pem -nocerts -nodes
```

### Certificate Renewal

When your certificate expires:
1. Replace files in `certs/` directory
2. Restart container: `docker-compose -f docker-compose.custom-cert.yml restart`

### Files
- `Dockerfile.custom-cert` - Build for custom certs
- `docker-compose.custom-cert.yml` - Custom cert orchestration

---

## Persistent Storage

All configurations use Docker volumes for persistence:

- **blob-data:** Database and encrypted blob storage
- **cert-data / letsencrypt / certs:** Certificate storage

### Backup

```bash
# Backup database
docker run --rm -v docker_blob-data:/data -v $(pwd):/backup \
  ubuntu tar czf /backup/blob-backup.tar.gz /data

# Backup certificates (self-signed)
docker run --rm -v docker_cert-data:/certs -v $(pwd):/backup \
  ubuntu tar czf /backup/cert-backup.tar.gz /certs

# Backup Let's Encrypt certs
docker run --rm -v docker_letsencrypt:/letsencrypt -v $(pwd):/backup \
  ubuntu tar czf /backup/letsencrypt-backup.tar.gz /letsencrypt
```

### Restore

```bash
# Restore database
docker run --rm -v docker_blob-data:/data -v $(pwd):/backup \
  ubuntu tar xzf /backup/blob-backup.tar.gz -C /

# Similar for certificates...
```

---

## Building from Source

To use a local development version:

1. Clone the repository
2. Modify docker-compose to use local build:
   ```yaml
   services:
     blob-server:
       build:
         context: ..
         dockerfile: docker/Dockerfile
   ```
3. Run: `docker-compose up --build`

---

## Security Considerations

### Self-Signed Setup
- CA private key stored in Docker volume - keep secure
- "setup/setup" account is public knowledge - only contains certificates
- Create personal accounts with strong passwords

### Let's Encrypt Setup
- Certificate renewal logs may contain your domain/email
- Port 80 must be accessible - consider firewall rules
- Rate limits apply - don't test excessively with production domains

### Custom Certificate Setup
- Protect your private key files (`chmod 600`)
- Use certificate chains if needed (intermediate + root)
- Monitor expiration dates

---

## Common Issues

### Port Already in Use
```bash
# Check what's using the port
sudo lsof -i :443
sudo lsof -i :5443

# Stop conflicting service or change port in docker-compose.yml
```

### Permission Denied on Volumes
```bash
# Fix volume permissions
docker-compose down
sudo chown -R $(id -u):$(id -g) ./certs
docker-compose up -d
```

### Container Won't Start
```bash
# Check logs
docker-compose logs

# Common issues:
# - Missing certificate files (custom cert setup)
# - Invalid domain configuration (Let's Encrypt)
# - Port conflicts
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/ramayer/encrypted-blob-server/issues
- Check container logs: `docker-compose logs -f`

## Quick Start

1. **Build and run the container:**
   ```bash
   docker-compose up -d
   ```

2. **Access the setup page:**
   ```
   https://localhost:5443/
   ```
   
   **Login credentials:**
   - Username: `setup`
   - Password: `setup`

3. **Your browser will show a security warning** - this is expected! Click "Advanced" → "Proceed anyway" (or similar) to access the setup page.

4. **Download the CA certificate** from the setup page and install it in your browser following the detailed instructions provided.

5. **Restart your browser** and access `https://localhost:5443/_/login` - no more warnings!

6. **Create your own account** with a unique username/password for encrypted storage.

## How It Works

The server automatically creates a "setup" account (`username: setup`, `password: setup`) that contains:
- **CA certificate files** (both `.cer` for browsers and `.pem` for command line)
- **Detailed installation instructions** for Chrome, Firefox, Safari, and command-line tools
- **Troubleshooting guide**

Everything is served through the encrypted blob server itself - no need for `docker cp` or shell access!

## Using with a Custom Hostname

If you want to access the server from other machines on your network:

1. Update `docker-compose.yml`:
   ```yaml
   environment:
     - SERVER_HOSTNAME=blob-server.local  # Your hostname
     - SERVER_PORT=5443
   ```

2. Add entry to your `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts` on Windows):
   ```
   192.168.1.100  blob-server.local
   ```

3. Rebuild and restart:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

4. Access at `https://blob-server.local:5443/` and follow the setup instructions

## Command Line Access

```bash
# Download the CA certificate (bypass SSL verification for this one request)
curl -k -u setup:setup https://localhost:5443/ca-cert.pem -o ca-cert.pem

# Now use it for all requests
curl --cacert ca-cert.pem -c cookies.txt -d 'username=myuser&password=mypass' \
  https://localhost:5443/_/login

curl --cacert ca-cert.pem -b cookies.txt -X PUT --data-binary @video.mp4 \
  -H 'Content-Type: video/mp4' \
  https://localhost:5443/videos/movie.mp4
```

## Persistent Storage

- **Database:** Stored in `/data/blobs.sqlite3` (persisted via `blob-data` volume)
- **Certificates:** Stored in `/root/.mitmproxy` (persisted via `cert-data` volume)
- **Setup account data:** Stored in the database under the "setup/setup" namespace

Certificates persist across container restarts, so you only need to trust the CA once.

## Security Notes

- **The "setup" account is public** - anyone who can access your server can login as `setup/setup`
- The setup account only contains CA certificates and instructions - no sensitive data
- **After trusting the certificate, create your own account** with a unique username/password
- Each account gets its own encrypted, isolated storage namespace
- Consider changing the default setup credentials if exposing to the internet (see below)

## Customizing Setup Credentials

To use different credentials for the setup account, modify `docker-entrypoint.py`:

```python
# In bootstrap_setup_account() function, change:
token = CryptoManager.derive_session_token("setup", "setup")

# To:
token = CryptoManager.derive_session_token("admin", "your-secret-password")
```

Then rebuild the container.

## Resetting Everything

```bash
# Stop and remove containers, volumes, and data
docker-compose down -v

# Start fresh
docker-compose up -d
```

This will regenerate new certificates and a fresh database.

## Development

To use a local development version instead of installing from GitHub:

1. Modify `Dockerfile`:
   ```dockerfile
   # Replace the pip install line with:
   COPY . /app/encrypted-blob-server
   RUN pip install --no-cache-dir /app/encrypted-blob-server mitmproxy
   ```

2. Build and run:
   ```bash
   docker-compose up --build
   ```

## Troubleshooting

**Can't access the server at all:**
- Check if container is running: `docker ps`
- Check logs: `docker-compose logs`
- Ensure port 5443 is not already in use

**Browser shows "Your connection is not private" even after installing certificate:**
- Make sure you restarted your browser after importing the certificate
- Verify you imported to "Trusted Root Certification Authorities" (not "Personal")
- Check that the hostname in your URL matches the `SERVER_HOSTNAME` environment variable
- Try clearing browser cache and SSL state

**Certificate appears to be invalid:**
- Check if the hostname matches: Certificate is issued for the exact hostname in `SERVER_HOSTNAME`
- If you changed hostnames, you need to regenerate certificates (reset volumes as shown above)

**Setup page not loading:**
- The setup account is created on first run - restart the container if needed
- Check container logs for bootstrap messages: `docker-compose logs | grep -i bootstrap` `mitmproxy-ca-cert.cer`
   - Check "Trust this CA to identify websites"
   
   **macOS:**
   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain mitmproxy-ca-cert.cer
   ```

4. **Access the server:**
   ```
   https://localhost:5443/_/login
   ```

## Building Without docker-compose

```bash
# Build the image
docker build -t encrypted-blob-server .

# Run the container
docker run -d \
  -p 5443:5443 \
  -v blob-data:/data \
  -v cert-data:/root/.mitmproxy \
  -e SERVER_HOSTNAME=localhost \
  encrypted-blob-server
```

## Using with a Custom Hostname

If you want to access the server from other machines on your network:

1. Update `docker-compose.yml`:
   ```yaml
   environment:
     - SERVER_HOSTNAME=blob-server.local  # Your hostname
   ```

2. Add entry to your `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts` on Windows):
   ```
   192.168.1.100  blob-server.local
   ```

3. Rebuild and restart:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

4. Extract and install the CA certificate (steps above)

5. Access at `https://blob-server.local:5443/_/login`

## Persistent Storage

- **Database:** Stored in `/data/blobs.sqlite3` (persisted via `blob-data` volume)
- **Certificates:** Stored in `/root/.mitmproxy` (persisted via `cert-data` volume)

Certificates persist across container restarts, so you only need to trust the CA once.

## Troubleshooting

**Browser shows "Your connection is not private":**
- Make sure you've imported the CA certificate (`mitmproxy-ca-cert.cer`)
- Restart your browser after importing the certificate
- Check that the certificate hostname matches the URL you're using

**Cannot access from other machines:**
- Ensure `SERVER_HOSTNAME` matches the hostname in your browser's URL
- Check firewall settings allow port 5443
- Verify `/etc/hosts` has the correct IP address

**Resetting certificates:**
```bash
docker-compose down
docker volume rm encrypted-blob-server_cert-data
docker-compose up -d
# Re-extract and re-install the CA certificate
```

## Development

To use a local development version instead of installing from GitHub:

1. Modify `Dockerfile`:
   ```dockerfile
   # Replace the pip install line with:
   COPY . /app/encrypted-blob-server
   RUN pip install --no-cache-dir /app/encrypted-blob-server mitmproxy
   ```

2. Build and run:
   ```bash
   docker-compose up --build
   ```

## Security Notes

- The generated CA is self-signed and only trusted by browsers where you manually import it
- The CA private key is stored in the `cert-data` volume - keep this secure
- In production, consider using proper certificates from Let's Encrypt or similar
- The server uses PBKDF2 with 100,000 iterations for password hashing
- All blob content is encrypted with ChaCha20Poly1305
