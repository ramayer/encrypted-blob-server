#!/bin/bash
set -e

DOMAIN="${CERTBOT_DOMAIN:-localhost}"
EMAIL="${CERTBOT_EMAIL:-admin@example.com}"
CERT_PATH="/etc/letsencrypt/live/$DOMAIN"

echo "=================================="
echo "Let's Encrypt HTTPS Setup"
echo "=================================="
echo "Domain: $DOMAIN"
echo "Email: $EMAIL"
echo ""

# Check if certificate already exists
if [ -d "$CERT_PATH" ]; then
    echo "✓ Certificate already exists for $DOMAIN"
else
    echo "Obtaining certificate for $DOMAIN..."
    
    # Start blob server temporarily on port 80 for ACME challenge
    encrypted-blob-server &
    BLOB_PID=$!
    sleep 2
    
    # Obtain certificate using standalone mode
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --domain "$DOMAIN" \
        --http-01-port 80
    
    # Stop temporary server
    kill $BLOB_PID || true
    wait $BLOB_PID 2>/dev/null || true
    
    echo "✓ Certificate obtained successfully"
fi

# Set up certificate renewal cron job (runs daily)
echo "0 0 * * * certbot renew --quiet --deploy-hook 'killall -HUP python3'" > /etc/cron.d/certbot-renew
chmod 0644 /etc/cron.d/certbot-renew
crontab /etc/cron.d/certbot-renew
cron

echo ""
echo "Starting encrypted blob server with Let's Encrypt certificate..."
echo "Access at: https://$DOMAIN/"
echo ""

# Run the blob server with proper SSL certificates
exec python3 -c "
from encrypted_blob_server import app
import ssl

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(
    '$CERT_PATH/fullchain.pem',
    '$CERT_PATH/privkey.pem'
)

app.run(
    host='0.0.0.0',
    port=443,
    ssl_context=ssl_context,
    debug=False
)
"