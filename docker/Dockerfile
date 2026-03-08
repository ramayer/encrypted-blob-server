FROM python:3.14-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install the encrypted blob server and mitmproxy
RUN pip install --no-cache-dir \
    "git+https://github.com/ramayer/encrypted-blob-server@main" \
    mitmproxy

# Create directory for certificates and database
RUN mkdir -p /root/.mitmproxy /data

# Expose HTTPS port
EXPOSE 5443

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV BLOB_DB_PATH=/data/blobs.sqlite3
ENV SERVER_HOSTNAME=localhost
ENV SERVER_PORT=5443

# Volume for persistent data
VOLUME /data
VOLUME /root/.mitmproxy

# Run the HTTPS-enabled server directly from the installed package
ENTRYPOINT ["encrypted-blob-docker-entrypoint"]
