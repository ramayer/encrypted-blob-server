#!/usr/bin/env python3
"""
Generate one-time invite tokens for encrypted-blob-server.

Usage:
    encrypted-blob-create-invites URL N
    
Example:
    encrypted-blob-create-invites https://localhost:5443 5
    
Prompts for BLOB_ADMIN_SECRET as the password for the _admin user.
"""

import sys, getpass, secrets
import requests

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    base_url = sys.argv[1]
    n        = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    password = getpass.getpass("Admin secret: ")

    s = requests.Session()
    r = s.post(f"{base_url}/_/login",
               data={"username": "_admin", "password": password},
               allow_redirects=False)
    if r.status_code not in (200, 302):
        print(f"Login failed: {r.status_code}", file=sys.stderr)
        sys.exit(1)

    for _ in range(n):
        t = secrets.token_hex(16)
        r = s.put(f"{base_url}/_invites/{t}", data=b"1",
                  headers={"Content-Type": "text/plain"})
        if r.status_code == 201:
            print(t)
        else:
            print(f"Failed to create token: {r.status_code} {r.text}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
