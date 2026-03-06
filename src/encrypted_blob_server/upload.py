#!/usr/bin/env python3
"""
Upload files and/or directories to encrypted-blob-storage.

Usage:
    python3 upload.py BASE_URL USERNAME PASSWORD [--prefix PREFIX] PATH [PATH ...]

Examples:
    # Firefox saved page — both args preserve their paths under the prefix
    python3 upload.py http://localhost:5000 alice secret --prefix=archive/2015 example.html example_files

    # Glob (shell-expanded before we see it, paths preserved as-is)
    python3 upload.py http://localhost:5000 alice secret --prefix=cats images/animals/cat*.jpg
"""

import sys, mimetypes, argparse
from pathlib import Path
import requests

def login(base_url: str, username: str, password: str) -> requests.Session:
    s = requests.Session()
    r = s.post(f"{base_url}/_/login",
               data={"username": username, "password": password},
               allow_redirects=False)
    if r.status_code not in (200, 302):
        raise RuntimeError(f"Login failed: {r.status_code}")
    return s

def collect(paths: list[Path]) -> list[tuple[Path, str]]:
    """Expand paths into (local_path, server_rel_path) pairs.
    Paths are preserved as given — files and directory trees alike."""
    results = []
    for path in paths:
        if path.is_file():
            results.append((path, str(path).replace("\\", "/")))
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    results.append((child, str(child).replace("\\", "/")))
        else:
            print(f"  ?  {path} — not found, skipping")
    return results

def upload(base_url: str, session: requests.Session,
           pairs: list[tuple[Path, str]], prefix: str):
    prefix = prefix.rstrip("/") + "/" if prefix else ""
    errors = []

    for local, rel in pairs:
        dest = prefix + rel
        mime = mimetypes.guess_type(str(local))[0] or "application/octet-stream"
        r    = session.put(f"{base_url}/{dest}",
                           data=local.read_bytes(),
                           headers={"Content-Type": mime})
        if r.status_code == 201:
            print(f"  ✓  /{dest}")
        else:
            print(f"  ✗  /{dest}  ({r.status_code} {r.text.strip()})")
            errors.append(dest)

    total = len(pairs)
    print(f"\n{total - len(errors)}/{total} uploaded successfully.")
    if errors:
        print("Failed:")
        for e in errors: print(f"  {e}")
        sys.exit(1)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("base_url")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("--prefix", default="")
    p.add_argument("paths", nargs="+", type=Path)
    args = p.parse_args()

    pairs = collect(args.paths)
    if not pairs:
        print("No files found.")
        sys.exit(1)

    print(f"Uploading {len(pairs)} file(s)...")
    session = login(args.base_url, args.username, args.password)
    upload(args.base_url, session, pairs, args.prefix)

if __name__ == "__main__":
    main()
