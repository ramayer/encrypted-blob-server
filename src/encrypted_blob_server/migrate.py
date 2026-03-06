#!/usr/bin/env python3
"""
Migrate blobs between encrypted-blob-storage accounts.

Usage:
    encrypted-blob-migrate SOURCE_URL SOURCE_USER DEST_URL DEST_USER

Prompts for both passwords. Iterates the source index, uploads each blob to
the destination, and deletes it from the source on success. Works as a
password change (same server, same or different username), a server migration,
or a way to split a bloated database by migrating subsets to another server.

Blobs not in the index (uploaded without a browser session) are not migrated —
only what appears in /_/index is visible to this script.
"""

import sys, argparse, getpass
import requests

def login(base_url: str, username: str, password: str) -> requests.Session:
    s = requests.Session()
    r = s.post(f"{base_url}/_/login",
               data={"username": username, "password": password},
               allow_redirects=False)
    if r.status_code not in (200, 302):
        raise RuntimeError(f"Login to {base_url} as {username!r} failed: {r.status_code}")
    return s

def get_index(session: requests.Session, base_url: str) -> dict:
    r = session.get(f"{base_url}/_/index")
    if r.status_code != 200:
        raise RuntimeError(f"Could not fetch index from {base_url}: {r.status_code}")
    return r.json()

def migrate(src_url, src_session, dst_url, dst_session, paths: list[str]):
    ok = []; failed = []; skipped = []

    for path in paths:
        # Fetch from source
        r = src_session.get(f"{src_url}/{path}")
        if r.status_code != 200:
            print(f"  ✗  /{path}  fetch failed ({r.status_code})")
            failed.append(path)
            continue

        mime = r.headers.get("Content-Type", "application/octet-stream")
        # Strip charset suffix if present — we store mime type clean
        mime = mime.split(";")[0].strip()

        # Upload to destination
        w = dst_session.put(f"{dst_url}/{path}",
                            data=r.content,
                            headers={"Content-Type": mime})
        if w.status_code != 201:
            print(f"  ✗  /{path}  upload failed ({w.status_code} {w.text.strip()})")
            failed.append(path)
            continue

        # Delete from source only after confirmed upload
        d = src_session.put(f"{src_url}/{path}", data=b"")
        if d.status_code == 204:
            print(f"  ✓  /{path}")
            ok.append(path)
        else:
            # Uploaded successfully but delete failed — not catastrophic,
            # blob now exists in both places. Report it but don't count as failed.
            print(f"  ~  /{path}  copied but source delete failed ({d.status_code})")
            skipped.append(path)

    total = len(paths)
    print(f"\n{len(ok)}/{total} migrated cleanly.")
    if skipped:
        print(f"{len(skipped)} copied but not deleted from source (check manually):")
        for p in skipped: print(f"  {p}")
    if failed:
        print(f"{len(failed)} failed (not touched on either side):")
        for p in failed: print(f"  {p}")
        sys.exit(1)

def main():
    p = argparse.ArgumentParser(
        description="Migrate blobs between encrypted-blob-storage accounts.")
    p.add_argument("src_url",  help="Source server URL")
    p.add_argument("src_user", help="Source username")
    p.add_argument("dst_url",  help="Destination server URL")
    p.add_argument("dst_user", help="Destination username")
    p.add_argument("--paths",  nargs="+",
                   help="Specific paths to migrate (default: everything in index)")
    args = p.parse_args()

    src_pass = getpass.getpass(f"Password for {args.src_user}@{args.src_url}: ")
    dst_pass = getpass.getpass(f"Password for {args.dst_user}@{args.dst_url}: ")

    print("Logging in...")
    src_session = login(args.src_url, args.src_user, src_pass)
    dst_session = login(args.dst_url, args.dst_user, dst_pass)

    if args.paths:
        paths = args.paths
    else:
        print("Fetching source index...")
        index = get_index(src_session, args.src_url)
        paths = sorted(index.get("files", {}).keys())

    if not paths:
        print("No files found in source index.")
        sys.exit(0)

    print(f"Migrating {len(paths)} file(s) from {args.src_url} ({args.src_user})"
          f" → {args.dst_url} ({args.dst_user})\n")
    migrate(args.src_url, src_session, args.dst_url, dst_session, paths)

if __name__ == "__main__":
    main()
