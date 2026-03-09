"""
Shared pytest fixtures.

Provides a temporary database for each test and patches the server module to
use it, so tests never touch a real database. BLOB_SALT is set to a random
value before import so the server never uses the default warning-triggering salt.
"""

import os
import secrets
import pytest

# Must be set before the server module is imported anywhere in the test session.
os.environ.setdefault("BLOB_SALT", secrets.token_hex(32))

import encrypted_blob_server.app as server


@pytest.fixture(autouse=True)
def temp_db(tmp_path):
    """Point the server at a fresh SQLite database for each test."""
    db_path = str(tmp_path / "test.sqlite3")
    original = server.DB_PATH
    server.DB_PATH = db_path
    server._init_db()
    server.cache_clear()
    yield db_path
    server.DB_PATH = original
    server.cache_clear()


@pytest.fixture(autouse=True)
def init_cookie_key():
    """Ensure the cookie HMAC key matches the current BLOB_SALT."""
    server._init_cookie_key()