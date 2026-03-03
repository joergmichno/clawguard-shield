"""
Shared test fixtures for ClawGuard Shield tests.
"""

import os
import sys
import tempfile
import pytest

# Add parent directory to path so we can import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Use temp database for tests
_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["SHIELD_DB_PATH"] = _test_db.name
_test_db.close()

from app import app as flask_app
from database import init_db
from auth import generate_api_key, hash_key, get_key_prefix


@pytest.fixture(autouse=True)
def reset_db():
    """Reset database before each test."""
    import database
    # Re-init the database fresh
    conn = database.get_connection()
    conn.executescript("""
        DROP TABLE IF EXISTS rate_limits;
        DROP TABLE IF EXISTS usage_log;
        DROP TABLE IF EXISTS api_keys;
    """)
    conn.commit()
    init_db()
    yield


@pytest.fixture
def client():
    """Flask test client."""
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


@pytest.fixture
def api_key():
    """Generate and store a test API key, return the raw key."""
    from database import insert_api_key
    raw_key = generate_api_key()
    key_hash = hash_key(raw_key)
    key_prefix = get_key_prefix(raw_key)
    insert_api_key(key_hash=key_hash, key_prefix=key_prefix, email="test@example.com", tier="free")
    return raw_key


@pytest.fixture
def pro_api_key():
    """Generate and store a Pro tier API key."""
    from database import insert_api_key
    raw_key = generate_api_key()
    key_hash = hash_key(raw_key)
    key_prefix = get_key_prefix(raw_key)
    insert_api_key(key_hash=key_hash, key_prefix=key_prefix, email="pro@example.com", tier="pro")
    return raw_key
