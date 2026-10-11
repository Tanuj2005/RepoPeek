"""
Shared test setup for GitShare backend tests.

SAFETY: This file forces *fake* credentials and replaces the Supabase client
with an in-memory fake BEFORE the app is imported, so running the tests never
touches your real Supabase database, GitHub, or .env secrets.
"""
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet

# ---- 1. Make `src` importable (run pytest from the repo root) -------------
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---- 2. Force fake environment (overrides any real .env values) -----------
TEST_FERNET_KEY = Fernet.generate_key().decode()
os.environ.update({
    "SUPABASE_URL": "https://fake-project.supabase.co",
    "SUPABASE_KEY": "fake-anon-key",
    "SUPABASE_SERVICE_KEY": "fake-service-key",
    "GITHUB_CLIENT_ID": "test-client-id",
    "GITHUB_CLIENT_SECRET": "test-client-secret",
    "ENCRYPTION_KEY": TEST_FERNET_KEY,
    "BACKEND_URL": "http://testserver",
    "ENVIRONMENT": "development",
})


# ---- 3. In-memory fake of the Supabase query builder ----------------------
class _Resp:
    def __init__(self, data):
        self.data = data


class _Query:
    def __init__(self, store, table):
        self.store, self.table = store, table
        self.op, self.payload, self.filters = None, None, []
        self.cols, self._order = "*", None

    def select(self, cols="*"):
        self.op, self.cols = "select", cols
        return self

    def insert(self, row):
        self.op, self.payload = "insert", row
        return self

    def update(self, values):
        self.op, self.payload = "update", values
        return self

    def delete(self):
        self.op = "delete"
        return self

    def eq(self, col, val):
        self.filters.append((col, val))
        return self

    def order(self, col, desc=False):
        self._order = (col, desc)
        return self

    def _match(self, row):
        return all(row.get(c) == v for c, v in self.filters)

    def execute(self):
        rows = self.store.tables.setdefault(self.table, [])
        if self.op == "insert":
            rows.append(dict(self.payload))
            return _Resp([dict(self.payload)])
        if self.op == "update":
            hit = [r for r in rows if self._match(r)]
            for r in hit:
                r.update(self.payload)
            return _Resp([dict(r) for r in hit])
        if self.op == "delete":
            gone = [r for r in rows if self._match(r)]
            self.store.tables[self.table] = [r for r in rows if not self._match(r)]
            return _Resp(gone)
        # select
        hit = [dict(r) for r in rows if self._match(r)]
        if self._order:
            hit.sort(key=lambda r: r[self._order[0]], reverse=self._order[1])
        if self.cols != "*":
            keep = [c.strip() for c in self.cols.split(",")]
            hit = [{k: r[k] for k in keep if k in r} for r in hit]
        return _Resp(hit)


class FakeSupabase:
    def __init__(self):
        self.tables = {}

    def table(self, name):
        return _Query(self, name)

    def reset(self):
        self.tables = {}

    # helper for tests
    @property
    def links(self):
        return self.tables.setdefault("share_links", [])


FAKE_DB = FakeSupabase()

# Patch BEFORE src.database is imported
import supabase as _supabase_pkg  # noqa: E402
_supabase_pkg.create_client = lambda *a, **k: FAKE_DB

# Now it is safe to import the app
from src.main import app  # noqa: E402
from src import database  # noqa: E402


# ---- 4. Fixtures -----------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_db():
    """Every test starts with an empty database."""
    FAKE_DB.reset()
    yield FAKE_DB
    FAKE_DB.reset()


@pytest.fixture
def db():
    return FAKE_DB


class SyncClient:
    """
    Tiny synchronous HTTP client that talks straight to the FastAPI app via
    httpx's ASGI transport. Used instead of Starlette's TestClient because the
    pinned fastapi==0.109 TestClient is incompatible with httpx>=0.28.
    Unhandled server errors are returned as HTTP 500 (not raised).
    """
    def __init__(self, asgi_app):
        self.app = asgi_app

    def request(self, method, url, **kwargs):
        import asyncio
        import httpx

        async def _go():
            transport = httpx.ASGITransport(
                app=self.app, raise_app_exceptions=False, client=("203.0.113.5", 5000))
            async with httpx.AsyncClient(transport=transport,
                                         base_url="http://testserver") as c:
                return await c.request(method, url, **kwargs)
        return asyncio.run(_go())

    def get(self, url, **kw): return self.request("GET", url, **kw)
    def post(self, url, **kw): return self.request("POST", url, **kw)
    def delete(self, url, **kw): return self.request("DELETE", url, **kw)
    def options(self, url, **kw): return self.request("OPTIONS", url, **kw)


@pytest.fixture
def client():
    return SyncClient(app)


@pytest.fixture
def make_link(db):
    """Insert a share link straight into the fake DB. Returns the link_id."""
    def _make(link_id="A" * 22, owner="alice", repo="secret-repo",
              token="gho_REAL_SECRET_TOKEN_123", user_id="1001",
              days=7, expired=False, access_count=0):
        now = datetime.now(timezone.utc)
        expires = now - timedelta(days=1) if expired else now + timedelta(days=days)
        db.links.append({
            "link_id": link_id,
            "owner": owner,
            "repo": repo,
            "encrypted_token": database.encrypt_token(token),
            "user_id": user_id,
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat(),
            "access_count": access_count,
            "last_accessed_at": None,
            "last_ip": None,
        })
        return link_id
    return _make


# ---- 5. Canned GitHub payloads --------------------------------------------
@pytest.fixture
def github_repo_json():
    return {
        "name": "secret-repo", "full_name": "alice/secret-repo", "private": True,
        "description": "top secret", "stargazers_count": 3, "forks_count": 1,
        "language": "Python", "html_url": "https://github.com/alice/secret-repo",
        "owner": {"login": "alice", "avatar_url": "https://a/x.png"},
        "default_branch": "main", "updated_at": "2026-01-01T00:00:00Z",
        "open_issues_count": 0, "watchers_count": 3,
    }


@pytest.fixture
def github_contents_json():
    return [
        {"name": "README.md", "path": "README.md", "type": "file", "size": 10},
        {"name": "src", "path": "src", "type": "dir", "size": 0},
        {"name": ".env", "path": ".env", "type": "file", "size": 50},
    ]
