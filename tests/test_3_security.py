"""
SUITE 3 - SECURITY TESTING (17 tests)  -  CO2/CO3: non-functional (security)

Tests marked "DEFECT CHECK" assert the SECURE behaviour. If they FAIL, the
failure is a genuine vulnerability to log in your defect tracker (JIRA/Bugzilla).
"""
import base64
import json
import re
from pathlib import Path

import httpx
import respx

from src import database
from src.database import ShareLinkDB

GH = "https://api.github.com"
SECRET = "gho_REAL_SECRET_TOKEN_123"
GEN = {"token": SECRET, "owner": "alice", "repo": "secret-repo",
       "user_id": "1001", "expires_in_days": 5}


def mock_viewer(repo_json, contents_json):
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=repo_json))
    respx.get(f"{GH}/repos/alice/secret-repo/contents").mock(return_value=httpx.Response(200, json=contents_json))
    respx.get(url__startswith=f"{GH}/repos/alice/secret-repo/commits").mock(
        return_value=httpx.Response(200, json=[{"sha": "a"}]))


# ============ A. Credential confidentiality (Sprint 1) ============
@respx.mock
def test_01_plaintext_token_never_stored_or_echoed(client, db, github_repo_json):
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=github_repo_json))
    r = client.post("/api/generate-link", json=GEN)
    assert db.links, "link was not created"
    assert SECRET not in json.dumps(db.links)
    assert SECRET not in r.text and "encrypted_token" not in r.text
    assert database.decrypt_token(db.links[0]["encrypted_token"]) == SECRET


@respx.mock
def test_02_viewer_html_never_contains_token_or_ciphertext(client, make_link, db, github_repo_json,
                                                           github_contents_json):
    lid = make_link(token=SECRET)
    mock_viewer(github_repo_json, github_contents_json)
    r = client.get(f"/view/{lid}")
    assert r.status_code == 200
    assert SECRET not in r.text and db.links[0]["encrypted_token"] not in r.text


@respx.mock
def test_03_no_api_endpoint_leaks_token_or_ciphertext(client, make_link, db):
    lid = make_link(token=SECRET)
    enc = db.links[0]["encrypted_token"]
    respx.route(url__startswith=GH).mock(return_value=httpx.Response(200, json=[]))
    for ep in ("commits", "forks", "stargazers", "contents"):
        body = client.get(f"/api/view/{lid}/{ep}").text
        assert SECRET not in body and enc not in body, f"leak in /{ep}"


@respx.mock
def test_04_token_is_only_sent_to_github_over_https(client, make_link, github_repo_json,
                                                    github_contents_json):
    lid = make_link(token=SECRET)
    mock_viewer(github_repo_json, github_contents_json)
    client.get(f"/view/{lid}")
    assert respx.calls
    for call in respx.calls:
        assert call.request.url.scheme == "https" and call.request.url.host == "api.github.com"


def test_05_no_hardcoded_secrets_in_source():
    pattern = re.compile(r"(gh[pousr]_[A-Za-z0-9]{30,}|client_secret\s*=\s*['\"][A-Za-z0-9]{20,})")
    root = Path(__file__).resolve().parent.parent
    files = list((root / "src").rglob("*.py")) + list((root / "api").rglob("*.py"))
    assert [str(p) for p in files if pattern.search(p.read_text(errors="ignore"))] == []


# ============ B. Link secrecy (Sprint 2) ============
@respx.mock
def test_06_link_ids_are_unique_unpredictable_and_long(client, github_repo_json):
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=github_repo_json))
    ids = [client.post("/api/generate-link", json={**GEN, "user_id": str(i)}).json()["link_id"]
           for i in range(30)]
    assert len(set(ids)) == 30
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{22,}", i) for i in ids)  # >=128 bits


def test_07_expired_and_nonexistent_links_are_indistinguishable(client, make_link):
    make_link(link_id="E" * 22, expired=True)
    a, b = client.get(f"/view/{'E' * 22}"), client.get(f"/view/{'N' * 22}")
    assert a.status_code == b.status_code == 404 and a.text == b.text


# ============ C. Injection and malformed input ============
def test_08_hostile_link_ids_return_404_and_are_not_reflected(client):
    payloads = ["' OR '1'='1' -- -------------", "1; DROP TABLE share_links; --",
                "<script>alert(1)</script>xxxxxxxx", "{{7*7}}{{config}}aaaaaaaaaaaaaaaa", "A" * 5000]
    for p in payloads:
        r = client.get(f"/view/{p}")
        assert r.status_code in (404, 422), f"{p[:20]!r} -> {r.status_code}"
        assert p not in r.text
        assert client.get(f"/api/view/{p}/commits").status_code in (404, 422)


def test_09_malicious_owner_repo_names_get_clean_422(client):
    """DEFECT CHECK: bad names are rejected, but the app crashes into HTTP 500
    because the custom validation handler cannot JSON-serialise pydantic's ValueError."""
    for field in ("owner", "repo"):
        for bad in ("../../x", "a;b", "<b>x</b>", "a b", "a/b", "$(id)"):
            body = {**GEN, field: bad}
            assert client.post("/api/generate-link", json=body).status_code == 422, f"{field}={bad!r}"


# ============ D. Access control ============
@respx.mock
def test_10_path_traversal_cannot_escape_the_shared_repository(client, make_link):
    """DEFECT CHECK (HIGH): `path` is concatenated into the GitHub URL and httpx
    collapses '../', so a viewer can make the server call GitHub's /user or the
    owner's OTHER private repos using the owner's token."""
    lid = make_link(owner="alice", repo="secret-repo", token=SECRET)
    respx.route(url__startswith=GH).mock(return_value=httpx.Response(200, json=[]))
    attacks = ["../../../../user", "../../../../repos/alice/OTHER-PRIVATE-REPO/contents",
               "../../../other-owner/other-repo/contents", "%2e%2e/%2e%2e/%2e%2e/%2e%2e/user"]
    for path in attacks:
        for ep in ("contents", "file", "raw"):
            client.get(f"/api/view/{lid}/{ep}", params={"path": path})
    outside = {str(c.request.url) for c in respx.calls
               if not str(c.request.url).startswith(f"{GH}/repos/alice/secret-repo/")}
    assert outside == set(), f"Server called outside the shared repo: {sorted(outside)}"


@respx.mock
def test_11_file_endpoint_does_not_serve_dotfiles(client, make_link):
    """DEFECT CHECK (MEDIUM): /contents hides dotfiles but /file?path=.env returns them."""
    lid = make_link()
    respx.get(f"{GH}/repos/alice/secret-repo/contents/.env").mock(
        return_value=httpx.Response(200, json={"name": ".env", "size": 9,
                                               "content": base64.b64encode(b"DB_PASS=1").decode()}))
    r = client.get(f"/api/view/{lid}/file", params={"path": ".env"})
    assert r.status_code in (400, 403, 404) and "DB_PASS" not in r.text


def test_12_revoke_with_wrong_user_id_is_denied(client, make_link, db):
    lid = make_link(user_id="1001")
    assert client.delete("/api/revoke-link", params={"link_id": lid, "user_id": "2002"}).status_code == 404
    assert len(db.links) == 1


def test_13_revoke_requires_proof_of_identity(client, make_link):
    """DEFECT CHECK (HIGH): revoke trusts a plain `user_id` query parameter (GitHub
    numeric IDs are public). It should require the owner's Authorization token."""
    lid = make_link(user_id="1001")
    r = client.delete("/api/revoke-link", params={"link_id": lid, "user_id": "1001"})
    assert r.status_code in (401, 403), "revoked without any credentials"


@respx.mock
def test_14_generate_link_rejects_spoofed_user_id(client, github_repo_json):
    """DEFECT CHECK (MEDIUM): body `user_id` is never verified against the token."""
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=github_repo_json))
    respx.get(f"{GH}/user").mock(return_value=httpx.Response(200, json={"id": 1001}))
    r = client.post("/api/generate-link", json={**GEN, "user_id": "999999"})
    assert r.status_code in (400, 401, 403)


# ============ E. CORS, errors, resilience ============
def test_15_cors_blocks_unknown_and_lookalike_origins(client):
    for origin in ("https://evil.example", "http://localhost.evil.com",
                   "chrome-extension://abc.evil.com", "null"):
        r = client.get("/health", headers={"Origin": origin})
        assert "access-control-allow-origin" not in r.headers, origin
    ok = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"


@respx.mock
def test_16_github_auth_does_not_reflect_arbitrary_origin(client):
    """DEFECT CHECK (MEDIUM): /api/github-auth echoes ANY Origin back with
    Allow-Credentials: true, bypassing the CORS allow-list."""
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "gho_x"}))
    respx.get(f"{GH}/user").mock(return_value=httpx.Response(200, json={"id": 1, "login": "a", "avatar_url": "x"}))
    r = client.post("/api/github-auth", json={"code": "c", "redirect_uri": "https://e/cb"},
                    headers={"Origin": "https://evil.example"})
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"


def test_17_internal_errors_do_not_leak_details(client, monkeypatch):
    """DEFECT CHECK (MEDIUM): API returns str(exception) as the 500 body."""
    async def boom(_):
        raise RuntimeError("connect to db-internal.corp:5432 failed password=hunter2")
    monkeypatch.setattr(ShareLinkDB, "get_link", staticmethod(boom))
    r = client.get(f"/api/view/{'A' * 22}/commits")
    assert r.status_code == 500
    assert "db-internal" not in r.text and "hunter2" not in r.text
