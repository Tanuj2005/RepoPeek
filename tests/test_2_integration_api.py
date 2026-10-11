"""
SUITE 2 - INTEGRATION / API TESTING (17 tests)  -  CO2/CO3: functional, black-box

Runs the real FastAPI app through HTTP. Only Supabase (in-memory) and GitHub
(respx) are faked. Tests follow the three sprints' user stories.
"""
import base64
from datetime import datetime, timezone, timedelta

import httpx
import respx

GH = "https://api.github.com"


def mock_viewer_github(repo_json, contents_json):
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=repo_json))
    respx.get(f"{GH}/repos/alice/secret-repo/contents").mock(return_value=httpx.Response(200, json=contents_json))
    respx.get(url__startswith=f"{GH}/repos/alice/secret-repo/commits").mock(
        return_value=httpx.Response(200, json=[{"sha": "abc"}]))


PAYLOAD = {"token": "gho_REAL", "owner": "alice", "repo": "secret-repo",
           "user_id": "1001", "expires_in_days": 10}


# ============ Sprint 1: authentication ============
def test_01_health_endpoint_is_up(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "healthy"


@respx.mock
def test_02_oauth_code_exchange_returns_user_and_never_the_client_secret(client):
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "gho_new"}))
    respx.get(f"{GH}/user").mock(return_value=httpx.Response(
        200, json={"id": 1001, "login": "alice", "name": "Alice", "avatar_url": "x"}))
    r = client.post("/api/github-auth", json={"code": "abc123", "redirect_uri": "https://ext/cb"})
    assert r.status_code == 200
    assert r.json()["success"] is True and r.json()["user"]["login"] == "alice"
    assert "test-client-secret" not in r.text


@respx.mock
def test_03_oauth_invalid_code_returns_400(client):
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"error": "bad_verification_code",
                                               "error_description": "incorrect"}))
    r = client.post("/api/github-auth", json={"code": "wrong", "redirect_uri": "https://ext/cb"})
    assert r.status_code == 400


# ============ Sprint 2: share link management ============
@respx.mock
def test_04_generate_link_for_private_repo_with_expiry(client, db, github_repo_json):
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=github_repo_json))
    r = client.post("/api/generate-link", json=PAYLOAD)
    assert r.status_code == 200
    body = r.json()
    assert body["share_link"] == f"http://testserver/view/{body['link_id']}"
    assert len(db.links) == 1
    exp = datetime.fromisoformat(db.links[0]["expires_at"])
    assert abs((exp - (datetime.now(timezone.utc) + timedelta(days=10))).total_seconds()) < 10


@respx.mock
def test_05_duplicate_request_returns_existing_link(client, db, github_repo_json):
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=github_repo_json))
    first = client.post("/api/generate-link", json=PAYLOAD).json()
    second = client.post("/api/generate-link", json=PAYLOAD).json()
    assert second["link_id"] == first["link_id"] and second["is_existing"] is True
    assert len(db.links) == 1


@respx.mock
def test_06_public_repo_is_rejected(client, github_repo_json):
    github_repo_json["private"] = False
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(200, json=github_repo_json))
    assert client.post("/api/generate-link", json=PAYLOAD).status_code == 400


@respx.mock
def test_07_repo_not_found_returns_404_and_stores_nothing(client, db):
    respx.get(f"{GH}/repos/alice/secret-repo").mock(return_value=httpx.Response(404))
    assert client.post("/api/generate-link", json=PAYLOAD).status_code == 404
    assert db.links == []


def test_08_revoke_by_owner_succeeds(client, make_link, db):
    lid = make_link(user_id="1001")
    r = client.delete("/api/revoke-link", params={"link_id": lid, "user_id": "1001"})
    assert r.status_code == 200 and r.json()["success"] is True
    assert db.links == []


def test_09_revoke_by_someone_else_is_denied_and_link_stays(client, make_link, db):
    lid = make_link(user_id="1001")
    r = client.delete("/api/revoke-link", params={"link_id": lid, "user_id": "6666"})
    assert r.status_code == 404 and len(db.links) == 1


@respx.mock
def test_10_revoked_link_stops_working_immediately(client, make_link, github_repo_json,
                                                   github_contents_json):
    lid = make_link(user_id="1001")
    mock_viewer_github(github_repo_json, github_contents_json)
    assert client.get(f"/view/{lid}").status_code == 200
    client.delete("/api/revoke-link", params={"link_id": lid, "user_id": "1001"})
    assert client.get(f"/view/{lid}").status_code == 404
    assert client.get(f"/api/view/{lid}/commits").status_code == 404


# ============ Sprint 3: viewer and access tracking ============
@respx.mock
def test_11_viewer_page_loads_repo_info_and_root_files_via_ajax(client, make_link, github_repo_json,
                                                                github_contents_json):
    lid = make_link()
    mock_viewer_github(github_repo_json, github_contents_json)
    r = client.get(f"/view/{lid}")
    assert r.status_code == 200
    assert "secret-repo" in r.text and "loadDirectory()" in r.text


@respx.mock
def test_12_initial_load_does_not_fetch_forks_or_stargazers(client, make_link, github_repo_json,
                                                            github_contents_json):
    lid = make_link()
    mock_viewer_github(github_repo_json, github_contents_json)
    client.get(f"/view/{lid}")
    called = [str(c.request.url) for c in respx.calls]
    assert not any("/forks" in u or "/stargazers" in u for u in called)


@respx.mock
def test_13_commits_load_on_demand_and_are_formatted(client, make_link):
    lid = make_link()
    respx.get(url__startswith=f"{GH}/repos/alice/secret-repo/commits").mock(
        return_value=httpx.Response(200, json=[{
            "sha": "abcdef1234567", "html_url": "u",
            "commit": {"message": "first\nbody", "author": {"name": "A", "date": "d"}},
            "author": {"avatar_url": "av", "login": "alice"}}]))
    c = client.get(f"/api/view/{lid}/commits").json()["commits"][0]
    assert c["sha"] == "abcdef1" and c["message"] == "first"


@respx.mock
def test_14_forks_and_stargazers_load_on_demand(client, make_link):
    lid = make_link()
    respx.get(url__startswith=f"{GH}/repos/alice/secret-repo/forks").mock(
        return_value=httpx.Response(200, json=[{
            "owner": {"login": "bob", "avatar_url": "a", "html_url": "h"}, "name": "r",
            "full_name": "bob/r", "description": None, "stargazers_count": 0,
            "forks_count": 0, "updated_at": "d", "html_url": "u"}]))
    respx.get(url__startswith=f"{GH}/repos/alice/secret-repo/stargazers").mock(
        return_value=httpx.Response(200, json=[
            {"login": "carol", "avatar_url": "a", "html_url": "h", "type": "User"}]))
    assert client.get(f"/api/view/{lid}/forks").json()["forks"][0]["owner"]["username"] == "bob"
    assert client.get(f"/api/view/{lid}/stargazers").json()["stargazers"][0]["username"] == "carol"


@respx.mock
def test_15_folder_click_loads_directory_and_hides_dotfiles(client, make_link, github_contents_json):
    lid = make_link()
    respx.get(f"{GH}/repos/alice/secret-repo/contents/src").mock(
        return_value=httpx.Response(200, json=github_contents_json))
    names = [i["name"] for i in client.get(f"/api/view/{lid}/contents", params={"path": "src"}).json()["contents"]]
    assert "README.md" in names and ".env" not in names


@respx.mock
def test_16_view_count_and_last_accessed_are_tracked(client, make_link, db, github_repo_json,
                                                     github_contents_json):
    lid = make_link(access_count=0)
    mock_viewer_github(github_repo_json, github_contents_json)
    for _ in range(3):
        client.get(f"/view/{lid}")
    assert db.links[0]["access_count"] == 3
    assert db.links[0]["last_accessed_at"] is not None


def test_17_expired_unknown_and_malformed_links_return_404(client, make_link):
    exp = make_link(link_id="E" * 22, expired=True)
    assert client.get(f"/view/{exp}").status_code == 404
    assert client.get(f"/api/view/{exp}/commits").status_code == 404
    assert client.get(f"/view/{'Z' * 22}").status_code == 404
    assert client.get("/view/short").status_code == 404
