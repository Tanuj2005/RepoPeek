"""
SUITE 1 - UNIT TESTING (15 tests)  -  CO2: black-box techniques (ECP, BVA)

Sprint 1: token encryption/decryption
Sprint 2: request validation (expiry 1-60 days, owner/repo names)
Sprint 3: access-tracking logic in ShareLinkDB
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet, InvalidToken
from pydantic import ValidationError

from src.database import encrypt_token, decrypt_token, ShareLinkDB
from src.schemas import GenerateLinkRequest


def run(coro):
    return asyncio.run(coro)


def make_req(**overrides):
    base = dict(token="gho_abc", owner="alice", repo="my-repo",
                user_id="1001", expires_in_days=7)
    base.update(overrides)
    return GenerateLinkRequest(**base)


# ---------------------- Sprint 1: encryption ----------------------
def test_01_encrypt_decrypt_roundtrip_returns_original_token():
    for token in ["gho_secret123", "a", "gho_" + "x" * 500, "tök€n-ünïcode"]:
        assert decrypt_token(encrypt_token(token)) == token


def test_02_ciphertext_hides_plaintext_and_is_randomised():
    ct1, ct2 = encrypt_token("gho_secret123"), encrypt_token("gho_secret123")
    assert "gho_secret123" not in ct1
    assert ct1 != ct2  # Fernet uses a random IV


def test_03_tampered_or_garbage_ciphertext_is_rejected():
    ct = encrypt_token("gho_secret123")
    tampered = ct[:-4] + ("AAAA" if not ct.endswith("AAAA") else "BBBB")
    for bad in (tampered, "not-a-real-ciphertext"):
        with pytest.raises(InvalidToken):
            decrypt_token(bad)


def test_04_token_encrypted_with_another_key_cannot_be_decrypted():
    foreign = Fernet(Fernet.generate_key()).encrypt(b"gho_x").decode()
    with pytest.raises(InvalidToken):
        decrypt_token(foreign)


# ---------------------- Sprint 2: validation ----------------------
def test_05_expiry_accepts_valid_range_boundaries():  # BVA: 1, 2, 59, 60
    for days in (1, 2, 30, 59, 60):
        assert make_req(expires_in_days=days).expires_in_days == days


def test_06_expiry_rejects_out_of_range_values():  # BVA: 0, 61, ECP: negative / text
    for days in (0, -1, 61, 10_000, "abc"):
        with pytest.raises(ValidationError):
            make_req(expires_in_days=days)


def test_07_default_expiry_is_7_days():
    assert GenerateLinkRequest(token="t", owner="a", repo="b", user_id="1").expires_in_days == 7


def test_08_valid_owner_and_repo_names_accepted():
    for name in ("alice", "my-repo", "my_repo", "Repo123", "a", "a" * 100):
        assert make_req(owner=name, repo=name).repo == name


def test_09_malicious_or_oversized_names_rejected_by_schema():
    for bad in ("../etc/passwd", "a/b", "a b", "a;b", "<script>", "$(id)", "", "a" * 101):
        with pytest.raises(ValidationError):
            make_req(repo=bad)


def test_10_repo_names_containing_dots_are_accepted():
    """DEFECT CHECK: GitHub allows '.' in repo names (e.g. next.js); the regex rejects them."""
    for name in ("next.js", "socket.io", "my.dotted.repo"):
        assert make_req(repo=name).repo == name


# ---------------------- Sprint 2/3: ShareLinkDB ----------------------
def test_11_create_link_stores_encrypted_token_and_correct_expiry(db):
    run(ShareLinkDB.create_link("L" * 22, "alice", "repo", "gho_plain", "1001", 10))
    row = db.links[0]
    assert "gho_plain" not in str(row)
    assert decrypt_token(row["encrypted_token"]) == "gho_plain"
    assert row["access_count"] == 0
    expected = datetime.now(timezone.utc) + timedelta(days=10)
    assert abs((datetime.fromisoformat(row["expires_at"]) - expected).total_seconds()) < 5


def test_12_get_link_returns_valid_but_none_for_expired_or_unknown(make_link):
    good = make_link(link_id="G" * 22)
    old = make_link(link_id="X" * 22, expired=True)
    assert run(ShareLinkDB.get_link(good))["link_id"] == good
    assert run(ShareLinkDB.get_link(old)) is None
    assert run(ShareLinkDB.get_link("does-not-exist")) is None


def test_13_increment_access_count_updates_count_time_and_ip(make_link, db):
    lid = make_link(access_count=4)
    run(ShareLinkDB.increment_access_count(lid, "9.9.9.9"))
    row = db.links[0]
    assert row["access_count"] == 5
    assert row["last_accessed_at"] is not None
    assert row["last_ip"] == "9.9.9.9"


def test_14_revoke_only_works_for_the_owner(make_link, db):
    lid = make_link(user_id="1001")
    assert run(ShareLinkDB.revoke_link(lid, "9999")) is False
    assert len(db.links) == 1
    assert run(ShareLinkDB.revoke_link(lid, "1001")) is True
    assert db.links == []


def test_15_user_link_listing_is_scoped_and_hides_encrypted_token(make_link):
    make_link(link_id="A" * 22, user_id="1")
    make_link(link_id="B" * 22, user_id="2")
    rows = run(ShareLinkDB.get_user_links("1"))
    assert [r["link_id"] for r in rows] == ["A" * 22]
    assert "encrypted_token" not in rows[0]
