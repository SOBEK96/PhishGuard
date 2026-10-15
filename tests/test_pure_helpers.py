"""Pure-function tests: input validation, feed-URL policy, record parsing.
These exercise the contract module's helpers directly (no storage, no clock)."""

import json

import pytest

from tests.conftest import FIRST_SEEN, PUBLISHED, TARGET, commit, rec


@pytest.mark.parametrize("slug", [
    "uniswap-claim-airdrop.com", "a.b", "abc", "0xdeadbeef", "x" * 128, "a-b-c.d-e.f",
    "sub.domain.example.org", "1inch-claim.io", "xn--80ak6aa92e.com",
])
def test_target_id_accepts_canonical_slugs(pg, mod, slug):
    assert mod._valid_target_id(slug) is True


@pytest.mark.parametrize("slug", [
    "", "ab", "x" * 129, "UPPER.com", "has space.com", "a/b.com", "a\\b.com", "a..b.com",
    ".lead.com", "trail.com.", "-lead.com", "trail-.com", "a?b=c.com", "a#b.com",
    "http://evil.com", "evil.com/../../etc", "a@b.com", "a:b.com", "emoji☃.com",
    "tab\t.com", "new\nline.com", None, 5, ["a.com"], b"a.com",
])
def test_target_id_rejects_non_canonical(pg, mod, slug):
    assert mod._valid_target_id(slug) is False


@pytest.mark.parametrize("h,ok", [
    ("a" * 64, True), ("0" * 64, True), (commit(), True),
    ("A" * 64, False), ("a" * 63, False), ("a" * 65, False), ("g" * 64, False),
    ("", False), ("0x" + "a" * 62, False), (None, False), (12, False),
])
def test_hash_validation(pg, mod, h, ok):
    assert mod._valid_hash(h) is ok


@pytest.mark.parametrize("label,ok", [
    ("permit2-airdrop-2026q4", True), ("uniswap", True), ("a_b-c", True), ("x" * 64, True),
    ("", False), ("x" * 65, False), ("Has.Dot", False), ("sp ace", False), ("a/b", False), (None, False),
])
def test_label_validation(pg, mod, label, ok):
    assert mod._valid_label(label) is ok


@pytest.mark.parametrize("op,ok", [
    ("github.com", True), ("jsdelivr.com", True), ("cert.example.org", True),
    ("nodot", False), ("", False), ("a.", False), (".a", False), ("UP.com", False), ("a b.com", False),
    (None, False), ("x" * 65 + ".com", False),
])
def test_operator_validation(pg, mod, op, ok):
    assert mod._valid_operator(op) is ok


GOOD = "https://raw.githubusercontent.com/SOBEK96/PhishGuard/abc123/deployments/mock_feeds/a/"


@pytest.mark.parametrize("url,host", [
    (GOOD, "raw.githubusercontent.com"),
    ("https://cdn.jsdelivr.net/gh/SOBEK96/PhishGuard@abc/deployments/mock_feeds/b/", "cdn.jsdelivr.net"),
    ("https://raw.githack.com/SOBEK96/PhishGuard/abc/x/", "raw.githack.com"),
    ("https://feeds.cert.example.org/v1/", "feeds.cert.example.org"),
])
def test_feed_host_accepts_https_roots(pg, mod, url, host):
    assert mod._feed_host(url) == host


@pytest.mark.parametrize("url", [
    "http://raw.githubusercontent.com/x/",              # not https
    "ftp://raw.githubusercontent.com/x/",
    "https://raw.githubusercontent.com/x",               # missing trailing slash
    "https://raw.githubusercontent.com:8443/x/",         # explicit port
    "https://user:pw@raw.githubusercontent.com/x/",      # credentials
    "https://raw.githubusercontent.com/x/?q=1",          # query
    "https://raw.githubusercontent.com/x/#frag",         # fragment
    "https://localhost/x/",                              # no dot
    "https://127.0.0.1/x/",                              # IP literal
    "https://10.0.0.5/x/",
    "https://192.168.1.1/x/",
    "https://printer.local/x/",                          # private suffix
    "https://svc.internal/x/",
    "https://evil.localhost/x/",
    "https://RAW.GITHUBUSERCONTENT.COM/x/",              # not lowercase
    "https://exa mple.com/x/",                           # whitespace
    "https://a..b.com/x/",
    "", "https://", "x/", None, 12,
    "https://" + "a" * 300 + ".com/",                    # too long
])
def test_feed_host_rejects_unsafe_roots(pg, mod, url):
    assert mod._feed_host(url) == ""


def test_commitment_is_domain_separated(pg, mod):
    base = mod._commitment(TARGET, "c1", "b1", 100)
    assert base == commit(TARGET, "c1", "b1", 100)
    assert mod._commitment(TARGET, "c1", "b1", 101) != base
    assert mod._commitment(TARGET, "c2", "b1", 100) != base
    assert mod._commitment(TARGET, "c1", "b2", 100) != base
    assert mod._commitment("other.com", "c1", "b1", 100) != base
    # field-boundary ambiguity must not collide
    assert mod._commitment("a.com", "bc", "d", 1) != mod._commitment("a.com", "b", "cd", 1)


def test_commitment_is_lowercase_hex_sha256(pg, mod):
    h = mod._commitment(TARGET, "c", "b", 1)
    assert len(h) == 64 and h == h.lower() and int(h, 16) >= 0


# --- record parsing -----------------------------------------------------------
def test_parse_record_roundtrip(pg, mod):
    r = mod._parse_record(rec(), TARGET)
    assert r["tier"] == 2 and r["status"] == "ACTIVE" and r["published_ts"] == PUBLISHED
    assert r["first_seen_ts"] == FIRST_SEEN and r["hash"] == commit()


def _mut(**kw):
    r = rec()
    r.update(kw)
    return r


@pytest.mark.parametrize("bad", [
    _mut(target_id="other.com"),            # served the wrong target's record
    _mut(tier=3), _mut(tier=-1), _mut(tier="2"), _mut(tier=True), _mut(tier=1.5), _mut(tier=None),
    _mut(status="PENDING"), _mut(status=None), _mut(status="active"),
    _mut(evidence_hash="xyz"), _mut(evidence_hash=""), _mut(evidence_hash="A" * 64),
    _mut(published_ts=0), _mut(published_ts=-5), _mut(published_ts="1"), _mut(published_ts=True),
    _mut(published_ts=5_000_000_000), _mut(first_seen_ts=-1), _mut(first_seen_ts="0"),
    _mut(campaign_id=None), _mut(campaign_id="x" * 65), _mut(brand_id=7), _mut(brand_id="x" * 65),
])
def test_parse_record_rejects_schema_violations(pg, mod, bad):
    assert mod._parse_record(bad, TARGET) is None


@pytest.mark.parametrize("not_a_dict", [[], "x", 5, None, [rec()]])
def test_parse_record_rejects_non_objects(pg, mod, not_a_dict):
    assert mod._parse_record(not_a_dict, TARGET) is None


def test_parse_record_missing_keys(pg, mod):
    for key in ("target_id", "tier", "status", "evidence_hash", "published_ts", "first_seen_ts",
                "campaign_id", "brand_id"):
        r = rec()
        del r[key]
        assert mod._parse_record(r, TARGET) is None, key


# --- HTTP -> source mapping ---------------------------------------------------
def body(**kw):
    return json.dumps(_mut(**kw)).encode()


@pytest.mark.parametrize("status,kind", [
    (404, "NOT_FOUND"), (410, "NOT_FOUND"),
    (500, "OUTAGE"), (502, "OUTAGE"), (503, "OUTAGE"), (504, "OUTAGE"), (429, "OUTAGE"),
    (301, "OUTAGE"), (302, "OUTAGE"), (403, "OUTAGE"), (401, "OUTAGE"), (400, "OUTAGE"),
    (None, "OUTAGE"), (204, "OUTAGE"),
])
def test_status_mapping(pg, mod, status, kind):
    assert mod._source_from_response(status, body(), TARGET)["k"] == kind


def test_200_valid_is_ok(pg, mod):
    s = mod._source_from_response(200, body(), TARGET)
    assert s["k"] == "OK" and s["rec"]["tier"] == 2


@pytest.mark.parametrize("raw", [b"{not json", b"", b"null", b"[]", b"<html></html>", b"\xff\xfe", None, 12])
def test_200_garbage_is_outage_not_404(pg, mod, raw):
    assert mod._source_from_response(200, raw, TARGET)["k"] == "OUTAGE"


def test_oversized_body_is_outage(pg, mod):
    big = json.dumps({**rec(), "pad": "x" * 9000}).encode()
    assert mod._source_from_response(200, big, TARGET)["k"] == "OUTAGE"


def test_str_body_is_accepted(pg, mod):
    assert mod._source_from_response(200, json.dumps(rec()), TARGET)["k"] == "OK"
