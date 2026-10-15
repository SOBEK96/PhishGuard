"""Shared fixtures + helpers for PhishGuard direct-mode tests.

Direct mode runs the contract in-process against the GenVM v0.3 runner. The
runner bundle is pinned here so the suite never depends on whichever GenVM
release happens to be newest.
"""

import calendar
import hashlib
import json
import os
import sys
import time

os.environ.setdefault("GENVM_VERSION", "v0.6.0-rc7")

import pytest  # noqa: E402

CONTRACT = "contracts/phish_guard.py"
ATTO = 10**18
BOND = 10**16
BOUNTY = 2 * 10**16
DAY = 86400

URL_A = "https://raw.githubusercontent.com/SOBEK96/PhishGuard/0123456789abcdef0123456789abcdef01234567/deployments/mock_feeds/a/"
URL_B = "https://cdn.jsdelivr.net/gh/SOBEK96/PhishGuard@0123456789abcdef0123456789abcdef01234567/deployments/mock_feeds/b/"
URL_C = "https://raw.githack.com/SOBEK96/PhishGuard/0123456789abcdef0123456789abcdef01234567/deployments/mock_feeds/c/"
OP_A, OP_B, OP_C = "github.com", "jsdelivr.com", "githack.com"

# 2026-10-15T00:00:00Z -- every fixture timestamp below is earlier.
NOW = calendar.timegm(time.strptime("2026-10-15", "%Y-%m-%d"))
NOW_ISO = "2026-10-15T00:00:00Z"
FIRST_SEEN = NOW - 20 * DAY
PUBLISHED = NOW - 10 * DAY
REVISED = NOW - 5 * DAY

TARGET = "uniswap-claim-airdrop.com"
CAMPAIGN = "permit2-airdrop-2026q4"
BRAND = "uniswap"


def commit(target=TARGET, campaign=CAMPAIGN, brand=BRAND, first_seen=FIRST_SEEN) -> str:
    return hashlib.sha256(f"phishguard.v1|{target}|{campaign}|{brand}|{first_seen}".encode()).hexdigest()


def rec(target=TARGET, tier=2, status="ACTIVE", published=PUBLISHED, campaign=CAMPAIGN,
        brand=BRAND, first_seen=FIRST_SEEN, ev=None):
    return {
        "target_id": target,
        "tier": tier,
        "status": status,
        "campaign_id": campaign,
        "brand_id": brand,
        "first_seen_ts": first_seen,
        "published_ts": published,
        "evidence_hash": ev if ev is not None else commit(target, campaign, brand, first_seen),
    }


def resp(kind):
    """Map a symbolic feed answer to a mocked HTTP response."""
    if isinstance(kind, dict):
        return {"status": 200, "body": json.dumps(kind)}
    if kind == "404":
        return {"status": 404, "body": "not found"}
    if kind == "500":
        return {"status": 500, "body": "boom"}
    if kind == "503":
        return {"status": 503, "body": ""}
    if kind == "429":
        return {"status": 429, "body": "slow down"}
    if kind == "badjson":
        return {"status": 200, "body": "{not json"}
    if kind == "html":
        return {"status": 200, "body": "<html>captcha</html>"}
    raise ValueError(kind)


def mock_feeds(vm, a, b, c):
    """Mock the three governed hosts independently. a/b/c: record dict | '404' | '500' | ..."""
    vm.clear_mocks()
    vm.mock_web(r"raw\.githubusercontent\.com/", resp(a))
    vm.mock_web(r"cdn\.jsdelivr\.net/", resp(b))
    vm.mock_web(r"raw\.githack\.com/", resp(c))


def contract_balance(c) -> int:
    return int(c.get_pool_state()["balance"])


def send(vm, c, who, fn, *args, value=0):
    """Call `fn` as `who`, crediting `value` to the contract balance first (direct
    mode does not move native value on its own)."""
    vm.sender = who
    if value:
        vm.deal(vm._contract_address, contract_balance(c) + value)
    vm.value = value
    try:
        return fn(*args)
    finally:
        vm.value = 0


def hexof(c, vm, who) -> str:
    prev = vm.sender
    vm.sender = who
    try:
        return c.whoami()
    finally:
        vm.sender = prev


def pool(c) -> dict:
    return c.get_pool_state()


def contract_module():
    return sys.modules["_contract_phish_guard"]


@pytest.fixture
def vm(direct_vm):
    direct_vm.warp(NOW_ISO)
    return direct_vm


@pytest.fixture
def pg(vm, direct_deploy, direct_owner):
    """A deployed PhishGuard, deployer == governor, with brands registered."""
    vm.sender = direct_owner
    c = direct_deploy(CONTRACT, URL_A, OP_A, URL_B, OP_B, URL_C, OP_C)
    for brand, domain in [
        ("uniswap", "app.uniswap.org"), ("opensea", "opensea.io"), ("rabby", "rabby.io"),
        ("aave", "app.aave.com"), ("lido", "stake.lido.fi"), ("curve", "curve.fi"),
    ]:
        c.register_brand(brand, domain)
    return c


@pytest.fixture
def funded(vm, pg, direct_owner):
    """pg with a 0.5 GEN bounty pool seeded by the governor."""
    send(vm, pg, direct_owner, pg.fund_bounty_pool, value=5 * 10**17)
    return pg


@pytest.fixture
def mod(pg):
    return contract_module()


def report(vm, c, who, target=TARGET, campaign=CAMPAIGN, brand=BRAND, first_seen=FIRST_SEEN,
           value=BOND, ev=None):
    h = ev if ev is not None else commit(target, campaign, brand, first_seen)
    return send(vm, c, who, c.report_target, target, h, campaign, brand, first_seen, value=value)
