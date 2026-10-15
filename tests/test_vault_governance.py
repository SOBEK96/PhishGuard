"""Vault share accounting, slash-reserve recycling, feed-rotation governance,
brand registry, and static invariants (zero floats, no governor drain)."""

import ast
import pathlib

import pytest

from tests.conftest import (
    BOND, BOUNTY, DAY, NOW, TARGET, hexof, mock_feeds, rec, report, send,
)

SRC = pathlib.Path(__file__).resolve().parents[1] / "contracts" / "phish_guard.py"
NEW_HOST_A = "https://cdn.statically.io/gh/SOBEK96/PhishGuard/9999999999999999999999999999999999999999/a/"
NEW_HOST_B = "https://gitcdn.link/repo/SOBEK96/PhishGuard/9999999999999999999999999999999999999999/b/"


def blacklist(vm, c, who, target=TARGET, campaign="permit2-airdrop-2026q4"):
    r = rec(target=target, campaign=campaign)
    mock_feeds(vm, r, r, r)
    return report(vm, c, who, target=target, campaign=campaign)


# =============================================================================
# Bounty vault
# =============================================================================
def test_first_deposit_mints_shares_minus_dead_floor(vm, pg, direct_alice):
    minted = send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**17)
    assert int(minted) == 10**17 - 1000
    p = pg.get_pool_state()
    assert p["total_shares"] == str(10**17) and p["bounty_pool"] == str(10**17)
    assert pg.shares_of(hexof(pg, vm, direct_alice)) == minted


def test_deposit_below_minimum_reverts(vm, pg, direct_alice):
    with vm.expect_revert("minimum pool deposit"):
        send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**15 - 1)


def test_second_depositor_gets_proportional_shares(vm, pg, direct_alice, direct_bob):
    send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**17)
    minted = int(send(vm, pg, direct_bob, pg.fund_bounty_pool, value=10**17))
    # equal deposit into an unchanged pool -> ~equal shares (virtual offset rounds slightly)
    assert abs(minted - (10**17 - 1000)) < 10**15


def test_withdraw_returns_pro_rata_assets(vm, pg, direct_alice):
    send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**17)
    shares = int(pg.shares_of(hexof(pg, vm, direct_alice)))
    out = int(send(vm, pg, direct_alice, pg.withdraw_pool_shares, shares // 2))
    assert out == shares // 2 * 10**17 // 10**17
    assert pg.claimable_of(hexof(pg, vm, direct_alice)) == str(out)


def test_withdraw_more_than_owned_reverts(vm, pg, direct_alice, direct_bob):
    send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**17)
    with vm.expect_revert("invalid share amount"):
        send(vm, pg, direct_bob, pg.withdraw_pool_shares, 1)
    with vm.expect_revert("invalid share amount"):
        send(vm, pg, direct_alice, pg.withdraw_pool_shares, 10**30)
    with vm.expect_revert("invalid share amount"):
        send(vm, pg, direct_alice, pg.withdraw_pool_shares, 0)


def test_last_contributor_cannot_orphan_reserved_capital(vm, pg, direct_alice, direct_bob):
    send(vm, pg, direct_alice, pg.fund_bounty_pool, value=5 * 10**17)
    blacklist(vm, pg, direct_bob)
    assert pg.get_target_status(TARGET)["bounty_reserved"] == str(BOUNTY)
    shares = int(pg.shares_of(hexof(pg, vm, direct_alice)))
    send(vm, pg, direct_alice, pg.withdraw_pool_shares, shares)  # exit everything
    p = pg.get_pool_state()
    assert p["reserved_bounty"] == str(BOUNTY)         # untouched
    assert p["held_bonds"] == str(BOND)                # untouched
    assert int(p["total_shares"]) >= 1000              # dead-share floor survives
    vm.warp("2026-10-16T00:00:00Z")
    assert send(vm, pg, direct_bob, pg.claim_settlement, TARGET) == str(BOND + BOUNTY)
    assert p["solvent"] is True


def test_withdraw_cannot_touch_slash_reserve(vm, pg, direct_alice, direct_bob):
    send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**17)
    mock_feeds(vm, "404", "404", "404")
    report(vm, pg, direct_bob)
    shares = int(pg.shares_of(hexof(pg, vm, direct_alice)))
    send(vm, pg, direct_alice, pg.withdraw_pool_shares, shares)
    assert pg.get_pool_state()["locked_slash_reserve"] == str(BOND)


def test_pool_can_never_be_fully_redeemed(vm, pg, direct_alice):
    send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**17)
    shares = int(pg.shares_of(hexof(pg, vm, direct_alice)))
    send(vm, pg, direct_alice, pg.withdraw_pool_shares, shares)
    p = pg.get_pool_state()
    assert p["total_shares"] == "1000" and int(p["bounty_pool"]) == 1000


def test_slashed_bonds_raise_share_price_after_recycle(vm, pg, direct_alice, direct_bob):
    send(vm, pg, direct_alice, pg.fund_bounty_pool, value=10**17)
    for i in range(12):  # 12 forfeited bonds -> 0.12 GEN, above the 0.1 GEN float
        mock_feeds(vm, "404", "404", "404")
        report(vm, pg, direct_bob, target=f"scam-report-{i}.com", campaign=f"c-{i}")
    reserve = int(pg.get_pool_state()["locked_slash_reserve"])
    assert reserve == 12 * BOND
    moved = int(send(vm, pg, direct_bob, pg.recycle_slash_reserve))
    assert moved == reserve - 10 * BOND
    p = pg.get_pool_state()
    assert p["locked_slash_reserve"] == str(10 * BOND)
    assert int(p["bounty_pool"]) == 10**17 + moved
    shares = int(pg.shares_of(hexof(pg, vm, direct_alice)))
    out = int(send(vm, pg, direct_alice, pg.withdraw_pool_shares, shares))
    assert out > 10**17 - 1000  # alice earned the recycled slashes


def test_recycle_reverts_at_or_below_floor(vm, pg, direct_alice):
    with vm.expect_revert("reserve at floor"):
        send(vm, pg, direct_alice, pg.recycle_slash_reserve)


def test_vault_stays_solvent_through_a_full_lifecycle(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    assert funded.get_pool_state()["solvent"] is True
    vm.warp("2026-10-16T00:00:00Z")
    send(vm, funded, direct_alice, funded.claim_settlement, TARGET)
    send(vm, funded, direct_alice, funded.claim_payout)
    assert funded.get_pool_state()["solvent"] is True


# =============================================================================
# Governance: feed rotation timelock + uniqueness
# =============================================================================
def test_only_governor_may_stage_feeds(vm, pg, direct_alice):
    with vm.expect_revert("ERR_UNAUTHORIZED"):
        send(vm, pg, direct_alice, pg.stage_feed, 0, NEW_HOST_A, "statically.io")


def test_stage_returns_ready_time_seven_days_out(vm, pg, direct_owner):
    ready = send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "statically.io")
    assert ready == NOW + 7 * DAY
    f = pg.get_feed_sources()[0]
    assert f["staged_host"] == "cdn.statically.io" and f["staged_ready_at"] == NOW + 7 * DAY
    assert f["host"] == "raw.githubusercontent.com"  # still active


def test_activation_blocked_during_timelock(vm, pg, direct_owner, direct_alice):
    send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "statically.io")
    with vm.expect_revert("ERR_TIMELOCK_ACTIVE"):
        send(vm, pg, direct_alice, pg.activate_feed, 0)
    vm.warp("2026-10-21T23:59:59Z")
    with vm.expect_revert("ERR_TIMELOCK_ACTIVE"):
        send(vm, pg, direct_alice, pg.activate_feed, 0)


def test_activation_succeeds_after_timelock_by_anyone(vm, pg, direct_owner, direct_alice):
    send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "statically.io")
    vm.warp("2026-10-22T00:00:00Z")
    send(vm, pg, direct_alice, pg.activate_feed, 0)
    f = pg.get_feed_sources()[0]
    assert f["host"] == "cdn.statically.io" and f["operator"] == "statically.io"
    assert f["staged_host"] == "" and f["staged_ready_at"] == 0


def test_activate_without_staging_reverts(vm, pg, direct_alice):
    with vm.expect_revert("nothing staged"):
        send(vm, pg, direct_alice, pg.activate_feed, 1)


def test_stage_rejects_host_used_by_another_active_slot(vm, pg, direct_owner):
    with vm.expect_revert("not unique"):
        send(vm, pg, direct_owner, pg.stage_feed, 0,
             "https://cdn.jsdelivr.net/gh/x/y@1/z/", "other-operator.org")  # slot B's host


def test_stage_rejects_operator_used_by_another_active_slot(vm, pg, direct_owner):
    with vm.expect_revert("not unique"):
        send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "jsdelivr.com")  # slot B's operator


def test_stage_rejects_collision_with_another_staged_slot(vm, pg, direct_owner):
    send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "statically.io")
    with vm.expect_revert("not unique"):
        send(vm, pg, direct_owner, pg.stage_feed, 1, NEW_HOST_A, "different-op.org")  # same host, staged
    with vm.expect_revert("not unique"):
        send(vm, pg, direct_owner, pg.stage_feed, 1, NEW_HOST_B, "statically.io")      # same operator, staged


def test_same_slot_may_be_repinned_on_same_host(vm, pg, direct_owner):
    ready = send(vm, pg, direct_owner, pg.stage_feed, 0,
                 "https://raw.githubusercontent.com/SOBEK96/PhishGuard/ffff/mock_feeds/a/", "github.com")
    assert ready == NOW + 7 * DAY


@pytest.mark.parametrize("url", [
    "http://cdn.statically.io/x/", "https://127.0.0.1/x/", "https://cdn.statically.io:444/x/",
    "https://cdn.statically.io/x", "https://localhost/x/", "https://u:p@cdn.statically.io/x/",
])
def test_stage_rejects_unsafe_urls(vm, pg, direct_owner, url):
    with vm.expect_revert("ERR_INVALID_FEED"):
        send(vm, pg, direct_owner, pg.stage_feed, 0, url, "statically.io")


def test_stage_rejects_bad_slot_and_operator(vm, pg, direct_owner):
    with vm.expect_revert("ERR_INVALID_PARAMS"):
        send(vm, pg, direct_owner, pg.stage_feed, 3, NEW_HOST_A, "statically.io")
    with vm.expect_revert("ERR_INVALID_FEED"):
        send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "NOT AN OPERATOR")


def test_cancel_staged_feed(vm, pg, direct_owner, direct_alice):
    send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "statically.io")
    with vm.expect_revert("ERR_UNAUTHORIZED"):
        send(vm, pg, direct_alice, pg.cancel_staged_feed, 0)
    send(vm, pg, direct_owner, pg.cancel_staged_feed, 0)
    vm.warp("2026-10-23T00:00:00Z")
    with vm.expect_revert("nothing staged"):
        send(vm, pg, direct_alice, pg.activate_feed, 0)


def test_rotated_feed_is_used_for_triage(vm, funded, direct_owner, direct_alice):
    send(vm, funded, direct_owner, funded.stage_feed, 0, NEW_HOST_A, "statically.io")
    vm.warp("2026-10-22T00:00:00Z")
    send(vm, funded, direct_alice, funded.activate_feed, 0)
    r = rec()
    vm.clear_mocks()
    vm.mock_web(r"cdn\.statically\.io/", {"status": 200, "body": __import__("json").dumps(r)})
    vm.mock_web(r"cdn\.jsdelivr\.net/", {"status": 200, "body": __import__("json").dumps(r)})
    vm.mock_web(r"raw\.githack\.com/", {"status": 404, "body": ""})
    assert report(vm, funded, direct_alice) == "BLACKLISTED"


def test_transfer_governor(vm, pg, direct_owner, direct_alice):
    send(vm, pg, direct_owner, pg.transfer_governor, hexof(pg, vm, direct_alice))
    assert pg.get_governor() == hexof(pg, vm, direct_alice)
    with vm.expect_revert("ERR_UNAUTHORIZED"):
        send(vm, pg, direct_owner, pg.stage_feed, 0, NEW_HOST_A, "statically.io")


def test_brand_registry(vm, pg, direct_owner, direct_alice):
    assert pg.get_brand("uniswap") == "app.uniswap.org"
    assert pg.get_brand("nobody") == ""
    with vm.expect_revert("ERR_UNAUTHORIZED"):
        send(vm, pg, direct_alice, pg.register_brand, "ens", "app.ens.domains")
    with vm.expect_revert("brand exists"):
        send(vm, pg, direct_owner, pg.register_brand, "uniswap", "other.uniswap.org")
    with vm.expect_revert("already official"):
        send(vm, pg, direct_owner, pg.register_brand, "ens", "app.uniswap.org")
    with vm.expect_revert("bad brand"):
        send(vm, pg, direct_owner, pg.register_brand, "Bad Brand", "app.ens.domains")
    send(vm, pg, direct_owner, pg.register_brand, "ens", "app.ens.domains")
    assert pg.get_brand("ens") == "app.ens.domains"


# =============================================================================
# Static invariants
# =============================================================================
def test_contract_source_has_no_float_literals_or_division():
    tree = ast.parse(SRC.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            assert not isinstance(node.value, float), f"float literal at line {node.lineno}"
        if isinstance(node, ast.BinOp):
            assert not isinstance(node.op, ast.Div), f"true division at line {node.lineno}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "float", f"float() call at line {node.lineno}"
        if isinstance(node, ast.AnnAssign) and isinstance(node.annotation, ast.Name):
            assert node.annotation.id != "float", f"float annotation at line {node.lineno}"
        if isinstance(node, ast.arg) and isinstance(node.annotation, ast.Name):
            assert node.annotation.id != "float", f"float parameter {node.arg}"


def _no_floats(obj, path="$"):
    if isinstance(obj, float):
        raise AssertionError(f"float at {path}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            assert isinstance(k, str), f"non-str key at {path}"
            _no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _no_floats(v, f"{path}[{i}]")


def test_every_view_is_float_free(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    for out in (
        funded.get_pool_state(), funded.get_feed_sources(), funded.get_target_status(TARGET),
        funded.get_target_status("never-seen.com"), funded.check_transaction_safety(TARGET),
        funded.get_target_count(), funded.get_brand("uniswap"), funded.claimable_of("0x0"),
    ):
        _no_floats(out)


def test_no_governor_value_extraction_surface():
    tree = ast.parse(SRC.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "PhishGuard")
    # Every public method that can move native value out of the contract.
    movers = []
    for fn in cls.body:
        if isinstance(fn, ast.FunctionDef):
            src = ast.get_source_segment(SRC.read_text(), fn) or ""
            if "emit_transfer" in src:
                movers.append(fn.name)
    assert movers == ["claim_payout"]  # the ONLY outflow, and it pays msg.sender its own claimable
    src = SRC.read_text()
    assert "drain" not in src.lower().replace("drainer", "")
    for fn in cls.body:
        if isinstance(fn, ast.FunctionDef) and fn.name.startswith("transfer"):
            assert fn.name == "transfer_governor"


def test_payout_goes_only_to_the_claimant():
    tree = ast.parse(SRC.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "PhishGuard")
    fn = next(f for f in cls.body if isinstance(f, ast.FunctionDef) and f.name == "claim_payout")
    text = ast.get_source_segment(SRC.read_text(), fn)
    assert "gl.chain.Account(gl.message.sender_address).emit_transfer(amount" in text


def test_public_surface_is_stable():
    tree = ast.parse(SRC.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "PhishGuard")
    names = set()
    for fn in cls.body:
        if isinstance(fn, ast.FunctionDef) and not fn.name.startswith("_"):
            names.add(fn.name)
    assert {"report_target", "appeal_classification", "check_transaction_safety", "assert_target_safe",
            "get_pool_state", "get_target_status", "get_feed_sources", "fund_bounty_pool",
            "claim_settlement", "claim_payout", "stage_feed", "activate_feed"} <= names
