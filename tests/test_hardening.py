"""Regression tests for the audit findings P01-P03, P06 (+ typecheck parity).

`send()` asserts the strict ledger invariants after every write:
  reserved_bounty == sum(target.bounty_reserved)  and  held_bonds == sum(target.bond_held)
"""

import pytest

from tests.conftest import (
    BOND, BOUNTY, DAY, FIRST_SEEN, MAX_TS, NOW, PUBLISHED, REVISED, TARGET,
    assert_accounting, commit, hexof, mock_feeds, rec, report, send,
)

REM = dict(tier=0, status="REMEDIATED", published=REVISED)
FP = dict(tier=0, status="FALSE_POSITIVE_REVOKED", published=REVISED)


def blacklist(vm, c, who, target=TARGET, campaign="permit2-airdrop-2026q4", **kw):
    r = rec(target=target, campaign=campaign, **kw)
    mock_feeds(vm, r, r, r)
    return report(vm, c, who, target=target, campaign=campaign)


# =============================================================================
# P01 - stranded reserved bounty after REMEDIATED + re-report
# =============================================================================
def test_remediated_then_rereported_target_never_strands_reserved_bounty(vm, funded, direct_alice, direct_bob, direct_charlie):
    blacklist(vm, funded, direct_alice)
    assert funded.get_pool_state()["reserved_bounty"] == str(BOUNTY)

    r = rec(**REM)
    mock_feeds(vm, r, r, r)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "REMEDIATED"
    assert funded.get_target_status(TARGET)["bounty_reserved"] == str(BOUNTY)  # still vesting for alice

    # A DIFFERENT reporter re-reports the same domain with another campaign. The
    # remediation feeds do not corroborate it -> DISMISSED, record replaced.
    mock_feeds(vm, r, r, r)
    out = report(vm, funded, direct_charlie, campaign="another-campaign")
    assert out == "DISMISSED"

    p = funded.get_pool_state()
    assert p["reserved_bounty"] == "0"                      # nothing stranded
    a = hexof(funded, vm, direct_alice)
    assert funded.claimable_of(a) == str(BOND + BOUNTY)     # bond (at appeal) + settled bounty
    assert p["solvent"] is True
    assert send(vm, funded, direct_alice, funded.claim_payout) == str(BOND + BOUNTY)


def test_rereport_that_verifies_settles_prior_and_reserves_new_bounty(vm, funded, direct_alice, direct_bob, direct_charlie):
    blacklist(vm, funded, direct_alice)
    r = rec(**REM)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    # the drainer comes back: fresh ACTIVE record, newer than the remediation
    again = rec(tier=2, campaign="relapse-2026q4", published=NOW - DAY)
    mock_feeds(vm, again, again, again)
    assert report(vm, funded, direct_charlie, campaign="relapse-2026q4") == "BLACKLISTED"
    t = funded.get_target_status(TARGET)
    assert t["reporter"] == hexof(funded, vm, direct_charlie)
    assert t["bounty_reserved"] == str(BOUNTY)
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == str(BOND + BOUNTY)
    assert funded.get_pool_state()["reserved_bounty"] == str(BOUNTY)  # exactly the NEW reservation


def test_override_active_path_also_settles_prior_reservation(vm, funded, direct_alice, direct_bob, direct_charlie):
    blacklist(vm, funded, direct_alice)
    r = rec(**REM)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    stale = rec(tier=2, campaign="stale-replay", published=PUBLISHED - 1)  # older than the override
    mock_feeds(vm, stale, stale, stale)
    assert report(vm, funded, direct_charlie, campaign="stale-replay") == "FALSE_POSITIVE_OVERRIDE_ACTIVE"
    assert funded.get_pool_state()["reserved_bounty"] == "0"
    assert funded.get_target_status(TARGET)["bounty_reserved"] == "0"
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == str(BOND + BOUNTY)


def test_fp_revocation_then_rereport_keeps_ledger_exact(vm, funded, direct_alice, direct_bob, direct_charlie):
    blacklist(vm, funded, direct_alice)
    r = rec(**FP)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    fresh = rec(tier=2, campaign="new-wave", published=NOW - DAY)
    mock_feeds(vm, fresh, fresh, fresh)
    assert report(vm, funded, direct_charlie, campaign="new-wave") == "BLACKLISTED"
    assert funded.get_pool_state()["reserved_bounty"] == str(BOUNTY)


def test_ledger_invariant_survives_a_mixed_sequence(vm, funded, direct_alice, direct_bob, direct_charlie):
    blacklist(vm, funded, direct_alice, target="one-drain.com", campaign="c-one")
    blacklist(vm, funded, direct_bob, target="two-drain.com", campaign="c-two")
    r = rec(target="one-drain.com", campaign="c-one", **REM)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_charlie, funded.appeal_classification, "one-drain.com", value=BOND)
    vm.warp("2026-10-16T00:00:01Z")
    send(vm, funded, direct_bob, funded.claim_settlement, "two-drain.com")
    mock_feeds(vm, "404", "404", "404")
    report(vm, funded, direct_charlie, target="one-drain.com", campaign="c-x")
    assert_accounting(funded)


# =============================================================================
# P02 - future-dated feed timestamps
# =============================================================================
def _mut(**kw):
    r = rec()
    r.update(kw)
    return r


def test_future_published_ts_in_remediation_or_report_is_rejected_as_invalid(vm, funded, direct_alice, direct_bob, mod):
    # unit level: ceiling is now + MAX_CLOCK_SKEW, inclusive
    assert mod._parse_record(_mut(published_ts=MAX_TS), TARGET, MAX_TS) is not None
    assert mod._parse_record(_mut(published_ts=MAX_TS + 1), TARGET, MAX_TS) is None
    assert mod._parse_record(_mut(first_seen_ts=MAX_TS + 1), TARGET, MAX_TS) is None
    assert mod._source_from_response(200, __import__("json").dumps(_mut(published_ts=4_000_000_000)), TARGET, MAX_TS)["k"] == "OUTAGE"

    # flow level: a future-dated remediation is an OUTAGE -> QUORUM_FAILURE, nothing changes
    blacklist(vm, funded, direct_alice)
    poisoned = rec(tier=0, status="FALSE_POSITIVE_REVOKED", published=4_000_000_000)
    mock_feeds(vm, poisoned, poisoned, poisoned)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "QUORUM_FAILURE"
    t = funded.get_target_status(TARGET)
    assert t["status"] == "BLACKLISTED" and t["override_ts"] == 0
    assert funded.claimable_of(hexof(funded, vm, direct_bob)) == str(BOND)


def test_future_dated_report_record_is_not_corroboration(vm, funded, direct_alice):
    future = rec(tier=2, published=NOW + 10 * DAY)
    mock_feeds(vm, future, future, future)
    assert report(vm, funded, direct_alice) == "QUORUM_FAILURE"
    assert funded.get_target_count() == 0


def test_remediation_within_skew_is_accepted(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    near = rec(tier=0, status="REMEDIATED", published=NOW + 1800)
    mock_feeds(vm, near, near, near)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "REMEDIATED"


def test_genuine_report_after_sane_remediation_is_not_locked_out(vm, funded, direct_alice, direct_bob, direct_charlie):
    blacklist(vm, funded, direct_alice)
    r = rec(**REM)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    back = rec(tier=2, campaign="back-again", published=NOW - 3600)
    mock_feeds(vm, back, back, back)
    assert report(vm, funded, direct_charlie, campaign="back-again") == "BLACKLISTED"


# =============================================================================
# P03 - dynamic epoch cap
# =============================================================================
def test_funding_empty_pool_mid_epoch_updates_epoch_bounty_cap(vm, pg, direct_alice, direct_bob, direct_charlie):
    assert blacklist(vm, pg, direct_alice, target="first-drain.com", campaign="camp-1") == "BLACKLISTED"
    assert pg.get_target_status("first-drain.com")["bounty_reserved"] == "0"
    assert pg.get_pool_state()["epoch_cap"] == "0"          # frozen at 0 by the empty-pool attempt

    send(vm, pg, direct_bob, pg.fund_bounty_pool, value=10**18)  # 1 GEN mid-epoch
    assert pg.get_pool_state()["epoch_cap"] == str(2 * 10**17)   # +20 % of the deposit

    assert blacklist(vm, pg, direct_charlie, target="second-drain.com", campaign="camp-2") == "BLACKLISTED"
    assert pg.get_target_status("second-drain.com")["bounty_reserved"] == str(BOUNTY)


def test_cap_tracks_each_topup_in_the_epoch(vm, pg, direct_alice, direct_bob):
    blacklist(vm, pg, direct_alice, target="seed-drain.com", campaign="seed-camp")
    send(vm, pg, direct_bob, pg.fund_bounty_pool, value=10**17)
    send(vm, pg, direct_bob, pg.fund_bounty_pool, value=3 * 10**17)
    assert pg.get_pool_state()["epoch_cap"] == str(8 * 10**16)  # 20 % of 0.4 GEN


def test_deposit_then_withdraw_cannot_inflate_the_cap(vm, pg, direct_alice, direct_bob):
    blacklist(vm, pg, direct_alice, target="seed-drain.com", campaign="seed-camp")  # creates the epoch cap (0)
    send(vm, pg, direct_bob, pg.fund_bounty_pool, value=10**18)
    shares = int(pg.shares_of(hexof(pg, vm, direct_bob)))
    send(vm, pg, direct_bob, pg.withdraw_pool_shares, shares)
    p = pg.get_pool_state()
    assert int(p["epoch_cap"]) <= 2 * 10**17 * (1000) // (10**18)  # back to ~dust, not 0.2 GEN


def test_cap_never_drops_below_amount_already_paid(vm, pg, direct_owner, direct_alice, direct_bob):
    send(vm, pg, direct_owner, pg.fund_bounty_pool, value=5 * 10**17)
    blacklist(vm, pg, direct_alice, target="paid-drain.com", campaign="paid-camp")
    assert pg.get_pool_state()["epoch_paid"] == str(BOUNTY)
    shares = int(pg.shares_of(hexof(pg, vm, direct_owner)))
    send(vm, pg, direct_owner, pg.withdraw_pool_shares, shares)
    assert int(pg.get_pool_state()["epoch_cap"]) >= BOUNTY


# =============================================================================
# P06 - subdomain hierarchy
# =============================================================================
PARENT = "evil-drainer.com"


def _list(vm, c, who, target, tier=2, campaign=None):
    camp = campaign or f"camp-{target.replace('.', '-')}"
    r = rec(target=target, tier=tier, campaign=camp)
    mock_feeds(vm, r, r, r)
    return report(vm, c, who, target=target, campaign=camp)


@pytest.mark.parametrize("sub", ["app.evil-drainer.com", "claim.app.evil-drainer.com", "a.b.c.evil-drainer.com"])
def test_subdomain_inherits_parent_domain_blacklist_and_quarantine_status(vm, funded, direct_alice, sub):
    assert _list(vm, funded, direct_alice, PARENT, tier=2) == "BLACKLISTED"
    c = funded.check_transaction_safety(sub)
    assert c["verdict"] == "BLOCK" and c["blocked"] is True and c["tier"] == 2
    assert c["inherited"] is True and c["matched_target"] == PARENT and c["known"] is True
    with vm.expect_revert("ERR_TARGET_BLOCKED"):
        funded.assert_target_safe(sub)
    s = funded.get_target_status(sub)
    assert s["known"] is False                       # no exact record ...
    assert s["effective_status"] == "BLACKLISTED" and s["effective_from"] == PARENT and s["inherited"] is True


def test_quarantined_parent_warns_for_subdomains(vm, funded, direct_alice):
    assert _list(vm, funded, direct_alice, PARENT, tier=1) == "QUARANTINED"
    c = funded.check_transaction_safety("login.evil-drainer.com")
    assert c["verdict"] == "WARN" and c["inherited"] is True
    assert funded.assert_target_safe("login.evil-drainer.com") == "WARN"


def test_exact_match_still_wins_when_stricter(vm, funded, direct_alice, direct_bob):
    _list(vm, funded, direct_alice, PARENT, tier=1)                  # parent: quarantined
    _list(vm, funded, direct_bob, "pay.evil-drainer.com", tier=2)    # child: blacklisted
    c = funded.check_transaction_safety("pay.evil-drainer.com")
    assert c["verdict"] == "BLOCK" and c["inherited"] is False and c["matched_target"] == "pay.evil-drainer.com"


def test_safe_parent_does_not_make_subdomain_safe(vm, funded, direct_alice, direct_bob):
    mock_feeds(vm, "404", "404", "404")
    assert report(vm, funded, direct_alice, target=PARENT, campaign="nothing") == "DISMISSED"  # parent: tier 0
    assert _list(vm, funded, direct_bob, "x.evil-drainer.com", tier=2) == "BLACKLISTED"
    assert funded.check_transaction_safety("x.evil-drainer.com")["verdict"] == "BLOCK"
    assert funded.check_transaction_safety("y.evil-drainer.com")["verdict"] == "ALLOW"  # parent safe != listed


def test_label_boundary_is_respected(vm, funded, direct_alice):
    _list(vm, funded, direct_alice, PARENT, tier=2)
    for other in ("notevil-drainer.com", "evil-drainer.com.other.org", "evil-drainer.co", "drainer.com"):
        c = funded.check_transaction_safety(other)
        assert c["verdict"] == "ALLOW" and c["inherited"] is False, other


def test_public_suffix_listing_is_never_inherited(vm, funded, direct_alice):
    assert _list(vm, funded, direct_alice, "co.uk", tier=2) == "BLACKLISTED"
    assert funded.check_transaction_safety("bank.co.uk")["verdict"] == "ALLOW"
    assert funded.check_transaction_safety("co.uk")["verdict"] == "BLOCK"  # exact only


def test_multi_tenant_host_listing_is_not_inherited(vm, funded, direct_alice):
    assert _list(vm, funded, direct_alice, "github.io", tier=2) == "BLACKLISTED"
    assert funded.check_transaction_safety("honest-user.github.io")["verdict"] == "ALLOW"
    assert _list(vm, funded, direct_alice, "scam.github.io", tier=2) == "BLACKLISTED"
    assert funded.check_transaction_safety("deep.scam.github.io")["verdict"] == "BLOCK"


def test_revoked_parent_stops_covering_subdomains(vm, funded, direct_alice, direct_bob):
    _list(vm, funded, direct_alice, PARENT, tier=2)
    fp = rec(target=PARENT, campaign="camp-evil-drainer-com", **FP)
    mock_feeds(vm, fp, fp, fp)
    send(vm, funded, direct_bob, funded.appeal_classification, PARENT, value=BOND)
    assert funded.check_transaction_safety("app.evil-drainer.com")["verdict"] == "ALLOW"


@pytest.mark.parametrize("host,chain", [
    ("evil.com", []),
    ("a.evil.com", ["evil.com"]),
    ("a.b.evil.com", ["b.evil.com", "evil.com"]),
    ("shop.evil.co.uk", ["evil.co.uk"]),
    ("evil.co.uk", []),
    ("x.y.scam.github.io", ["y.scam.github.io", "scam.github.io"]),
    ("localhost-ish", []),
    ("0xdeadbeef", []),
])
def test_parent_chain(pg, mod, host, chain):
    assert mod._parent_chain(host) == chain


def test_unlisted_unrelated_host_is_unknown_not_safe(vm, funded):
    c = funded.check_transaction_safety("never-seen.org")
    assert c["known"] is False and c["verdict"] == "ALLOW" and c["matched_target"] == ""
