"""Stateful end-to-end tests in GenVM direct mode (mocked threat-intel hosts)."""

import pytest

from tests.conftest import (
    BOND, BOUNTY, BRAND, CAMPAIGN, DAY, FIRST_SEEN, NOW, PUBLISHED, REVISED, TARGET,
    URL_A, URL_B, URL_C, OP_A, OP_B, OP_C, commit, contract_balance, hexof, mock_feeds, rec,
    report, send,
)

FP = dict(tier=0, status="FALSE_POSITIVE_REVOKED", published=REVISED)
REM = dict(tier=0, status="REMEDIATED", published=REVISED)


def drainer(**kw):
    return rec(tier=2, **kw)


def blacklist(vm, c, who, target=TARGET, campaign=CAMPAIGN, brand=BRAND):
    r = rec(target=target, campaign=campaign, brand=brand)
    mock_feeds(vm, r, r, r)
    return report(vm, c, who, target=target, campaign=campaign, brand=brand)


# =============================================================================
# Deployment / constructor invariants
# =============================================================================
def test_deploys_with_three_distinct_hosts_and_operators(pg):
    feeds = pg.get_feed_sources()
    assert [f["slot"] for f in feeds] == ["A", "B", "C"]
    assert len({f["host"] for f in feeds}) == 3
    assert len({f["operator"] for f in feeds}) == 3
    assert feeds[0]["host"] == "raw.githubusercontent.com"
    assert feeds[1]["host"] == "cdn.jsdelivr.net"
    assert feeds[2]["host"] == "raw.githack.com"


@pytest.mark.parametrize("urls,ops,needle", [
    ((URL_A, URL_A, URL_C), (OP_A, OP_B, OP_C), "distinct"),           # duplicate host
    ((URL_A, URL_B, URL_A), (OP_A, OP_B, OP_C), "distinct"),
    ((URL_A, URL_B, URL_C), (OP_A, OP_A, OP_C), "distinct"),           # duplicate operator
    ((URL_A, URL_B, URL_C), (OP_A, OP_B, OP_B), "distinct"),
    (("http://raw.githubusercontent.com/x/", URL_B, URL_C), (OP_A, OP_B, OP_C), "rejected"),
    ((URL_A, "https://127.0.0.1/x/", URL_C), (OP_A, OP_B, OP_C), "rejected"),
    ((URL_A, URL_B, "https://raw.githack.com/no-trailing-slash"), (OP_A, OP_B, OP_C), "rejected"),
    ((URL_A, URL_B, URL_C), (OP_A, "bad op", OP_C), "rejected"),
])
def test_constructor_rejects_unsafe_feed_sets(vm, direct_deploy, direct_owner, urls, ops, needle):
    vm.sender = direct_owner
    with pytest.raises(Exception) as ei:
        direct_deploy("contracts/phish_guard.py", urls[0], ops[0], urls[1], ops[1], urls[2], ops[2])
    assert "ERR_INVALID_FEED" in str(ei.value) and needle in str(ei.value)


def test_governor_is_deployer(vm, pg, direct_owner):
    assert pg.get_governor() == hexof(pg, vm, direct_owner)


def test_fresh_pool_state(pg):
    p = pg.get_pool_state()
    assert p["bounty_pool"] == "0" and p["locked_slash_reserve"] == "0" and p["solvent"] is True
    assert p["max_epoch_bounty_bps"] == 2000 and p["cooldown_window"] == DAY
    assert p["quarantine_watch"] == 2 * DAY and p["feed_timelock"] == 7 * DAY


# =============================================================================
# Reporting: tier 2 -> BLACKLISTED
# =============================================================================
def test_drainer_report_blacklists_and_reserves_bounty(vm, funded, direct_alice):
    assert blacklist(vm, funded, direct_alice) == "BLACKLISTED"
    t = funded.get_target_status(TARGET)
    assert t["status"] == "BLACKLISTED" and t["tier"] == 2 and t["tier_name"] == "TIER_2_DRAINER"
    assert t["bond_held"] == str(BOND) and t["bounty_reserved"] == str(BOUNTY)
    assert t["vest_at"] == NOW + DAY and t["source_count"] == 3 and t["published_ts"] == PUBLISHED
    p = funded.get_pool_state()
    assert p["reserved_bounty"] == str(BOUNTY) and p["held_bonds"] == str(BOND)
    assert int(p["bounty_pool"]) == 5 * 10**17 - BOUNTY and p["solvent"] is True


def test_claim_is_blocked_until_cooldown_ends(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    with vm.expect_revert("ERR_TIMELOCK_ACTIVE"):
        send(vm, funded, direct_alice, funded.claim_settlement, TARGET)
    vm.warp("2026-10-15T23:59:59Z")
    with vm.expect_revert("ERR_TIMELOCK_ACTIVE"):
        send(vm, funded, direct_alice, funded.claim_settlement, TARGET)


def test_claim_after_cooldown_pays_bond_plus_bounty(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    vm.warp("2026-10-16T00:00:00Z")
    out = send(vm, funded, direct_alice, funded.claim_settlement, TARGET)
    assert out == str(BOND + BOUNTY)
    a = hexof(funded, vm, direct_alice)
    assert funded.claimable_of(a) == str(BOND + BOUNTY)
    p = funded.get_pool_state()
    assert p["held_bonds"] == "0" and p["reserved_bounty"] == "0"
    assert funded.get_target_status(TARGET)["status"] == "BLACKLISTED"  # claiming never un-lists


def test_claim_payout_clears_balance(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    vm.warp("2026-10-16T00:00:00Z")
    send(vm, funded, direct_alice, funded.claim_settlement, TARGET)
    assert send(vm, funded, direct_alice, funded.claim_payout) == str(BOND + BOUNTY)
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == "0"
    with vm.expect_revert("ERR_NOTHING_TO_CLAIM"):
        send(vm, funded, direct_alice, funded.claim_payout)


def test_only_reporter_can_claim(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    vm.warp("2026-10-16T00:00:00Z")
    with vm.expect_revert("ERR_UNAUTHORIZED"):
        send(vm, funded, direct_bob, funded.claim_settlement, TARGET)


def test_double_claim_is_impossible(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    vm.warp("2026-10-16T00:00:00Z")
    send(vm, funded, direct_alice, funded.claim_settlement, TARGET)
    with vm.expect_revert("ERR_NOTHING_TO_CLAIM"):
        send(vm, funded, direct_alice, funded.claim_settlement, TARGET)


def test_blacklisted_target_cannot_be_re_reported(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    with vm.expect_revert("already blacklisted"):
        report(vm, funded, direct_bob)


def test_two_of_three_with_outage_still_blacklists(vm, funded, direct_alice):
    r = drainer()
    mock_feeds(vm, r, r, "500")
    assert report(vm, funded, direct_alice) == "BLACKLISTED"
    assert funded.get_target_status(TARGET)["source_count"] == 2


def test_two_of_three_with_lagging_404_blacklists(vm, funded, direct_alice):
    r = drainer()
    mock_feeds(vm, r, "404", r)
    assert report(vm, funded, direct_alice) == "BLACKLISTED"


def test_conservative_min_tier_on_split_two_sources(vm, funded, direct_alice):
    mock_feeds(vm, rec(tier=1), rec(tier=2), "404")
    assert report(vm, funded, direct_alice) == "QUARANTINED"
    assert funded.get_target_status(TARGET)["tier"] == 1


def test_median_tier_on_three_sources(vm, funded, direct_alice):
    mock_feeds(vm, rec(tier=1), rec(tier=2), rec(tier=2))
    assert report(vm, funded, direct_alice) == "BLACKLISTED"


# =============================================================================
# Reporting: tier 1 quarantine + re-evaluation
# =============================================================================
def test_tier1_quarantines_with_full_bond_refund(vm, funded, direct_alice):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_alice) == "QUARANTINED"
    t = funded.get_target_status(TARGET)
    assert t["quarantine_until"] == NOW + 2 * DAY and t["bond_held"] == "0" and t["bounty_reserved"] == "0"
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == str(BOND)  # 0 slash, 0 bounty
    assert funded.get_pool_state()["locked_slash_reserve"] == "0"


def test_quarantined_target_rejects_rereport_during_watch(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    with vm.expect_revert("under quarantine watch"):
        report(vm, funded, direct_bob)


def test_reevaluate_blocked_before_watch_elapses(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    with vm.expect_revert("ERR_TIMELOCK_ACTIVE"):
        send(vm, funded, direct_bob, funded.reevaluate_target, TARGET)


def test_after_watch_rereport_demands_reevaluation(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    vm.warp("2026-10-17T00:00:01Z")
    with vm.expect_revert("call reevaluate_target"):
        report(vm, funded, direct_bob)


def test_reevaluate_escalates_to_blacklist(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    vm.warp("2026-10-17T00:00:01Z")
    up = rec(tier=2, published=REVISED)
    mock_feeds(vm, up, up, up)
    assert send(vm, funded, direct_bob, funded.reevaluate_target, TARGET) == "BLACKLISTED"
    t = funded.get_target_status(TARGET)
    assert t["status"] == "BLACKLISTED" and t["tier"] == 2
    assert t["bounty_reserved"] == str(BOUNTY)  # original reporter earns the bounty


def test_reevaluate_clears_when_feeds_say_safe(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    vm.warp("2026-10-17T00:00:01Z")
    safe = rec(tier=0, published=REVISED)
    mock_feeds(vm, safe, safe, safe)
    assert send(vm, funded, direct_bob, funded.reevaluate_target, TARGET) == "CLEARED"
    assert funded.check_transaction_safety(TARGET)["verdict"] == "ALLOW"


def test_reevaluate_renews_watch_if_still_tier1(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    vm.warp("2026-10-17T00:00:01Z")
    assert send(vm, funded, direct_bob, funded.reevaluate_target, TARGET) == "QUARANTINED"
    assert funded.get_target_status(TARGET)["quarantine_until"] > NOW + 2 * DAY


def test_reevaluate_quorum_failure_changes_nothing(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    vm.warp("2026-10-17T00:00:01Z")
    mock_feeds(vm, r, "404", "500")
    assert send(vm, funded, direct_bob, funded.reevaluate_target, TARGET) == "QUORUM_FAILURE"
    assert funded.get_target_status(TARGET)["status"] == "QUARANTINED"


def test_reevaluate_requires_quarantined_target(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    with vm.expect_revert("not quarantined"):
        send(vm, funded, direct_alice, funded.reevaluate_target, TARGET)
    with vm.expect_revert("unknown target"):
        send(vm, funded, direct_alice, funded.reevaluate_target, "never-seen.com")


# =============================================================================
# Reporting: quorum failure and unfounded reports (bond economics)
# =============================================================================
@pytest.mark.parametrize("feeds", [
    ("rec", "404", "500"),      # the spec case: 1 CONFIRMED + 1 404 (lag) + 1 OUTAGE
    ("rec", "500", "404"),
    ("404", "rec", "503"),
    ("rec", "500", "500"),
    ("500", "500", "500"),
    ("rec", "badjson", "404"),  # schema error counts as outage
    ("rec", "html", "429"),
    ("404", "500", "500"),
])
def test_quorum_failure_never_slashes(vm, funded, direct_alice, feeds):
    r = rec()
    mock_feeds(vm, *[r if f == "rec" else f for f in feeds])
    assert report(vm, funded, direct_alice) == "QUORUM_FAILURE"
    a = hexof(funded, vm, direct_alice)
    assert funded.claimable_of(a) == str(BOND)               # bond intact
    assert funded.get_pool_state()["locked_slash_reserve"] == "0"
    assert funded.get_target_count() == 0                     # nothing recorded
    assert funded.check_transaction_safety(TARGET)["known"] is False


def test_quorum_failure_is_retryable(vm, funded, direct_alice):
    r = drainer()
    mock_feeds(vm, r, "404", "500")
    assert report(vm, funded, direct_alice) == "QUORUM_FAILURE"
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_alice) == "BLACKLISTED"


@pytest.mark.parametrize("feeds", [
    ("404", "404", "404"),
    ("404", "404", "500"),
    ("500", "404", "404"),
    ("safe", "safe", "safe"),
    ("safe", "safe", "500"),
    ("safe", "404", "404"),
    ("threat", "safe", "404"),
    ("threat", "404", "404"),
    ("safe", "404", "safe"),
])
def test_unfounded_or_safe_reports_forfeit_the_bond(vm, funded, direct_alice, feeds):
    lookup = {"threat": rec(tier=2), "safe": rec(tier=0)}
    mock_feeds(vm, *[lookup.get(f, f) for f in feeds])
    assert report(vm, funded, direct_alice) == "DISMISSED"
    p = funded.get_pool_state()
    assert p["locked_slash_reserve"] == str(BOND)
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == "0"
    assert funded.check_transaction_safety(TARGET)["verdict"] == "ALLOW"
    assert p["solvent"] is True


def test_slashed_bond_never_reaches_governor(vm, funded, direct_alice, direct_owner):
    mock_feeds(vm, "404", "404", "404")
    report(vm, funded, direct_alice)
    gov = hexof(funded, vm, direct_owner)
    assert funded.claimable_of(gov) == "0"
    with vm.expect_revert("ERR_NOTHING_TO_CLAIM"):
        send(vm, funded, direct_owner, funded.claim_payout)


def test_commitment_mismatch_with_feeds_is_unfounded(vm, funded, direct_alice):
    r = rec(ev="e" * 64)  # feeds publish a different indicator set than the reporter committed to
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_alice) == "DISMISSED"


def test_dismissed_target_can_be_reported_again_after_feeds_update(vm, funded, direct_alice, direct_bob):
    mock_feeds(vm, "404", "404", "404")
    assert report(vm, funded, direct_alice) == "DISMISSED"
    r = drainer()
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_bob) == "BLACKLISTED"
    assert funded.get_target_count() == 1  # same slot reused


def test_official_brand_domain_cannot_be_blacklisted(vm, funded, direct_alice):
    t = "app.uniswap.org"
    r = rec(target=t)
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_alice, target=t) == "TIER_0_SAFE_OFFICIAL_DOMAIN"
    assert funded.get_pool_state()["locked_slash_reserve"] == str(BOND)
    assert funded.check_transaction_safety(t)["verdict"] == "ALLOW"


# =============================================================================
# Reporting: input validation
# =============================================================================
def test_bond_below_minimum_reverts(vm, funded, direct_alice):
    r = drainer()
    mock_feeds(vm, r, r, r)
    with vm.expect_revert("ERR_INSUFFICIENT_BOND"):
        report(vm, funded, direct_alice, value=BOND - 1)


def test_zero_bond_reverts(vm, funded, direct_alice):
    with vm.expect_revert("ERR_INSUFFICIENT_BOND"):
        report(vm, funded, direct_alice, value=0)


def test_evidence_hash_must_commit_to_attributes(vm, funded, direct_alice):
    with vm.expect_revert("does not commit"):
        report(vm, funded, direct_alice, ev="a" * 64)


def test_tampered_campaign_breaks_commitment(vm, funded, direct_alice):
    h = commit()
    with vm.expect_revert("does not commit"):
        send(vm, funded, direct_alice, funded.report_target, TARGET, h, "other-campaign", BRAND, FIRST_SEEN, value=BOND)


def test_future_first_seen_earns_no_bounty(vm, funded, direct_alice):
    future = NOW + 1
    r = rec(first_seen=future, published=NOW + 10)
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_alice, first_seen=future) == "BLACKLISTED"
    t = funded.get_target_status(TARGET)
    assert t["bounty_reserved"] == "0" and t["first_seen_ts"] == future


@pytest.mark.parametrize("bad", ["UPPER.com", "a/b.com", "x", "has space.com", "evil.com/../x", "a..b.com"])
def test_bad_target_ids_revert_before_any_fetch(vm, funded, direct_alice, bad):
    vm.clear_mocks()
    with vm.expect_revert("ERR_INVALID_PARAMS"):
        send(vm, funded, direct_alice, funded.report_target, bad, commit(), CAMPAIGN, BRAND, FIRST_SEEN, value=BOND)


def test_bad_hash_format_reverts(vm, funded, direct_alice):
    with vm.expect_revert("bad evidence_hash"):
        send(vm, funded, direct_alice, funded.report_target, TARGET, "xyz", CAMPAIGN, BRAND, FIRST_SEEN, value=BOND)


def test_bad_labels_revert(vm, funded, direct_alice):
    with vm.expect_revert("bad campaign/brand label"):
        send(vm, funded, direct_alice, funded.report_target, TARGET, commit(), "Bad Campaign", BRAND, FIRST_SEEN, value=BOND)


# =============================================================================
# Anti-bounty-farming / provenance gates
# =============================================================================
def test_unregistered_brand_gets_bond_back_but_no_bounty(vm, funded, direct_alice):
    r = rec(brand="notabrand")
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_alice, brand="notabrand") == "BLACKLISTED"
    t = funded.get_target_status(TARGET)
    assert t["bounty_reserved"] == "0" and t["bond_held"] == str(BOND)
    assert funded.get_pool_state()["reserved_bounty"] == "0"


def test_first_seen_after_feed_publication_earns_no_bounty(vm, funded, direct_alice):
    late = PUBLISHED + 100
    r = rec(first_seen=late)
    mock_feeds(vm, r, r, r)
    assert report(vm, funded, direct_alice, first_seen=late) == "BLACKLISTED"
    assert funded.get_target_status(TARGET)["bounty_reserved"] == "0"


def test_one_bounty_per_campaign(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice, target="drain-one.com")
    blacklist(vm, funded, direct_bob, target="drain-two.com")  # same campaign id
    assert funded.get_target_status("drain-one.com")["bounty_reserved"] == str(BOUNTY)
    assert funded.get_target_status("drain-two.com")["bounty_reserved"] == "0"
    assert funded.get_target_status("drain-two.com")["status"] == "BLACKLISTED"


def test_reporter_epoch_bounty_cap(vm, funded, direct_alice):
    for i in range(4):
        blacklist(vm, funded, direct_alice, target=f"drain-{i}.com", campaign=f"camp-{i}")
    got = [funded.get_target_status(f"drain-{i}.com")["bounty_reserved"] for i in range(4)]
    assert got == [str(BOUNTY)] * 3 + ["0"]


def test_epoch_cap_limits_total_payout_to_20_percent(vm, pg, direct_owner, direct_alice, direct_bob, direct_charlie):
    send(vm, pg, direct_owner, pg.fund_bounty_pool, value=5 * 10**16)  # 0.05 GEN pool -> cap 0.01 GEN
    assert pg.get_pool_state()["epoch_cap"] == str(10**16)
    blacklist(vm, pg, direct_alice, target="cap-a.com", campaign="cap-a")
    assert pg.get_target_status("cap-a.com")["bounty_reserved"] == "0"  # 0.02 > cap 0.01
    p = pg.get_pool_state()
    assert p["reserved_bounty"] == "0" and p["epoch_paid"] == "0"


def test_epoch_cap_allows_exactly_cap_many_bounties(vm, pg, direct_owner, direct_alice, direct_bob, direct_charlie):
    send(vm, pg, direct_owner, pg.fund_bounty_pool, value=2 * 10**17)  # cap = 0.04 GEN = two bounties
    for who, i in ((direct_alice, 0), (direct_bob, 1), (direct_charlie, 2)):
        blacklist(vm, pg, who, target=f"cap-{i}.com", campaign=f"cap-{i}")
    got = [pg.get_target_status(f"cap-{i}.com")["bounty_reserved"] for i in range(3)]
    assert got == [str(BOUNTY), str(BOUNTY), "0"]
    assert pg.get_pool_state()["epoch_paid"] == str(2 * BOUNTY)


def test_empty_pool_pays_no_bounty_but_still_blacklists(vm, pg, direct_alice):
    assert blacklist(vm, pg, direct_alice) == "BLACKLISTED"
    assert pg.get_target_status(TARGET)["bounty_reserved"] == "0"


def test_self_manufactured_phishing_domain_costs_the_attacker(vm, funded, direct_alice):
    mine = "my-own-throwaway-drainer.xyz"
    mock_feeds(vm, "404", "404", "404")  # no feed has heard of it
    assert report(vm, funded, direct_alice, target=mine, campaign="mine-1") == "DISMISSED"
    p = funded.get_pool_state()
    assert p["locked_slash_reserve"] == str(BOND) and p["reserved_bounty"] == "0"
    assert int(p["bounty_pool"]) == 5 * 10**17


def test_single_colluding_feed_cannot_blacklist(vm, funded, direct_alice):
    mock_feeds(vm, drainer(), "404", "404")
    assert report(vm, funded, direct_alice) == "DISMISSED"


def test_two_colluding_feeds_with_forged_hash_cannot_earn_bounty(vm, funded, direct_alice):
    forged = rec(campaign="fake", ev="b" * 64)
    mock_feeds(vm, forged, forged, "404")
    assert report(vm, funded, direct_alice) == "DISMISSED"


# =============================================================================
# Appeals
# =============================================================================
def test_appeal_false_positive_slashes_reporter_to_challenger(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**FP)
    mock_feeds(vm, r, r, r)
    out = send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    assert out == "REVOKED_FALSE_POSITIVE"
    t = funded.get_target_status(TARGET)
    assert t["status"] == "REVOKED_FALSE_POSITIVE" and t["tier"] == 0 and t["override_ts"] == REVISED
    assert t["bond_held"] == "0" and t["bounty_reserved"] == "0"
    assert funded.claimable_of(hexof(funded, vm, direct_bob)) == str(2 * BOND)  # own bond + slashed reporter bond
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == "0"
    p = funded.get_pool_state()
    assert p["reserved_bounty"] == "0" and p["held_bonds"] == "0"
    assert int(p["bounty_pool"]) == 5 * 10**17  # bounty returned
    assert funded.check_transaction_safety(TARGET)["verdict"] == "ALLOW"
    assert p["solvent"] is True


def test_revoked_reporter_cannot_claim_anything(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**FP)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    vm.warp("2026-10-20T00:00:00Z")
    with vm.expect_revert("ERR_NOTHING_TO_CLAIM"):
        send(vm, funded, direct_alice, funded.claim_settlement, TARGET)


def test_revoked_campaign_can_be_bountied_again(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**FP)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    blacklist(vm, funded, direct_alice, target="different-drainer.com")
    assert funded.get_target_status("different-drainer.com")["bounty_reserved"] == str(BOUNTY)


def test_appeal_after_reporter_claimed_pays_challenger_from_slash_float(vm, funded, direct_alice, direct_bob, direct_charlie):
    mock_feeds(vm, "404", "404", "404")
    report(vm, funded, direct_charlie, target="some-false-report.com", campaign="sfr")  # seeds slash reserve
    blacklist(vm, funded, direct_alice)
    vm.warp("2026-10-16T00:00:00Z")
    send(vm, funded, direct_alice, funded.claim_settlement, TARGET)
    r = rec(**FP)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    assert funded.claimable_of(hexof(funded, vm, direct_bob)) == str(2 * BOND)
    assert funded.get_pool_state()["locked_slash_reserve"] == "0"
    assert funded.get_pool_state()["solvent"] is True


def test_remediation_refunds_both_bonds_without_slashing(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**REM)
    mock_feeds(vm, r, r, r)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "REMEDIATED"
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == str(BOND)
    assert funded.claimable_of(hexof(funded, vm, direct_bob)) == str(BOND)
    assert funded.get_pool_state()["locked_slash_reserve"] == "0"
    t = funded.get_target_status(TARGET)
    assert t["status"] == "REMEDIATED" and t["bond_held"] == "0"
    assert funded.check_transaction_safety(TARGET)["blocked"] is False


def test_remediated_reporter_still_earns_the_vested_bounty(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**REM)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    vm.warp("2026-10-16T00:00:00Z")
    assert send(vm, funded, direct_alice, funded.claim_settlement, TARGET) == str(BOUNTY)


def test_appeal_rejected_when_feeds_still_show_drainer(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = drainer()
    mock_feeds(vm, r, r, r)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "APPEAL_REJECTED"
    assert funded.get_target_status(TARGET)["status"] == "BLACKLISTED"
    assert funded.get_pool_state()["locked_slash_reserve"] == str(BOND)
    assert funded.claimable_of(hexof(funded, vm, direct_bob)) == "0"


def test_stale_revision_does_not_count(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    stale = rec(tier=0, status="FALSE_POSITIVE_REVOKED", published=PUBLISHED - 1)  # older than the report
    mock_feeds(vm, stale, stale, stale)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "APPEAL_REJECTED"


def test_same_timestamp_revision_does_not_count(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    same = rec(tier=0, status="FALSE_POSITIVE_REVOKED", published=PUBLISHED)
    mock_feeds(vm, same, same, same)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "APPEAL_REJECTED"


def test_single_source_revision_is_not_enough(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    mock_feeds(vm, rec(**FP), drainer(), drainer())
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "APPEAL_REJECTED"


def test_appeal_with_unreachable_source_is_quorum_failure_and_refunded(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    mock_feeds(vm, rec(**FP), "404", "500")
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "QUORUM_FAILURE"
    assert funded.claimable_of(hexof(funded, vm, direct_bob)) == str(BOND)
    assert funded.get_target_status(TARGET)["status"] == "BLACKLISTED"


def test_two_revisions_plus_outage_is_enough(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**FP)
    mock_feeds(vm, r, r, "503")
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "REVOKED_FALSE_POSITIVE"


def test_reporter_cannot_appeal_own_report(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    with vm.expect_revert("reporter cannot appeal"):
        send(vm, funded, direct_alice, funded.appeal_classification, TARGET, value=BOND)


def test_appeal_bond_floor(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    with vm.expect_revert("ERR_INSUFFICIENT_BOND"):
        send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND - 1)


def test_appeal_needs_a_listed_target(vm, funded, direct_alice, direct_bob):
    with vm.expect_revert("unknown target"):
        send(vm, funded, direct_bob, funded.appeal_classification, "never-seen.com", value=BOND)
    mock_feeds(vm, "404", "404", "404")
    report(vm, funded, direct_alice)  # DISMISSED
    with vm.expect_revert("nothing to appeal"):
        send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)


def test_appeal_on_quarantined_target(vm, funded, direct_alice, direct_bob):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    fp = rec(tier=0, status="FALSE_POSITIVE_REVOKED", published=REVISED)
    mock_feeds(vm, fp, fp, fp)
    assert send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND) == "REVOKED_FALSE_POSITIVE"
    assert funded.check_transaction_safety(TARGET)["verdict"] == "ALLOW"


def test_fp_override_blocks_relisting_from_stale_feed(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**FP)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    stale = drainer()  # feed re-asserts the OLD (pre-revocation) record
    mock_feeds(vm, stale, stale, stale)
    assert report(vm, funded, direct_alice) == "FALSE_POSITIVE_OVERRIDE_ACTIVE"
    assert funded.check_transaction_safety(TARGET)["verdict"] == "ALLOW"
    assert funded.claimable_of(hexof(funded, vm, direct_alice)) == str(BOND)  # refunded, not slashed


def test_fresh_evidence_newer_than_override_can_relist(vm, funded, direct_alice, direct_bob):
    blacklist(vm, funded, direct_alice)
    r = rec(**FP)
    mock_feeds(vm, r, r, r)
    send(vm, funded, direct_bob, funded.appeal_classification, TARGET, value=BOND)
    fresh = drainer(published=NOW - DAY)
    mock_feeds(vm, fresh, fresh, fresh)
    assert report(vm, funded, direct_alice) == "BLACKLISTED"


# =============================================================================
# Firewall consumer
# =============================================================================
def test_firewall_allows_unknown_targets(pg):
    r = pg.check_transaction_safety("never-seen.com")
    assert r["verdict"] == "ALLOW" and r["known"] is False and r["tier"] == 0
    assert pg.assert_target_safe("never-seen.com") == "SAFE"


def test_firewall_blocks_drainers(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice)
    r = funded.check_transaction_safety(TARGET)
    assert r["verdict"] == "BLOCK" and r["blocked"] is True and r["tier"] == 2
    with vm.expect_revert("ERR_TARGET_BLOCKED"):
        funded.assert_target_safe(TARGET)


def test_firewall_warns_on_suspicious(vm, funded, direct_alice):
    r = rec(tier=1)
    mock_feeds(vm, r, r, r)
    report(vm, funded, direct_alice)
    c = funded.check_transaction_safety(TARGET)
    assert c["verdict"] == "WARN" and c["warn"] is True and c["blocked"] is False
    assert funded.assert_target_safe(TARGET) == "WARN"


def test_firewall_rejects_malformed_ids(pg):
    with pytest.raises(Exception):
        pg.check_transaction_safety("NOT VALID")
    with pytest.raises(Exception):
        pg.assert_target_safe("a/b")


def test_target_index_enumeration(vm, funded, direct_alice):
    blacklist(vm, funded, direct_alice, target="one-drain.com", campaign="c-1")
    blacklist(vm, funded, direct_alice, target="two-drain.com", campaign="c-2")
    assert funded.get_target_count() == 2
    assert funded.get_target_id_by_index(0) == "one-drain.com"
    assert funded.get_target_id_by_index(1) == "two-drain.com"
    with pytest.raises(Exception):
        funded.get_target_id_by_index(2)


def test_unknown_target_status_shape(pg):
    t = pg.get_target_status("never-seen.com")
    assert t["known"] is False and t["status"] == "UNKNOWN" and t["bond_held"] == "0"
