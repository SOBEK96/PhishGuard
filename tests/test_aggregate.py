"""Exhaustive tests of the fault-tolerant 5-field `_aggregate` + validator guards."""

import itertools

import pytest

from tests.conftest import PUBLISHED, REVISED, commit

EV = commit()
SYMS = ["C2", "C1", "S", "M", "X", "U"]  # confirm T2, confirm T1, safe, mismatched-hash threat, 404, outage


def mk(mod, sym, ts=PUBLISHED):
    if sym == "X":
        return {"k": "NOT_FOUND"}
    if sym == "U":
        return {"k": "OUTAGE"}
    base = {"tier": 2, "status": "ACTIVE", "hash": EV, "published_ts": ts,
            "first_seen_ts": 1, "campaign_id": "c", "brand_id": "b"}
    if sym == "C1":
        base["tier"] = 1
    elif sym == "S":
        base["tier"] = 0
    elif sym == "M":
        base["hash"] = "f" * 64
    return {"k": "OK", "rec": base}


def oracle(syms):
    """Independent semantic oracle: the verdict is whatever EVERY completion of the
    unreachable sources agrees on; otherwise QUORUM_FAILURE.

    LAG RULE: exactly one confirmation next to any 404/outage is a (retryable)
    QUORUM_FAILURE, never a slash -- a lone early record is what honest CDN lag
    looks like."""
    known = [s for s in syms if s != "U"]
    n_out = len(syms) - len(known)
    confirm = sum(1 for s in known if s in ("C1", "C2"))
    if confirm == 1 and any(s in ("X", "U") for s in syms):
        return 2
    outcomes = set()
    for fills in itertools.product([0, 1], repeat=n_out):  # 1 == outage turns out to confirm
        outcomes.add(1 if confirm + sum(fills) >= 2 else 0)
    return outcomes.pop() if len(outcomes) == 1 else 2


COMBOS = list(itertools.product(SYMS, repeat=3))


@pytest.mark.parametrize("combo", COMBOS, ids=lambda c: "-".join(c))
def test_verdict_matches_semantic_oracle(pg, mod, combo):
    p = mod._aggregate([mk(mod, s) for s in combo], EV)
    assert p["verdict"] == oracle(combo)
    assert set(p) == {"verdict", "tier", "source_count", "evidence_hash", "published_ts"}
    assert p["evidence_hash"] == EV
    assert mod._payload_shape_ok(p, False)


def test_spec_case_confirmed_404_outage_is_quorum_failure(pg, mod):
    p = mod._aggregate([mk(mod, "C2"), mk(mod, "X"), mk(mod, "U")], EV)
    assert p["verdict"] == 2 and p["tier"] == 0 and p["published_ts"] == 0


def test_two_404_and_outage_is_unfounded_not_failure(pg, mod):
    assert mod._aggregate([mk(mod, "X"), mk(mod, "X"), mk(mod, "U")], EV)["verdict"] == 0


def test_two_safe_and_outage_is_safe(pg, mod):
    assert mod._aggregate([mk(mod, "S"), mk(mod, "S"), mk(mod, "U")], EV)["verdict"] == 0


def test_three_clean_with_single_threat_is_safe(pg, mod):
    # every source answered with a valid record and only one confirms: dismissed
    assert mod._aggregate([mk(mod, "C2"), mk(mod, "S"), mk(mod, "S")], EV)["verdict"] == 0
    assert mod._aggregate([mk(mod, "C2"), mk(mod, "S"), mk(mod, "M")], EV)["verdict"] == 0
    assert mod._aggregate([mk(mod, "C1"), mk(mod, "M"), mk(mod, "M")], EV)["verdict"] == 0


@pytest.mark.parametrize("others", [("X", "X"), ("X", "U"), ("U", "U"), ("X", "S"), ("X", "M"), ("S", "X"), ("U", "S"), ("M", "U")])
@pytest.mark.parametrize("conf", ["C1", "C2"])
def test_single_confirmation_with_404_or_outage_is_quorum_failure_never_a_slash(pg, mod, conf, others):
    for order in (0, 1, 2):
        srcs = [mk(mod, others[0]), mk(mod, others[1])]
        srcs.insert(order, mk(mod, conf))
        p = mod._aggregate(srcs, EV)
        assert p["verdict"] == 2, (conf, others, order)
        assert p["tier"] == 0 and p["published_ts"] == 0


def test_no_confirmation_at_all_is_still_dismissed(pg, mod):
    # the lag rule is about ONE real confirmation; fabricated reports still lose the bond
    assert mod._aggregate([mk(mod, "X"), mk(mod, "X"), mk(mod, "X")], EV)["verdict"] == 0
    assert mod._aggregate([mk(mod, "X"), mk(mod, "X"), mk(mod, "U")], EV)["verdict"] == 0
    assert mod._aggregate([mk(mod, "S"), mk(mod, "S"), mk(mod, "X")], EV)["verdict"] == 0


def test_all_outage_is_quorum_failure(pg, mod):
    p = mod._aggregate([mk(mod, "U")] * 3, EV)
    assert p["verdict"] == 2 and p["source_count"] == 0


@pytest.mark.parametrize("tiers,expected", [
    ((2, 2), 2), ((1, 1), 1), ((1, 2), 1), ((2, 1), 1),       # 2-source: conservative min
    ((2, 2, 2), 2), ((1, 1, 1), 1), ((1, 2, 2), 2), ((1, 1, 2), 1), ((2, 1, 2), 2),  # 3-source: median
])
def test_tier_is_min_on_two_and_median_on_three(pg, mod, tiers, expected):
    srcs = []
    for t in tiers:
        s = mk(mod, "C2")
        s["rec"]["tier"] = t
        srcs.append(s)
    while len(srcs) < 3:
        srcs.append(mk(mod, "X"))
    p = mod._aggregate(srcs, EV)
    assert p["verdict"] == 1 and p["tier"] == expected


def test_published_ts_is_min_of_confirming_sources(pg, mod):
    srcs = [mk(mod, "C2", 300), mk(mod, "C2", 100), mk(mod, "C2", 200)]
    assert mod._aggregate(srcs, EV)["published_ts"] == 100


def test_source_count_counts_clean_answers(pg, mod):
    assert mod._aggregate([mk(mod, "C2"), mk(mod, "C2"), mk(mod, "U")], EV)["source_count"] == 2
    assert mod._aggregate([mk(mod, "C2"), mk(mod, "C2"), mk(mod, "X")], EV)["source_count"] == 3


def test_mismatched_evidence_hash_does_not_confirm(pg, mod):
    p = mod._aggregate([mk(mod, "M"), mk(mod, "M"), mk(mod, "M")], EV)
    assert p["verdict"] == 0


def test_revoked_or_remediated_record_never_confirms(pg, mod):
    for status in ("FALSE_POSITIVE_REVOKED", "REMEDIATED"):
        s = mk(mod, "C2")
        s["rec"]["status"] = status
        assert mod._aggregate([s, s, s], EV)["verdict"] == 0


# --- revision detection ----------------------------------------------------------
def revised(mod, status, ts):
    s = mk(mod, "S", ts)
    s["rec"]["status"] = status
    return s


def test_revision_requires_two_sources(pg, mod):
    fp = revised(mod, "FALSE_POSITIVE_REVOKED", REVISED)
    assert mod._revision_of([fp, fp, mk(mod, "X")]) == 1
    assert mod._revision_of([fp, mk(mod, "X"), mk(mod, "X")]) == 0
    rem = revised(mod, "REMEDIATED", REVISED)
    assert mod._revision_of([rem, rem, mk(mod, "U")]) == 2


def test_mixed_revisions_do_not_reach_quorum(pg, mod):
    fp = revised(mod, "FALSE_POSITIVE_REVOKED", REVISED)
    rem = revised(mod, "REMEDIATED", REVISED)
    assert mod._revision_of([fp, rem, mk(mod, "C2")]) == 0


def test_revision_published_ts_is_min_of_revision_sources(pg, mod):
    a = revised(mod, "FALSE_POSITIVE_REVOKED", 500)
    b = revised(mod, "FALSE_POSITIVE_REVOKED", 400)
    p = mod._aggregate([a, b, mk(mod, "C2")], EV)
    assert p["verdict"] == 0 and p["published_ts"] == 400


# --- payload shape / forgery guards -----------------------------------------------
GOOD = {"verdict": 1, "tier": 2, "source_count": 3, "evidence_hash": EV, "published_ts": PUBLISHED}


def variant(**kw):
    p = dict(GOOD)
    p.update(kw)
    return p


def test_good_payload_passes(pg, mod):
    assert mod._payload_shape_ok(GOOD, False)


@pytest.mark.parametrize("bad", [
    variant(verdict=3), variant(verdict=-1), variant(verdict="1"), variant(verdict=True),
    variant(tier=3), variant(tier=-1), variant(tier=1.0), variant(tier="2"),
    variant(source_count=4), variant(source_count=-1), variant(source_count="3"),
    variant(evidence_hash="zz"), variant(evidence_hash=""), variant(evidence_hash=None),
    variant(published_ts=-1), variant(published_ts="1"), variant(published_ts=None),
    variant(verdict=1, tier=0),                       # verified report must carry a threat tier
    variant(verdict=1, source_count=1),               # verified needs >= 2 sources
    variant(verdict=1, published_ts=0),
    variant(verdict=0, tier=2),                       # safe verdict cannot carry a threat tier
    variant(verdict=2, tier=1),
    variant(verdict=2, tier=0, published_ts=5),       # failure carries no timestamp
])
def test_forged_payloads_are_rejected(pg, mod, bad):
    assert not mod._payload_shape_ok(bad, False)


@pytest.mark.parametrize("bad", [
    {}, [], None, "x", 5,
    {k: v for k, v in GOOD.items() if k != "tier"},                 # missing field
    {**GOOD, "extra": 1},                                           # extra field
    {**GOOD, "revision": 0},                                        # revision not allowed on report payloads
])
def test_structurally_wrong_payloads_are_rejected(pg, mod, bad):
    assert not mod._payload_shape_ok(bad, False)


def test_appeal_payload_needs_revision_field(pg, mod):
    safe = {"verdict": 0, "tier": 0, "source_count": 3, "evidence_hash": EV,
            "published_ts": REVISED, "revision": 1}
    assert mod._payload_shape_ok(safe, True)
    assert not mod._payload_shape_ok({k: v for k, v in safe.items() if k != "revision"}, True)
    assert not mod._payload_shape_ok({**safe, "revision": 3}, True)
    assert not mod._payload_shape_ok({**safe, "revision": True}, True)
    # a revision may only accompany a SAFE verdict
    assert not mod._payload_shape_ok({**GOOD, "revision": 1}, True)


def test_validator_agreement_compares_decision_fields(pg, mod):
    other = dict(GOOD)
    assert mod._payloads_agree(GOOD, other, False)
    for key, val in (("verdict", 0), ("tier", 1), ("published_ts", 1), ("evidence_hash", "f" * 64)):
        assert not mod._payloads_agree(GOOD, {**GOOD, key: val}, False)
    # source_count feeds the bounty gate, so it is consensus-agreed too.
    assert not mod._payloads_agree(GOOD, {**GOOD, "source_count": 2}, False)


def test_validator_agreement_compares_revision_on_appeals(pg, mod):
    a = {"verdict": 0, "tier": 0, "source_count": 3, "evidence_hash": EV, "published_ts": 9, "revision": 1}
    assert mod._payloads_agree(a, dict(a), True)
    assert not mod._payloads_agree(a, {**a, "revision": 2}, True)


# --- appeal aggregation: an outage may complete a REVISION quorum --------------
@pytest.mark.parametrize("a,b,c,verdict,rev", [
    ("FP", "X", "U", 2, 0),     # 1 revoked + 404 + outage  -> retry, never slash the appellant
    ("FP", "U", "U", 2, 0),
    ("REM", "S", "U", 2, 0),
    ("FP", "FP", "U", 0, 1),    # quorum reached despite the outage
    ("REM", "REM", "X", 0, 2),
    ("FP", "REM", "U", 2, 0),   # either kind could still reach 2
    ("FP", "REM", "S", 0, 0),   # all clean, no revision quorum -> rejected
    ("X", "X", "U", 0, 0),      # a revision cannot appear from nothing
    ("S", "S", "U", 0, 0),
    ("FP", "X", "X", 0, 0),
    ("C2", "C2", "FP", 1, 0),   # still corroborated threat -> appeal rejected
])
def test_appeal_aggregate_outage_semantics(pg, mod, a, b, c, verdict, rev):
    def make(sym):
        if sym == "FP":
            return revised(mod, "FALSE_POSITIVE_REVOKED", REVISED)
        if sym == "REM":
            return revised(mod, "REMEDIATED", REVISED)
        return mk(mod, sym)
    p = mod._aggregate_appeal([make(a), make(b), make(c)], EV)
    assert (p["verdict"], p["revision"]) == (verdict, rev)
    assert mod._payload_shape_ok(p, True)
