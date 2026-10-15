#!/usr/bin/env python3
"""Generate the commit-pinned threat-intel fixtures under deployments/mock_feeds/{a,b,c}.

Each file is `<target_id>.json`. `evidence_hash` is the SHA-256 commitment the
contract recomputes:  sha256("phishguard.v1|target|campaign|brand|first_seen").
Deterministic: running it twice produces byte-identical files.
"""
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1] / "deployments" / "mock_feeds"

# target -> (campaign, brand, first_seen_ts, per-feed [(tier, status, published_ts) | None])
# None == the feed has no record (HTTP 404).
SCENARIOS = {
    # Confirmed Permit2 drainer corroborated by all three feeds.
    "uniswap-claim-airdrop.com": ("permit2-airdrop-2026q4", "uniswap", 1790000000,
        [(2, "ACTIVE", 1790100000), (2, "ACTIVE", 1790100300), (2, "ACTIVE", 1790100600)]),
    # Seaport approval hijack; feed C lags (404) -> still a 2-of-3 quorum.
    "opensea-seaport-mint.net": ("seaport-hijack-2026q4", "opensea", 1790200000,
        [(2, "ACTIVE", 1790300000), (2, "ACTIVE", 1790300100), None]),
    # Typosquat anomaly, no drainer payload -> 48h quarantine watch.
    "rabby-wallet-verify.xyz": ("typosquat-rabby-2026q4", "rabby", 1790400000,
        [(1, "ACTIVE", 1790500000), (1, "ACTIVE", 1790500100), (1, "ACTIVE", 1790500200)]),
    # Mixed tiers (1,2,2): conservative / median aggregation exercise.
    "aave-rewards-claim.app": ("mixed-tier-2026q4", "aave", 1790600000,
        [(1, "ACTIVE", 1790700000), (2, "ACTIVE", 1790700100), (2, "ACTIVE", 1790700200)]),
    # Explicit false-positive revocation published by every feed.
    "lido-staking-rewards.org": ("fp-revoked-2026q4", "lido", 1790800000,
        [(0, "FALSE_POSITIVE_REVOKED", 1790900000), (0, "FALSE_POSITIVE_REVOKED", 1790900100),
         (0, "FALSE_POSITIVE_REVOKED", 1790900200)]),
    # Post-remediation cleanup.
    "curve-pool-bonus.fi": ("remediated-2026q4", "curve", 1791000000,
        [(0, "REMEDIATED", 1791100000), (0, "REMEDIATED", 1791100100), (0, "REMEDIATED", 1791100200)]),
    # Benign: every feed says tier 0.
    "docs.ens-benign-example.org": ("benign-2026q4", "ens", 1791200000,
        [(0, "ACTIVE", 1791300000), (0, "ACTIVE", 1791300100), (0, "ACTIVE", 1791300200)]),
}


def commitment(target, campaign, brand, first_seen):
    return hashlib.sha256(f"phishguard.v1|{target}|{campaign}|{brand}|{first_seen}".encode()).hexdigest()


def main():
    for slot in "abc":
        (ROOT / slot).mkdir(parents=True, exist_ok=True)
    for target, (campaign, brand, first_seen, feeds) in SCENARIOS.items():
        ev = commitment(target, campaign, brand, first_seen)
        for slot, rec in zip("abc", feeds):
            path = ROOT / slot / f"{target}.json"
            if rec is None:
                if path.exists():
                    path.unlink()
                continue
            tier, status, pub = rec
            body = {
                "target_id": target,
                "tier": tier,
                "status": status,
                "campaign_id": campaign,
                "brand_id": brand,
                "first_seen_ts": first_seen,
                "published_ts": pub,
                "evidence_hash": ev,
                "feed": {"a": "phishguard-primary", "b": "independent-cert-mirror", "c": "open-threat-exchange"}[slot],
            }
            path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print("wrote fixtures for", len(SCENARIOS), "targets")


if __name__ == "__main__":
    main()
