# PhishGuard — Decentralized Web3 Anti-Phishing & Drainer Triage Oracle

A GenLayer Intelligent Contract that classifies reported domains into discrete threat tiers
by reading **three independent threat-intel hosts**, settles staked reporter bonds and bounties,
and exposes an on-chain firewall (`check_transaction_safety`, `assert_target_safe`) that wallets
and routers can query before signing.

| Tier | Meaning | Outcome |
|---|---|---|
| `TIER_0_SAFE` (0) | clean / official | reporter bond **forfeited** to `locked_slash_reserve` |
| `TIER_1_SUSPICIOUS` (1) | anomaly, no drainer payload | 48h `QUARANTINE_WATCH`, bond refunded |
| `TIER_2_DRAINER` (2) | confirmed drainer | `BLACKLISTED`; bond + fixed bounty vest after a 24h cooldown |

## Live deployment (GenLayer Studio Next, chain 61997) - lag-rule build

| | |
|---|---|
| Contract | `0x49EC7a7bDBD93d26f81b019310041C523d4E4717` ([explorer](https://explorer-studio-next.genlayer.com/address/0x49EC7a7bDBD93d26f81b019310041C523d4E4717)) |
| Deployer / governor | `0xE6d38f463c03b2B9fB42a9D565c69a1ddc283964` (`phishguard-deployer`) |
| Reporter | `0xfc35738E3c8dA590E1Fe0006E25FD031f93df246` (`phishguard-reporter`) |
| Source SHA-256 | `bb1082bbc4a9f28e699c4a077e03ecbd04673d62bdd2f3e0dc4b5c1433b6d5f2` (equals the on-chain deployed code hash) |
| Feed pin | commit `7f7173bf44bc1b868733978b9675882b9f6ac7f8` |

Transactions (all `ACCEPTED` / `MAJORITY_AGREE`):

| Step | Hash |
|---|---|
| deploy | `0xd6e755d1cf92df40592f05dc10f74562668b80a8e41d03068b9a7e96ee06bb3e` |
| register_brand:uniswap | `0x371cff0667066eebf372c2ffe4747388725e21649e69eca2b05496147d9fd1a5` |
| register_brand:opensea | `0x1fd94ab8fe4534706a0540bcd50531b5ddc4583ea58fb14728ea6ed1149efe85` |
| fund_bounty_pool(70000000000000000 wei) | `0x4db25ace306ead69d371f8ba8b2d0ab67d24cff5635cc0f87c438c8ef738732d` |
| report_target(0.01 GEN bond) | `0xcd8ec346d2671a3f3656ea07763a5281877b93671500e6091f1fdd1d8b08c1b8` |

Live `gen_call` readbacks (full output in `deployments/studio-next.json`):

* `get_target_status("uniswap-claim-airdrop.com")` -> `BLACKLISTED`, tier 2, `source_count 3`, `bond_held 0.01 GEN`
* `check_transaction_safety` -> exact `BLOCK`; `app.…` -> `BLOCK` (inherited); `claim.app.…` -> `BLOCK`; unrelated host -> `ALLOW`
* `assert_target_safe` reverts for the exact host and for `app.…`
* `get_pool_state()` -> `bounty_pool 0.07 GEN`, `epoch_cap 0.014 GEN` (20 % of net capital), `solvent: true`
* `get_feed_sources()` -> `raw.githubusercontent.com` / `cdn.jsdelivr.net` / `raw.githack.com`

### Honest deviations

* **The live pool is small (0.07 GEN) and no bounty was reserved live**: 20 % of 0.07 GEN is below the fixed 0.02 GEN
  bounty. Earlier seeds sit in superseded contracts whose emitted payout transfers Studio Next never executed.
* **`claim_payout` settlement is unverified on Studio Next.** A successful receipt means "recorded", not "paid".
* **The lag rule is test-verified, not live-verified.** Showing "1 confirmation + 404s -> QUORUM_FAILURE" on chain
  needs a fixture present in only one pinned feed; the feeds are pinned to commit `7f7173b` and rotation sits behind
  the 7-day governance timelock.
* Faucet `sim_fundAccount` credited 0; accounts were funded from existing unlocked CLI accounts.
* 2 brands registered (uniswap, opensea) to conserve fee deposits.
* Direct-mode tests need the v0.3 runner (`py-genlayer:5jycge…`, `GENVM_VERSION=v0.6.0-rc7`).
* Superseded deployments (left untouched): `0x4135EAF1…B01b`, `0x5Ecc9853…E8DB`, `0x4890C058…6507`, `0x07d4631B…1077`.

## Verdicts and threat model

`_aggregate` reads the three governed feeds and returns one of three verdicts. Each source answers `CONFIRM` (a valid
ACTIVE tier >= 1 record carrying the reporter's evidence commitment), `CLEAN` (any other valid record: safe, revoked,
remediated, or a different commitment), `404`, or `OUTAGE` (timeout / 5xx / schema error / future-dated record).

| Sources | Verdict | Bond |
|---|---|---|
| >= 2 CONFIRM | `VERIFIED_REPORT` (tier: min of 2, median of 3) | returned / vests |
| **exactly 1 CONFIRM + any 404 or OUTAGE** | **`QUORUM_FAILURE`** | **intact, retry** |
| 1 CONFIRM, the other two both CLEAN | `SAFE_OR_UNFOUNDED` | forfeited |
| 0 CONFIRM (>= 2 CLEAN, or 404s, or fabricated) | `SAFE_OR_UNFOUNDED` | forfeited |
| 0 CONFIRM + an unreachable source that could still complete a quorum | `QUORUM_FAILURE` | intact, retry |
| every source in OUTAGE | `QUORUM_FAILURE` | intact, retry |

**Why a lone confirmation next to a 404 is a retry, not a slash.** A single feed that already carries the record
while the others have not propagated (CDN lag, regional sync delay) is exactly what an honest early report looks like.
Dismissing it would permanently penalise the reporter for feed lag, so it is retryable with the bond intact. A report is
only dismissed when no source confirms it, or every source answered with a clean, non-confirming record.

**Known limitations (not hidden):**

* **Single-key governor.** One account registers brands and stages feed rotations; rotation is behind a 7-day
  timelock and cannot move funds, but it is one key, not a multisig or DAO.
* **Three CDN mirrors of one repository.** The three hosts are distinct hostnames, but all serve the single
  `SOBEK96/PhishGuard` repo; `operator` is a registered string, not verified ownership. They are not three independent
  sources of threat truth, and the fixtures are commit-pinned, so a new threat or remediation requires a governance
  re-pin. This is a demo feed set, not a live threat-intelligence service.
* Payout settlement via `emit_transfer` is unverified on Studio Next (see above).
* Unknown targets are `ALLOW` by design (unassessed, not verified safe).

## Audit hardening (review of eacf14c)

| # | Finding | Fix | Regression test |
|---|---|---|---|
| P01 | reserved bounty stranded when a REMEDIATED target was re-reported | prior record's `bond_held`/`bounty_reserved` are settled to the prior reporter's ledger before overwrite; strict invariant `reserved_bounty == Σ bounty_reserved`, `held_bonds == Σ bond_held` asserted after every write in the suite | `test_remediated_then_rereported_target_never_strands_reserved_bounty` (+3 variants) |
| P02 | future `published_ts` poisoned the override high-water mark | records dated beyond `now + MAX_CLOCK_SKEW` (3600 s) are schema errors (OUTAGE); ceiling is captured outside the nondet block so validators agree | `test_future_published_ts_in_remediation_or_report_is_rejected_as_invalid` |
| P03 | empty-pool report froze `epoch_cap` at 0 | `fund_bounty_pool` raises the current epoch cap by 20 % of the deposit; withdrawals lower it (never below paid) so deposit/withdraw cannot inflate it | `test_funding_empty_pool_mid_epoch_updates_epoch_bounty_cap` |
| P04 | frontend accepted documents the contract treats as OUTAGE | TS classifier now enforces the same fields, integer-literal rules (`2.0` is not an int), byte cap, code-point lengths and timestamp ceiling; shared 87-vector golden corpus checked by Python **and** vitest | `tests/test_feed_parity.py`, `frontend/tests/parity.test.ts` |
| P05 | polling superseded the loader generation and starved the list tail | single-flight `SerialLoader`: overlapping ticks coalesce into one follow-up pass, only `reset()` cancels; progressive publish; recent-50 + pinned targets | `serialLoader.test.ts` (single-flight suite) |
| P06 | blacklisted domain did not cover its subdomains | `check_transaction_safety` / `assert_target_safe` / `get_target_status` walk registrable parents and apply the strictest active tier; public suffixes and multi-tenant hosts are never inherited; a safe parent does not clear a subdomain | `test_subdomain_inherits_parent_domain_blacklist_and_quarantine_status` (+8) |
| P07 | LPs could deposit but not redeem in the UI | Redeem-shares form: balance, redeemable GEN, lock breakdown, 2-step (redeem -> claim) | `vault.test.ts` |
| TC | 18 typecheck diagnostics (`u256(...)` calls) | plain-int keys; `genvm-lint typecheck` reports 0 diagnostics on rc3/rc5/rc6/rc7/rc8 | - |
| - | `source_count` was not part of validator agreement | now compared by validators | `test_validator_agreement_compares_decision_fields` |

## Design invariants

1. **No floats.** Ratios are integer basis points, money is wei; every view returns int/str/bool/list/dict
   (enforced by an AST test).
2. **No arbitrary URLs.** Reporters submit `target_id` + `evidence_hash` (SHA-256 of
   `phishguard.v1|target|campaign|brand|first_seen`, recomputed on-chain). Fetch URLs are `feed_base + slug + ".json"`.
3. **3 hosts, 3 operators.** Uniqueness is enforced at construction, at staging (against active *and* staged slots) and at
   activation; rotation has a 7-day timelock.
4. **Fault-tolerant `_aggregate`.** Payload `{verdict, tier, source_count, evidence_hash, published_ts}`. Verified iff ≥2
   feeds confirm the commitment; if an unreachable feed could still complete the quorum the result is
   `QUORUM_FAILURE` (bond intact, retry). 2 sources → `min(tier)`, 3 sources → median. Appeals add a `revision`
   field and apply the same outage rule to *revision* quorums.
5. **Anti bounty-farming.** Bounty needs ≥2 corroborating feeds, a campaign id, `first_seen_ts ≤ report time` and
   `≤ feed publication`, a registered brand, one bounty per campaign, ≤3 per reporter per epoch, and a 20 %
   (`max_epoch_bounty_bps = 2000`) per-epoch pool cap, vesting after 24h.
6. **No governor conflict.** Slashed bonds go to `locked_slash_reserve` (recyclable to the pool by anyone above a
   floor, or paid to appeal challengers). The only outflow is `claim_payout` to the caller's own claimable balance.
7. **Vault floor.** ERC-4626-style shares with 1000 dead shares; withdrawals only touch free liquidity.
8. **Appeals.** Succeed only on a ≥2-source *newer* record: `FALSE_POSITIVE_REVOKED` slashes the reporter's escrowed
   bond to the challenger; `REMEDIATED` refunds both bonds without slashing; otherwise the appeal bond is slashed.

## Layout

```
contracts/phish_guard.py      GenLayer contract (zero floats)
deployments/mock_feeds/{a,b,c}  commit-pinned fixtures (scripts/gen_mock_feeds.py)
deployments/studio-next.json  authoritative deployment + readbacks
deployments/phish_guard_abi.json  live contract schema
deploy/deploy_phish_guard.ts  deploy + seed + live report + readback (genlayer-js 2.0.0-rc.1)
deploy/ops.ts                 ad-hoc signed writes with SDK fee estimation
deploy/post_deploy.ts         live mid-epoch top-up + second report + readbacks
tests/                        720 direct-mode pytest tests (+ tests/vectors golden corpus)
frontend/                     Next.js 16.4.1 + Tailwind 4 SOC console (612 vitest tests)
```

## Verify

```bash
uv venv --python 3.12 && uv pip install --prerelease=allow -r requirements-dev.txt
export GENVM_VERSION=v0.6.0-rc7
.venv/bin/genvm-lint check contracts/phish_guard.py     # lint + validation
.venv/bin/genvm-lint typecheck contracts/phish_guard.py # 0 errors, 0 diagnostics
.venv/bin/python -m pytest tests -q                     # 720 passed
cd frontend && npm ci && npx tsc --noEmit && npx eslint --max-warnings 0 . && npx vitest run && npm run build
npm audit --registry=https://registry.npmjs.org         # 0 vulnerabilities
```

Deploy: `PHISHGUARD_KEYSTORE_PASSWORD=… PHISHGUARD_SEED_WEI=… npx tsx deploy/deploy_phish_guard.ts`.
