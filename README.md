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

## Live deployment (GenLayer Studio Next, chain 61997) - economically hardened build

| | |
|---|---|
| Contract | `0x07d4631B39CD5817f28C2Aff0f28B58f34911077` ([explorer](https://explorer-studio-next.genlayer.com/address/0x07d4631B39CD5817f28C2Aff0f28B58f34911077)) |
| Deployer / governor | `0xE6d38f463c03b2B9fB42a9D565c69a1ddc283964` (`phishguard-deployer`) |
| Reporter | `0xfc35738E3c8dA590E1Fe0006E25FD031f93df246` (`phishguard-reporter`) |
| Source SHA-256 | `2d882b08fccb1a2daebdb19cd9d19799e79784e6d76969508959d76d72cf883e` (equals the on-chain deployed code hash) |
| Feed pin | commit `7f7173bf44bc1b868733978b9675882b9f6ac7f8` |

Transactions (all `ACCEPTED` / `MAJORITY_AGREE`):

| Step | Hash |
|---|---|
| deploy | `0xb67635de53005499ddbb3bb0b9f206b306422eda1c79e40badcde4c8caccca72` |
| register_brand:uniswap | `0x859d6a5ba551b2c4fd76505a254c372188e249a7b2fd75ed9331b7cfa3d7bff0` |
| register_brand:opensea | `0x89edbb5a0736331944c067aa71833a56855421cf3d144475c595451584fa224c` |
| fund_bounty_pool(12000000000000000 wei) | `0x32f9098eb0a786182eb029f6650114e276328a6770f6e10a400f056b1d4123c1` |
| report_target(0.01 GEN bond) | `0x37020a3c3388faefcf5135cd660d5cd21845d110aff9b54c2b9a4280280b4c5c` |

Live `gen_call` readbacks (full output in `deployments/studio-next.json`):

* `get_target_status("uniswap-claim-airdrop.com")` -> `BLACKLISTED`, tier 2, `source_count 3`, `bond_held 0.01 GEN`, `vest_at 1792169127` (report time + 24h)
* `check_transaction_safety` -> exact `BLOCK`; `app.…` -> `BLOCK` (inherited from `uniswap-claim-airdrop.com`); `claim.app.…` -> `BLOCK`; unrelated host -> `ALLOW`
* `assert_target_safe` reverts for the exact host and for `app.…`
* `get_pool_state()` -> `bounty_pool 0.012 GEN`, `epoch_cap 0.0024 GEN` (20 % of net capital), `held_bonds 0.01 GEN`, `solvent: true`
* `get_feed_sources()` -> `raw.githubusercontent.com` / `cdn.jsdelivr.net` / `raw.githack.com`

### Honest deviations

* **The live pool is tiny (0.012 GEN), so this build reserved no bounty live.** Earlier seeds (0.5 GEN, 0.1 GEN,
  0.12 GEN) sit in superseded contracts and the funding accounts were nearly empty. 20 % of 0.012 GEN is below the fixed
  0.02 GEN bounty. The net-capital cap and the fresh vest window are therefore verified by tests (695 pytest), not
  re-demonstrated live on this build (the previous build did show the mid-epoch cap live).
* **`claim_payout` settlement is unverified on Studio Next.** The first deployment's emitted transfer was finalized but
  never executed, which is also why those funds are stranded. A successful receipt means "recorded", not "paid".
* Faucet `sim_fundAccount` credited 0; accounts were funded from existing unlocked CLI accounts.
* 2 brands registered (uniswap, opensea) to conserve fee deposits.
* Direct-mode tests need the v0.3 runner (`py-genlayer:5jycge…`, `GENVM_VERSION=v0.6.0-rc7`).
* Superseded deployments (left untouched): `0x4135EAF1…B01b`, `0x5Ecc9853…E8DB` (eacf14c), `0x4890C058…6507` (f8434bd).
* Three CDN hosts of one repo are not three independent sources of threat truth; `operator` is a registered string.
  Fixtures are commit-pinned, so a new threat/remediation needs governance to re-pin feeds.

## Economic hardening (recheck of f8434bd)

| Finding | Root cause | Fix | Regression test |
|---|---|---|---|
| Re-report could short-circuit a vest window | `_settle_prior` credited the previous cycle's *unvested* bounty immediately, tying its payout to the new report instead of its own cooldown | superseded escrow moves to its own `VestEntry` with its **original** `vest_at` (`claim_vested`); every fresh verified report gets a new `now + 24h` window; neither can shorten or inherit the other | `test_rereported_target_cannot_bypass_cooldown_window` (+2) |
| Recycling liquidity inflated the epoch cap | cap tracked deposit/withdraw *deltas*, floored at `paid`: once slack hit the floor a withdrawal was free and the re-deposit added 20 % again (0.5 GEN -> 0.18 GEN reservable, 36 %) | cap is a pure function of **net capital** = `bounty_pool + reserved_bounty` at reservation time (`epoch_paid + bounty <= 20 % x capital`); no stored cap to drift | `test_recycling_same_liquidity_via_deposit_withdraw_cannot_inflate_epoch_cap` (fails on f8434bd: 0.18 > 0.1) |

Note on the requested formula: `bounty_pool - reserved_bounty` would double-count, because reserving already moves money
out of `bounty_pool`; a reserved bounty is still vault capital until it vests. Reserved + free is the net figure.

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
tests/                        695 direct-mode pytest tests (+ tests/vectors golden corpus)
frontend/                     Next.js 16.4.1 + Tailwind 4 SOC console (597 vitest tests)
```

## Verify

```bash
uv venv --python 3.12 && uv pip install --prerelease=allow -r requirements-dev.txt
export GENVM_VERSION=v0.6.0-rc7
.venv/bin/genvm-lint check contracts/phish_guard.py     # lint + validation
.venv/bin/genvm-lint typecheck contracts/phish_guard.py # 0 errors, 0 diagnostics
.venv/bin/python -m pytest tests -q                     # 695 passed
cd frontend && npm ci && npx tsc --noEmit && npx eslint --max-warnings 0 . && npx vitest run && npm run build
npm audit --registry=https://registry.npmjs.org         # 0 vulnerabilities
```

Deploy: `PHISHGUARD_KEYSTORE_PASSWORD=… PHISHGUARD_SEED_WEI=… npx tsx deploy/deploy_phish_guard.ts`.
