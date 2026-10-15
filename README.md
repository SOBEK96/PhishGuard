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

## Live deployment (GenLayer Studio Next, chain 61997) - hardened build

| | |
|---|---|
| Contract | `0x4890C058f446A2B8DAb7d5b80c6F75B436756507` |
| Deployer / governor | `0xE6d38f463c03b2B9fB42a9D565c69a1ddc283964` (`phishguard-deployer`) |
| Reporter | `0xfc35738E3c8dA590E1Fe0006E25FD031f93df246` (`phishguard-reporter`) |
| Source SHA-256 | `2123670368f120923fded700b707ae9d7b43e15655b18b159efcea2249524889` (equals the on-chain deployed code hash) |
| Feed pin | commit `7f7173bf44bc1b868733978b9675882b9f6ac7f8` |

Transactions (all `ACCEPTED` / `FINISHED_WITH_RETURN` / `MAJORITY_AGREE`):

| Step | Hash |
|---|---|
| deploy | `0x79aa13e0f15261269903797bb834166b0adf988c1a4284178e5cb5d3c6ccc7cc` |
| register_brand:uniswap | `0xce04e38315147b92cac3d77c4a7c2b701609eec01c9fc8da678ba39e00faa1b8` |
| register_brand:opensea | `0x411304b43168db0182be6095c24040de180b8a9bf334b062860f87e3536b192c` |
| register_brand:rabby | `0xc16fad83901861fd95bddaa247182675a0a8cbd5726712434dc1720addc6c6ed` |
| register_brand:aave | `0x21d2f047b1f292bcb8e41d07e2ad458aa91a9d02885232d777cd9677e2f2f03a` |
| fund_bounty_pool(80000000000000000 wei) | `0xdd00cc7211b82ed8ed309545af017bdc656f94495224d723314270bd3ddf8317` |
| report_target(0.01 GEN bond) | `0x902599daf34cf90e07ce73c1ded59ce6f3c0354a2fec25726287a85de3fe7671` |
| fund_bounty_pool(+40000000000000000 wei, mid-epoch top-up) | `0x3c570627e4ce0db4ea1c0562244e3db58552c347d4c73d06a821f85e0fb2f9de` |
| report_target(second target, 0.01 GEN bond) | `0x6783208280f16c2145f991d546573353976896405061fedd3bb73071b9a2f885` |

Live `gen_call` readbacks (full output in `deployments/studio-next.json`):

* `get_target_status("uniswap-claim-airdrop.com")` -> `BLACKLISTED`, tier 2, `source_count 3`, `bond_held 0.01 GEN`
* `check_transaction_safety("uniswap-claim-airdrop.com")` -> `BLOCK`
* **Subdomains:** `check_transaction_safety("app.uniswap-claim-airdrop.com")` -> `BLOCK`
  (`inherited: true`, `matched_target: uniswap-claim-airdrop.com`); `claim.app.…` -> `BLOCK`;
  `assert_target_safe("app.uniswap-claim-airdrop.com")` reverts; the unrelated `notuniswap-claim-airdrop.com` -> `ALLOW`
* **Mid-epoch cap (P03):** `epoch_cap` 0.016 -> 0.024 GEN after a 0.04 GEN top-up; the second report
  (`opensea-seaport-mint.net`) then reserved the 0.02 GEN bounty; `reserved_bounty == sum(target.bounty_reserved)`,
  `solvent: true`
* `get_feed_sources()` -> A `raw.githubusercontent.com`, B `cdn.jsdelivr.net`, C `raw.githack.com`

### Honest deviations

* **Seed is 0.08 GEN (+0.04 top-up), not 0.5 GEN.** The first deployment's 0.5 GEN seed is stranded on
  `0x4135EAF1…B01b`: Studio Next finalized the `claim_payout` but never executed the emitted transfer message.
  **`claim_payout` settlement is therefore unverified on Studio Next**; `claim_settlement` / receipts must not be read
  as "money arrived in the wallet".
* With a seed of 0.08 GEN the 20 % epoch cap (0.016) is below the fixed 0.02 bounty, so the first live report reserved no
  bounty - the top-up exercised the P03 fix instead.
* Faucet `sim_fundAccount` credited 0; accounts were funded from existing unlocked CLI accounts as allowed.
* Direct-mode tests need the v0.3 runner (`py-genlayer:5jycge…`, `GENVM_VERSION=v0.6.0-rc7`).
* Superseded deployments (left untouched on chain): `0x4135EAF1…B01b`, and `0x5Ecc9853…E8DB` (eacf14c).
* Three CDN hosts of one repo are not three independent sources of threat truth; `operator` is a registered string, not
  verified ownership. The fixtures are commit-pinned, so a new threat/remediation needs governance to re-pin feeds.

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
tests/                        689 direct-mode pytest tests (+ tests/vectors golden corpus)
frontend/                     Next.js 16.4.1 + Tailwind 4 SOC console (591 vitest tests)
```

## Verify

```bash
uv venv --python 3.12 && uv pip install --prerelease=allow -r requirements-dev.txt
export GENVM_VERSION=v0.6.0-rc7
.venv/bin/genvm-lint check contracts/phish_guard.py     # lint + validation
.venv/bin/genvm-lint typecheck contracts/phish_guard.py # 0 errors, 0 diagnostics
.venv/bin/python -m pytest tests -q                     # 689 passed
cd frontend && npm ci && npx tsc --noEmit && npx eslint --max-warnings 0 . && npx vitest run && npm run build
npm audit --registry=https://registry.npmjs.org         # 0 vulnerabilities
```

Deploy: `PHISHGUARD_KEYSTORE_PASSWORD=… PHISHGUARD_SEED_WEI=… npx tsx deploy/deploy_phish_guard.ts`.
