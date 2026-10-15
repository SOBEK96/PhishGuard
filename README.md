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

## Live deployment (GenLayer Studio Next, chain 61997)

| | |
|---|---|
| Contract | `0x5Ecc98535e3EBBbC965f72ee8C3E411c402CE8DB` |
| Deployer / governor | `0xE6d38f463c03b2B9fB42a9D565c69a1ddc283964` (`phishguard-deployer`) |
| Reporter | `0xfc35738E3c8dA590E1Fe0006E25FD031f93df246` (`phishguard-reporter`) |
| Source SHA-256 | `1336df9c8a3dbc055672e96938d46d9d7885835410262d21536ae7479b1169c8` (equals the on-chain deployed code hash) |
| Feed pin | commit `7f7173bf44bc1b868733978b9675882b9f6ac7f8` |

Transactions (all `ACCEPTED` / `FINISHED_WITH_RETURN` / `MAJORITY_AGREE`):

| Step | Hash |
|---|---|
| deploy | `0xf04e86a9456a2b660182760d6d9a7861b0540353f1c8b0c29f36806e74476305` |
| register_brand uniswap | `0x3de1c3254d56e59a28ec39a87ed9d884904d3a9cadcaa876bc97d4bffc7fa8be` |
| register_brand opensea | `0x1a67f0734b94f05907016b2033862b5d81446526bbf0dd4c951f5c83d59f83a3` |
| register_brand rabby | `0x13ecb1e22dc58253f682ea6d948ba9e33164addf2e131ec45605467503e77b50` |
| register_brand aave | `0x3b6d4a32fa47ccf2db6896e0a6ccca38be32d6168ceb6da9cfe67dcb32d2ee6c` |
| fund_bounty_pool (0.1 GEN) | `0x8f08de485412798406385fc2a5a01868a477fcffc4a1aa499dfc7c39465bb0b8` |
| report_target (0.01 GEN bond, live triage) | `0x59a0d7ad95d726e698307aeac3e96fb7de5d3957db197c2b7a6f56d9d2ccfbf9` |

Live `gen_call` readbacks (full output in `deployments/studio-next.json`):

* `get_target_status("uniswap-claim-airdrop.com")` → `status: BLACKLISTED`, `tier: 2`, `source_count: 3`,
  `bond_held: 10000000000000000`, `bounty_reserved: 20000000000000000`, `vest_at: 1792163020`
* `get_pool_state()` → `bounty_pool: 80000000000000000`, `reserved_bounty: 20000000000000000`,
  `held_bonds: 10000000000000000`, `epoch_cap: 20000000000000000`, `solvent: true`
* `get_feed_sources()` → A `raw.githubusercontent.com`, B `cdn.jsdelivr.net`, C `raw.githack.com`
  (operators `github.com` / `jsdelivr.com` / `githack.com`)
* `check_transaction_safety("uniswap-claim-airdrop.com")` → `verdict: BLOCK`

### Honest deviations from the brief

* **Seed is 0.1 GEN, not 0.5 GEN.** The first deployment (`0x4135EAF1…B01b`, superseded; it hard-reverted on
  `first_seen_ts > now`, which breaks SDK fee simulation) was seeded with 0.5 GEN. I withdrew it with
  `withdraw_pool_shares` + `claim_payout`; the finalized transaction emitted the transfer message but Studio
  Next never executed it (`triggered_transactions` empty, value still on that contract). Those 0.5 GEN are stranded —
  by design there is no admin sweep. **`claim_payout`'s on-chain settlement is therefore unverified on Studio Next.**
* **Faucet credited 0.** `sim_fundAccount` returned hashes but balances stayed 0, so the new accounts were topped up
  from existing unlocked CLI accounts, as the brief allowed.
* Brand registry holds 4 brands to conserve fee deposits.
* Direct-mode tests need the v0.3 runner (`py-genlayer:5jycge…`, `GENVM_VERSION=v0.6.0-rc7`); `genlayer-test`
  0.30.0rc2 cannot load the newer `1jb45…` runner layout.
* Studio Next only: the simulation clock is not the block clock, so time gates must not hard-revert.

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
tests/                        570 direct-mode pytest tests
frontend/                     Next.js 16.4.1 + Tailwind 4 SOC console (450 vitest tests)
```

## Verify

```bash
uv venv --python 3.12 && uv pip install --prerelease=allow -r requirements-dev.txt
export GENVM_VERSION=v0.6.0-rc7
.venv/bin/genvm-lint check contracts/phish_guard.py     # lint + validation
.venv/bin/genvm-lint typecheck contracts/phish_guard.py # 0 errors
.venv/bin/python -m pytest tests -q                     # 570 passed
cd frontend && npm ci && npx tsc --noEmit && npx eslint --max-warnings 0 . && npx vitest run && npm run build
npm audit --registry=https://registry.npmjs.org         # 0 vulnerabilities
```

Deploy: `PHISHGUARD_KEYSTORE_PASSWORD=… PHISHGUARD_SEED_WEI=… npx tsx deploy/deploy_phish_guard.ts`.
