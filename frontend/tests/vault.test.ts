import { describe, expect, it } from "vitest";
import { MIN_LOCKED_SHARES, lockBreakdown, redeemableAssets, validateRedeem } from "../src/lib/vault";
import type { PoolState } from "../src/lib/types";

const pool = (over: Partial<PoolState> = {}): PoolState => ({
  balance: "110000000000000000", bounty_pool: "80000000000000000", reserved_bounty: "20000000000000000",
  locked_slash_reserve: "0", held_bonds: "10000000000000000", total_claimable: "0",
  total_shares: "100000000000000000", epoch: 1, epoch_paid: "0", epoch_cap: "0", max_epoch_bounty_bps: 2000,
  tier2_bounty: "20000000000000000", min_report_bond: "10000000000000000", min_appeal_bond: "10000000000000000",
  cooldown_window: 86400, quarantine_watch: 172800, feed_timelock: 604800, target_count: 0, total_reports: 0,
  solvent: true, ...over,
});

describe("redeemableAssets", () => {
  it("is pro-rata against FREE liquidity only", () => {
    expect(redeemableAssets(50n, 100n, 80n)).toBe(40n);
    expect(redeemableAssets(100n, 100n, 80n)).toBe(80n);
  });
  it("floors", () => expect(redeemableAssets(1n, 3n, 10n)).toBe(3n));
  it.each([[0n, 100n, 80n], [5n, 0n, 80n], [5n, 100n, 0n], [-1n, 100n, 80n]])("is 0 for %s/%s/%s", (s, t, f) => {
    expect(redeemableAssets(s, t, f)).toBe(0n);
  });
  it("never exceeds free liquidity", () => expect(redeemableAssets(200n, 100n, 80n)).toBe(80n));
});

describe("lockBreakdown", () => {
  it("separates free, reserved, held, slash and dead shares", () => {
    const b = lockBreakdown(pool());
    expect(b.freeLiquidity).toBe(80000000000000000n);
    expect(b.reservedBounties).toBe(20000000000000000n);
    expect(b.heldBonds).toBe(10000000000000000n);
    expect(b.deadShares).toBe(MIN_LOCKED_SHARES);
    expect(b.outsideShares).toBe(100000000000000000n - MIN_LOCKED_SHARES);
  });
  it("has no dead shares before the first deposit", () => {
    const b = lockBreakdown(pool({ total_shares: "0", bounty_pool: "0" }));
    expect(b.deadShares).toBe(0n);
    expect(b.outsideShares).toBe(0n);
  });
});

describe("validateRedeem", () => {
  it("accepts a valid request", () => expect(validateRedeem(10n, 100n, 1000n, 500n)).toBeNull());
  it("rejects zero / negative", () => {
    expect(validateRedeem(0n, 100n, 1000n, 500n)).toMatch(/greater than zero/);
    expect(validateRedeem(-1n, 100n, 1000n, 500n)).toMatch(/greater than zero/);
  });
  it("rejects more than held", () => expect(validateRedeem(101n, 100n, 1000n, 500n)).toMatch(/do not hold/));
  it("rejects dust that redeems nothing", () => expect(validateRedeem(1n, 100n, 1_000_000n, 10n)).toMatch(/too small/));
});
