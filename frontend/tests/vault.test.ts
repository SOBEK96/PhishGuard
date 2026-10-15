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

import { vestStatus } from "../src/lib/vault";
import { parseVestEntry } from "../src/lib/parse";
import type { VestEntry } from "../src/lib/types";

describe("vestStatus (superseded escrow keeps its own cooldown)", () => {
  const A = "0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaa";
  const B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const e = (id: number, owner: string, bounty: string, vest_at: number, bond = "0"): VestEntry => ({
    id, owner, target_id: `t${id}.com`, bond, bounty, vest_at,
  });
  it("splits an owner's entries into claimable and pending by THEIR vest time", () => {
    const r = vestStatus([e(0, A, "1", 100), e(1, A, "1", 500), e(2, B, "1", 100)], A.toLowerCase(), 200);
    expect(r.claimable.map((x) => x.id)).toEqual([0]);
    expect(r.pending.map((x) => x.id)).toEqual([1]);
  });
  it("a vest time equal to now is claimable", () => {
    expect(vestStatus([e(0, A, "1", 200)], A, 200).claimable).toHaveLength(1);
  });
  it("ignores emptied entries and other owners / no account", () => {
    expect(vestStatus([e(0, A, "0", 100)], A, 200).claimable).toHaveLength(0);
    expect(vestStatus([e(0, B, "1", 100)], A, 200).claimable).toHaveLength(0);
    expect(vestStatus([e(0, A, "1", 100)], "", 200).claimable).toHaveLength(0);
  });
  it("bond-only entries count as value", () => {
    expect(vestStatus([e(0, A, "0", 100, "5")], A, 200).claimable).toHaveLength(1);
  });
});

describe("parseVestEntry", () => {
  it("decodes", () => {
    expect(parseVestEntry({ id: 3, owner: "0xabc", target_id: "x.com", bond: "0", bounty: "20000000000000000", vest_at: 9 }).bounty).toBe("20000000000000000");
  });
  it("rejects bad shapes", () => {
    expect(() => parseVestEntry({ id: 3, owner: "0xabc", target_id: "x.com", bond: "0", bounty: "1.5", vest_at: 9 })).toThrow();
    expect(() => parseVestEntry({ id: -1, owner: "0xabc", target_id: "x.com", bond: "0", bounty: "1", vest_at: 9 })).toThrow();
  });
});
