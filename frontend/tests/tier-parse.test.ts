import { describe, expect, it } from "vitest";
import { STATUS_COPY, TIER_COLOR, TIER_LABEL, TIER_NAME, isTerminalForReporter, tierFromStatus, verdictForStatus } from "../src/lib/tier";
import { parseFeeds, parsePool, parseSafety, parseTarget } from "../src/lib/parse";
import type { TargetState } from "../src/lib/types";

describe("tiers", () => {
  it("matches the contract tier names", () => {
    expect(TIER_NAME).toEqual({ 0: "TIER_0_SAFE", 1: "TIER_1_SUSPICIOUS", 2: "TIER_2_DRAINER" });
    expect(TIER_LABEL[2]).toBe("DRAINER");
  });
  it("uses the SOC palette", () => {
    expect(TIER_COLOR).toEqual({ 0: "#10B981", 1: "#F59E0B", 2: "#EF4444" });
  });
  it.each<[TargetState, number, string]>([
    ["UNKNOWN", 0, "ALLOW"],
    ["DISMISSED", 0, "ALLOW"],
    ["QUARANTINED", 1, "WARN"],
    ["BLACKLISTED", 2, "BLOCK"],
    ["CLEARED", 0, "ALLOW"],
    ["REVOKED_FALSE_POSITIVE", 0, "ALLOW"],
    ["REMEDIATED", 0, "ALLOW"],
  ])("%s -> tier %d, %s", (status, tier, verdict) => {
    expect(tierFromStatus(status)).toBe(tier);
    expect(verdictForStatus(status)).toBe(verdict);
    expect(STATUS_COPY[status].length).toBeGreaterThan(5);
  });
  it("terminal states", () => {
    expect(isTerminalForReporter("BLACKLISTED")).toBe(false);
    expect(isTerminalForReporter("QUARANTINED")).toBe(false);
    expect(isTerminalForReporter("DISMISSED")).toBe(true);
  });
});

const pool = {
  balance: "500000000000000000", bounty_pool: "500000000000000000", reserved_bounty: "0", locked_slash_reserve: "0",
  held_bonds: "0", total_claimable: "0", total_shares: "500000000000000000", epoch: 2963, epoch_paid: "0",
  epoch_cap: "100000000000000000", max_epoch_bounty_bps: 2000, tier2_bounty: "20000000000000000",
  min_report_bond: "10000000000000000", min_appeal_bond: "10000000000000000", cooldown_window: 86400,
  quarantine_watch: 172800, feed_timelock: 604800, target_count: 0, total_reports: 0, solvent: true,
};

describe("parsePool", () => {
  it("decodes a valid pool", () => expect(parsePool(pool).max_epoch_bounty_bps).toBe(2000));
  it("accepts a Map (SDK calldata shape)", () => expect(parsePool(new Map(Object.entries(pool))).epoch).toBe(2963));
  it("accepts bigint integers", () => expect(parsePool({ ...pool, epoch: 2963n }).epoch).toBe(2963));
  it.each(Object.keys(pool))("throws when %s is missing", (k) => {
    const c: Record<string, unknown> = { ...pool };
    delete c[k];
    expect(() => parsePool(c)).toThrow();
  });
  it("rejects float amounts", () => expect(() => parsePool({ ...pool, epoch: 1.5 })).toThrow());
  it("rejects non-numeric wei", () => expect(() => parsePool({ ...pool, bounty_pool: "1.5" })).toThrow());
  it("rejects non-objects", () => {
    expect(() => parsePool(null)).toThrow();
    expect(() => parsePool([])).toThrow();
  });
});

const target = {
  target_id: "evil.com", known: true, status: "BLACKLISTED", tier: 2, tier_name: "TIER_2_DRAINER", reporter: "0xabc",
  bond_amount: "1", bond_held: "1", bounty_reserved: "2", vest_at: 5, report_ts: 4, published_ts: 3, quarantine_until: 0,
  override_ts: 0, evidence_hash: "a".repeat(64), campaign_id: "c", brand_id: "b", first_seen_ts: 1, source_count: 3, resolutions: 1,
  effective_status: "BLACKLISTED", effective_tier: 2, effective_from: "evil.com", inherited: false,
};

describe("parseTarget / parseSafety / parseFeeds", () => {
  it("decodes a target", () => expect(parseTarget(target).status).toBe("BLACKLISTED"));
  it("rejects an unknown status", () => expect(() => parseTarget({ ...target, status: "HACKED" })).toThrow());
  it("rejects an out-of-range tier", () => expect(() => parseTarget({ ...target, tier: 3 })).toThrow());
  it("decodes a safety check", () => {
    const s = parseSafety({ target_id: "evil.com", known: true, status: "BLACKLISTED", tier: 2, tier_name: "TIER_2_DRAINER", verdict: "BLOCK", blocked: true, warn: false, quarantine_until: 0, matched_target: "evil.com", inherited: false });
    expect(s.verdict).toBe("BLOCK");
    expect(s.inherited).toBe(false);
  });
  it("decodes an inherited subdomain verdict", () => {
    const s = parseSafety({ target_id: "app.evil.com", known: true, status: "BLACKLISTED", tier: 2, tier_name: "TIER_2_DRAINER", verdict: "BLOCK", blocked: true, warn: false, quarantine_until: 0, matched_target: "evil.com", inherited: true });
    expect(s.inherited).toBe(true);
    expect(s.matched_target).toBe("evil.com");
  });
  it("requires the inheritance fields", () => {
    expect(() => parseSafety({ target_id: "x.com", known: false, status: "UNKNOWN", tier: 0, tier_name: "T", verdict: "ALLOW", blocked: false, warn: false, quarantine_until: 0 })).toThrow();
    const { inherited: _i, ...noInherited } = target as Record<string, unknown>;
    void _i;
    expect(() => parseTarget(noInherited)).toThrow();
  });
  it("rejects an unknown verdict", () => {
    expect(() => parseSafety({ target_id: "x.com", known: false, status: "UNKNOWN", tier: 0, tier_name: "T", verdict: "MAYBE", blocked: false, warn: false, quarantine_until: 0, matched_target: "", inherited: false })).toThrow();
  });
  const feed = (slot: string) => ({ slot, base_url: "https://h/", host: "h", operator: "o", staged_url: "", staged_host: "", staged_operator: "", staged_ready_at: 0 });
  it("decodes three feeds", () => expect(parseFeeds([feed("A"), feed("B"), feed("C")])).toHaveLength(3));
  it("requires exactly three feeds", () => {
    expect(() => parseFeeds([feed("A")])).toThrow();
    expect(() => parseFeeds("nope")).toThrow();
  });
  it("rejects an unknown slot", () => expect(() => parseFeeds([feed("A"), feed("B"), feed("Z")])).toThrow());
});
