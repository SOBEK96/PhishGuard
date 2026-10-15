/** Strict decoders for contract view output: never trust the wire shape. */
import type { FeedSource, PoolState, SafetyCheck, TargetState, TargetStatus, TierNumber } from "./types";

const STATES: TargetState[] = [
  "UNKNOWN", "DISMISSED", "QUARANTINED", "BLACKLISTED", "CLEARED", "REVOKED_FALSE_POSITIVE", "REMEDIATED",
];

function obj(v: unknown, what: string): Record<string, unknown> {
  if (v instanceof Map) return Object.fromEntries(v) as Record<string, unknown>;
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`${what}: expected object`);
  return v as Record<string, unknown>;
}

function str(o: Record<string, unknown>, k: string): string {
  const v = o[k];
  if (typeof v !== "string") throw new Error(`${k}: expected string`);
  return v;
}

function wei(o: Record<string, unknown>, k: string): string {
  const v = o[k];
  const s = typeof v === "bigint" ? v.toString() : v;
  if (typeof s !== "string" || !/^\d+$/.test(s)) throw new Error(`${k}: expected wei string`);
  return s;
}

function int(o: Record<string, unknown>, k: string): number {
  const v = o[k];
  const n = typeof v === "bigint" ? Number(v) : v;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) throw new Error(`${k}: expected non-negative integer`);
  return n;
}

function bool(o: Record<string, unknown>, k: string): boolean {
  if (typeof o[k] !== "boolean") throw new Error(`${k}: expected boolean`);
  return o[k] as boolean;
}

function tier(o: Record<string, unknown>, k: string): TierNumber {
  const n = int(o, k);
  if (n > 2) throw new Error(`${k}: tier out of range`);
  return n as TierNumber;
}

function state(o: Record<string, unknown>, k: string): TargetState {
  const s = str(o, k);
  if (!STATES.includes(s as TargetState)) throw new Error(`${k}: unknown status ${s}`);
  return s as TargetState;
}

export function parsePool(v: unknown): PoolState {
  const o = obj(v, "pool");
  return {
    balance: wei(o, "balance"),
    bounty_pool: wei(o, "bounty_pool"),
    reserved_bounty: wei(o, "reserved_bounty"),
    locked_slash_reserve: wei(o, "locked_slash_reserve"),
    held_bonds: wei(o, "held_bonds"),
    total_claimable: wei(o, "total_claimable"),
    total_shares: wei(o, "total_shares"),
    epoch: int(o, "epoch"),
    epoch_paid: wei(o, "epoch_paid"),
    epoch_cap: wei(o, "epoch_cap"),
    max_epoch_bounty_bps: int(o, "max_epoch_bounty_bps"),
    tier2_bounty: wei(o, "tier2_bounty"),
    min_report_bond: wei(o, "min_report_bond"),
    min_appeal_bond: wei(o, "min_appeal_bond"),
    cooldown_window: int(o, "cooldown_window"),
    quarantine_watch: int(o, "quarantine_watch"),
    feed_timelock: int(o, "feed_timelock"),
    target_count: int(o, "target_count"),
    total_reports: int(o, "total_reports"),
    solvent: bool(o, "solvent"),
  };
}

export function parseFeeds(v: unknown): FeedSource[] {
  const arr = Array.isArray(v) ? v : null;
  if (!arr || arr.length !== 3) throw new Error("feeds: expected 3 sources");
  return arr.map((raw, i) => {
    const o = obj(raw, `feed[${i}]`);
    const slot = str(o, "slot");
    if (slot !== "A" && slot !== "B" && slot !== "C") throw new Error("feed slot");
    return {
      slot,
      base_url: str(o, "base_url"),
      host: str(o, "host"),
      operator: str(o, "operator"),
      staged_url: str(o, "staged_url"),
      staged_host: str(o, "staged_host"),
      staged_operator: str(o, "staged_operator"),
      staged_ready_at: int(o, "staged_ready_at"),
    };
  });
}

export function parseTarget(v: unknown): TargetStatus {
  const o = obj(v, "target");
  return {
    target_id: str(o, "target_id"),
    known: bool(o, "known"),
    status: state(o, "status"),
    tier: tier(o, "tier"),
    tier_name: str(o, "tier_name"),
    reporter: str(o, "reporter"),
    bond_amount: wei(o, "bond_amount"),
    bond_held: wei(o, "bond_held"),
    bounty_reserved: wei(o, "bounty_reserved"),
    vest_at: int(o, "vest_at"),
    report_ts: int(o, "report_ts"),
    published_ts: int(o, "published_ts"),
    quarantine_until: int(o, "quarantine_until"),
    override_ts: int(o, "override_ts"),
    evidence_hash: str(o, "evidence_hash"),
    campaign_id: str(o, "campaign_id"),
    brand_id: str(o, "brand_id"),
    first_seen_ts: int(o, "first_seen_ts"),
    source_count: int(o, "source_count"),
    resolutions: int(o, "resolutions"),
    effective_status: state(o, "effective_status"),
    effective_tier: tier(o, "effective_tier"),
    effective_from: str(o, "effective_from"),
    inherited: bool(o, "inherited"),
  };
}

export function parseSafety(v: unknown): SafetyCheck {
  const o = obj(v, "safety");
  const verdict = str(o, "verdict");
  if (verdict !== "ALLOW" && verdict !== "WARN" && verdict !== "BLOCK") throw new Error("verdict");
  return {
    target_id: str(o, "target_id"),
    known: bool(o, "known"),
    status: state(o, "status"),
    tier: tier(o, "tier"),
    tier_name: str(o, "tier_name"),
    verdict,
    blocked: bool(o, "blocked"),
    warn: bool(o, "warn"),
    quarantine_until: int(o, "quarantine_until"),
    matched_target: str(o, "matched_target"),
    inherited: bool(o, "inherited"),
  };
}
