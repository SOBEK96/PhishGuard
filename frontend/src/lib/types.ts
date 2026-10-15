/** Wire types for the PhishGuard contract views. Amounts are decimal strings of wei. */

export type TierNumber = 0 | 1 | 2;

export type TargetState =
  | "UNKNOWN"
  | "DISMISSED"
  | "QUARANTINED"
  | "BLACKLISTED"
  | "CLEARED"
  | "REVOKED_FALSE_POSITIVE"
  | "REMEDIATED";

export interface PoolState {
  balance: string;
  bounty_pool: string;
  reserved_bounty: string;
  locked_slash_reserve: string;
  held_bonds: string;
  total_claimable: string;
  total_shares: string;
  epoch: number;
  epoch_paid: string;
  epoch_cap: string;
  max_epoch_bounty_bps: number;
  tier2_bounty: string;
  min_report_bond: string;
  min_appeal_bond: string;
  cooldown_window: number;
  quarantine_watch: number;
  feed_timelock: number;
  target_count: number;
  total_reports: number;
  solvent: boolean;
}

export interface FeedSource {
  slot: "A" | "B" | "C";
  base_url: string;
  host: string;
  operator: string;
  staged_url: string;
  staged_host: string;
  staged_operator: string;
  staged_ready_at: number;
}

export interface TargetStatus {
  target_id: string;
  known: boolean;
  status: TargetState;
  tier: TierNumber;
  tier_name: string;
  reporter: string;
  bond_amount: string;
  bond_held: string;
  bounty_reserved: string;
  vest_at: number;
  report_ts: number;
  published_ts: number;
  quarantine_until: number;
  override_ts: number;
  evidence_hash: string;
  campaign_id: string;
  brand_id: string;
  first_seen_ts: number;
  source_count: number;
  resolutions: number;
  effective_status: TargetState;
  effective_tier: TierNumber;
  effective_from: string;
  inherited: boolean;
}

export type FirewallVerdict = "ALLOW" | "WARN" | "BLOCK";

export interface SafetyCheck {
  target_id: string;
  known: boolean;
  status: TargetState;
  tier: TierNumber;
  tier_name: string;
  verdict: FirewallVerdict;
  blocked: boolean;
  warn: boolean;
  quarantine_until: number;
  /** The host (exact or registrable parent) whose listing decided the verdict. */
  matched_target: string;
  /** True when the verdict came from a parent domain, not the exact host. */
  inherited: boolean;
}

/** What one threat-intel host answered for a target. */
export type SourceOutcome =
  | { kind: "OK"; tier: TierNumber; status: string; evidenceHash: string; publishedTs: number }
  | { kind: "NOT_FOUND" }
  | { kind: "OUTAGE"; reason: string };

export interface AggregatePayload {
  verdict: 0 | 1 | 2;
  tier: TierNumber;
  source_count: number;
  evidence_hash: string;
  published_ts: number;
}
