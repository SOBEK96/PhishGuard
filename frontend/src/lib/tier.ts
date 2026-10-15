import type { FirewallVerdict, TargetState, TierNumber } from "./types";

export const TIER_NAME: Record<TierNumber, string> = {
  0: "TIER_0_SAFE",
  1: "TIER_1_SUSPICIOUS",
  2: "TIER_2_DRAINER",
};

export const TIER_LABEL: Record<TierNumber, string> = {
  0: "SAFE",
  1: "SUSPICIOUS",
  2: "DRAINER",
};

/** Tailwind-free colour tokens (hex) so charts/SVG can reuse them. */
export const TIER_COLOR: Record<TierNumber, string> = {
  0: "#10B981",
  1: "#F59E0B",
  2: "#EF4444",
};

export function tierFromStatus(status: TargetState): TierNumber {
  if (status === "BLACKLISTED") return 2;
  if (status === "QUARANTINED") return 1;
  return 0;
}

export function verdictForStatus(status: TargetState): FirewallVerdict {
  const t = tierFromStatus(status);
  return t === 2 ? "BLOCK" : t === 1 ? "WARN" : "ALLOW";
}

export const STATUS_COPY: Record<TargetState, string> = {
  UNKNOWN: "No triage record. Unlisted targets are allowed.",
  DISMISSED: "Report was unfounded or benign; the reporter bond was forfeited.",
  QUARANTINED: "Suspicious. On a 48h quarantine watch before re-evaluation.",
  BLACKLISTED: "Confirmed wallet drainer. Blocked on-chain for every consumer.",
  CLEARED: "Re-evaluation found no corroborated threat.",
  REVOKED_FALSE_POSITIVE: "Feeds revoked the listing as a false positive.",
  REMEDIATED: "Threat was remediated; listing removed without slashing.",
};

export function isTerminalForReporter(status: TargetState): boolean {
  return ["DISMISSED", "CLEARED", "REVOKED_FALSE_POSITIVE", "REMEDIATED"].includes(status);
}
