/** Mirrors the contract's input rules so bad input never costs a transaction. */

const SLUG = /^[a-z0-9.-]+$/;
const LABEL = /^[a-z0-9_-]+$/;
const HASH = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export function isValidTargetId(s: unknown): s is string {
  if (typeof s !== "string" || s.length < 3 || s.length > 128) return false;
  if (!SLUG.test(s)) return false;
  if (/^[.-]/.test(s) || /[.-]$/.test(s) || s.includes("..")) return false;
  return s.split(".").every((l) => l.length > 0 && !l.startsWith("-") && !l.endsWith("-"));
}

export function isValidLabel(s: unknown, max = 64): s is string {
  return typeof s === "string" && s.length >= 1 && s.length <= max && LABEL.test(s);
}

export function isEvidenceHash(s: unknown): s is string {
  return typeof s === "string" && HASH.test(s);
}

export function isAddress(s: unknown): s is string {
  return typeof s === "string" && ADDRESS.test(s);
}

/**
 * Turn whatever a user pasted ("HTTPS://Evil.COM/claim?x=1", "evil.com:443")
 * into the canonical slug the contract accepts, or null when it cannot be one.
 */
export function normalizeTarget(input: string): string | null {
  let s = input.trim().toLowerCase();
  if (s === "") return null;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.replace(/^[^@/]*@/, "");
  s = s.split(/[/?#]/)[0] ?? "";
  s = s.replace(/:\d+$/, "");
  s = s.replace(/\.$/, "");
  return isValidTargetId(s) ? s : null;
}

export interface Attributes {
  targetId: string;
  campaignId: string;
  brandId: string;
  firstSeenTs: number;
}

export function commitmentPreimage(a: Attributes): string {
  return `phishguard.v1|${a.targetId}|${a.campaignId}|${a.brandId}|${a.firstSeenTs}`;
}

/** SHA-256 commitment over the canonical indicator attributes (matches the contract). */
export async function commitment(a: Attributes): Promise<string> {
  const data = new TextEncoder().encode(commitmentPreimage(a));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface ReportInput {
  targetId: string;
  campaignId: string;
  brandId: string;
  firstSeenTs: number;
  bondWei: bigint;
}

export function validateReport(i: ReportInput, minBondWei: bigint): string | null {
  if (!isValidTargetId(i.targetId)) return "Target must be a lowercase domain slug (a-z, 0-9, '.', '-').";
  if (!isValidLabel(i.campaignId)) return "Campaign id must be 1-64 chars of a-z, 0-9, '_' or '-'.";
  if (!isValidLabel(i.brandId)) return "Brand id must be 1-64 chars of a-z, 0-9, '_' or '-'.";
  if (!Number.isSafeInteger(i.firstSeenTs) || i.firstSeenTs < 0) return "first_seen_ts must be a non-negative integer.";
  if (i.bondWei < minBondWei) return "Bond is below the minimum report bond.";
  return null;
}
