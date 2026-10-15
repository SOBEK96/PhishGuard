/**
 * Client-side mirror of the contract's fault-tolerant 2-of-3 aggregation.
 * The Threat Radar uses it to show, per host, WHY a verdict resolves the way it
 * does -- and the unit tests pin it to a brute-force semantic oracle so it
 * cannot drift from the on-chain rules.
 */
import { FloatLiteral, parseStrictJson, type JsonValue } from "./strictJson";
import type { AggregatePayload, SourceOutcome, TierNumber } from "./types";

export const VERDICT = { SAFE_OR_UNFOUNDED: 0, VERIFIED_REPORT: 1, QUORUM_FAILURE: 2 } as const;
export const VERDICT_LABEL = ["SAFE_OR_UNFOUNDED", "VERIFIED_REPORT", "QUORUM_FAILURE"] as const;

const REC_STATUSES = ["ACTIVE", "FALSE_POSITIVE_REVOKED", "REMEDIATED"];
const HASH = /^[0-9a-f]{64}$/;

export function isConfirming(s: SourceOutcome, expectedHash: string): boolean {
  return s.kind === "OK" && s.status === "ACTIVE" && s.tier >= 1 && s.evidenceHash === expectedHash;
}

export function aggregate(sources: SourceOutcome[], expectedHash: string): AggregatePayload {
  const confirms: Extract<SourceOutcome, { kind: "OK" }>[] = [];
  let clean = 0;
  let outage = 0;
  let missing = 0;
  for (const s of sources) {
    if (s.kind === "OUTAGE") {
      outage += 1;
      continue;
    }
    clean += 1;
    if (s.kind === "NOT_FOUND") missing += 1;
    if (isConfirming(s, expectedHash)) confirms.push(s as Extract<SourceOutcome, { kind: "OK" }>);
  }
  if (confirms.length >= 2) {
    const tiers = confirms.map((c) => c.tier).sort((a, b) => a - b);
    const tier = (tiers.length === 2 ? tiers[0] : tiers[1]) as TierNumber;
    return {
      verdict: 1,
      tier,
      source_count: clean,
      evidence_hash: expectedHash,
      published_ts: Math.min(...confirms.map((c) => c.publishedTs)),
    };
  }
  // LAG RULE: one confirmation next to any 404/outage is what an honest early
  // report looks like while CDNs propagate -> retryable, never a slash.
  if (confirms.length === 1 && (missing > 0 || outage > 0)) {
    return { verdict: 2, tier: 0, source_count: clean, evidence_hash: expectedHash, published_ts: 0 };
  }
  if (outage > 0 && confirms.length + outage >= 2) {
    return { verdict: 2, tier: 0, source_count: clean, evidence_hash: expectedHash, published_ts: 0 };
  }
  let pub = 0;
  for (const s of sources) if (s.kind === "OK" && s.publishedTs > pub) pub = s.publishedTs;
  return { verdict: 0, tier: 0, source_count: clean, evidence_hash: expectedHash, published_ts: pub };
}

/** Hard ceiling on a feed body (bytes) -- identical to the contract's MAX_BODY_BYTES. */
export const MAX_BODY_BYTES = 8192;
/** A record may not be dated further ahead than this -- the contract's MAX_CLOCK_SKEW. */
export const MAX_CLOCK_SKEW = 3600;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function defaultMaxTs(nowSeconds: number = Math.floor(Date.now() / 1000)): number {
  return nowSeconds + MAX_CLOCK_SKEW;
}

const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
const codePoints = (s: string): number => Array.from(s).length;

/**
 * Same HTTP -> outcome mapping as the contract (`_source_from_response` +
 * `_parse_record`): same required fields, integer rules (a float literal such
 * as `2.0` is NOT an integer), timestamp ceiling, byte-size cap and hash check.
 * Differential-tested against the contract with tests/vectors/feed_parity.json.
 */
export function classifyResponse(
  status: number | null,
  body: string | Uint8Array | null,
  targetId: string,
  maxTs: number = defaultMaxTs(),
): SourceOutcome {
  const outage = (reason: string): SourceOutcome => ({ kind: "OUTAGE", reason });
  if (status === 404 || status === 410) return { kind: "NOT_FOUND" };
  if (status !== 200) return outage(status === null ? "no response" : `HTTP ${status}`);
  if (body === null) return outage("empty body");

  let bytes: Uint8Array;
  if (typeof body === "string") bytes = new TextEncoder().encode(body);
  else bytes = body;
  if (bytes.length > MAX_BODY_BYTES) return outage("oversized body");

  let data: JsonValue;
  try {
    data = parseStrictJson(STRICT_UTF8.decode(bytes));
  } catch {
    return outage("invalid JSON");
  }
  if (typeof data !== "object" || data === null || Array.isArray(data) || data instanceof FloatLiteral) {
    return outage("schema error");
  }
  const r = data as { [k: string]: JsonValue };
  if (r.target_id !== targetId) return outage("wrong target");
  const tier = r.tier;
  if (!isInt(tier) || tier < 0 || tier > 2) return outage("bad tier");
  if (typeof r.status !== "string" || !REC_STATUSES.includes(r.status)) return outage("bad status");
  if (typeof r.evidence_hash !== "string" || !HASH.test(r.evidence_hash)) return outage("bad hash");
  const pub = r.published_ts;
  if (!isInt(pub) || pub <= 0 || pub > maxTs) return outage("bad published_ts");
  const first = r.first_seen_ts;
  if (!isInt(first) || first < 0 || first > maxTs) return outage("bad first_seen_ts");
  if (typeof r.campaign_id !== "string" || codePoints(r.campaign_id) > 64) return outage("bad campaign_id");
  if (typeof r.brand_id !== "string" || codePoints(r.brand_id) > 64) return outage("bad brand_id");
  return {
    kind: "OK",
    tier: tier as TierNumber,
    status: r.status,
    evidenceHash: r.evidence_hash,
    publishedTs: pub,
  };
}

export function feedUrl(baseUrl: string, targetId: string): string {
  return `${baseUrl}${targetId}.json`;
}

/** Fetch one host with a hard timeout; never throws (an outage is a value). */
export async function fetchSource(
  baseUrl: string,
  targetId: string,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 8000,
  maxTs: number = defaultMaxTs(),
): Promise<SourceOutcome> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(feedUrl(baseUrl, targetId), { signal: ctl.signal, cache: "no-store" });
    if (res.status !== 200) return classifyResponse(res.status, null, targetId);
    return classifyResponse(200, new Uint8Array(await res.arrayBuffer()), targetId, maxTs);
  } catch (e) {
    return { kind: "OUTAGE", reason: e instanceof Error ? e.name : "network error" };
  } finally {
    clearTimeout(timer);
  }
}
