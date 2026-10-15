/**
 * Client-side mirror of the contract's fault-tolerant 2-of-3 aggregation.
 * The Threat Radar uses it to show, per host, WHY a verdict resolves the way it
 * does -- and the unit tests pin it to a brute-force semantic oracle so it
 * cannot drift from the on-chain rules.
 */
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
  for (const s of sources) {
    if (s.kind === "OUTAGE") {
      outage += 1;
      continue;
    }
    clean += 1;
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
  if (outage > 0 && confirms.length + outage >= 2) {
    return { verdict: 2, tier: 0, source_count: clean, evidence_hash: expectedHash, published_ts: 0 };
  }
  let pub = 0;
  for (const s of sources) if (s.kind === "OK" && s.publishedTs > pub) pub = s.publishedTs;
  return { verdict: 0, tier: 0, source_count: clean, evidence_hash: expectedHash, published_ts: pub };
}

/** Same HTTP -> outcome mapping as the contract (`_source_from_response`). */
export function classifyResponse(status: number | null, body: unknown, targetId: string): SourceOutcome {
  if (status === 404 || status === 410) return { kind: "NOT_FOUND" };
  if (status !== 200) return { kind: "OUTAGE", reason: status === null ? "no response" : `HTTP ${status}` };
  let data: unknown = body;
  if (typeof body === "string") {
    if (body.length > 8192) return { kind: "OUTAGE", reason: "oversized body" };
    try {
      data = JSON.parse(body);
    } catch {
      return { kind: "OUTAGE", reason: "invalid JSON" };
    }
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return { kind: "OUTAGE", reason: "schema error" };
  }
  const r = data as Record<string, unknown>;
  const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
  if (r.target_id !== targetId) return { kind: "OUTAGE", reason: "wrong target" };
  if (!isInt(r.tier) || r.tier < 0 || r.tier > 2) return { kind: "OUTAGE", reason: "bad tier" };
  if (typeof r.status !== "string" || !REC_STATUSES.includes(r.status)) return { kind: "OUTAGE", reason: "bad status" };
  if (typeof r.evidence_hash !== "string" || !HASH.test(r.evidence_hash)) return { kind: "OUTAGE", reason: "bad hash" };
  if (!isInt(r.published_ts) || r.published_ts <= 0 || r.published_ts > 4102444800) {
    return { kind: "OUTAGE", reason: "bad published_ts" };
  }
  return {
    kind: "OK",
    tier: r.tier as TierNumber,
    status: r.status,
    evidenceHash: r.evidence_hash,
    publishedTs: r.published_ts,
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
): Promise<SourceOutcome> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(feedUrl(baseUrl, targetId), { signal: ctl.signal, cache: "no-store" });
    if (res.status !== 200) return classifyResponse(res.status, null, targetId);
    return classifyResponse(200, await res.text(), targetId);
  } catch (e) {
    return { kind: "OUTAGE", reason: e instanceof Error ? e.name : "network error" };
  } finally {
    clearTimeout(timer);
  }
}
