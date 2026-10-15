import { describe, expect, it } from "vitest";
import { aggregate, classifyResponse, feedUrl, fetchSource, isConfirming } from "../src/lib/aggregate";
import type { SourceOutcome } from "../src/lib/types";

const EV = "a".repeat(64);
const mkOk = (tier: 0 | 1 | 2, extra: Partial<Extract<SourceOutcome, { kind: "OK" }>> = {}): SourceOutcome => ({
  kind: "OK", tier, status: "ACTIVE", evidenceHash: EV, publishedTs: 1000, ...extra,
});
const SYM: Record<string, SourceOutcome> = {
  C2: mkOk(2),
  C1: mkOk(1),
  S: mkOk(0),
  M: mkOk(2, { evidenceHash: "b".repeat(64) }),
  X: { kind: "NOT_FOUND" },
  U: { kind: "OUTAGE", reason: "x" },
};
const KEYS = Object.keys(SYM);

/** Independent oracle: verdict is whatever EVERY completion of the outages agrees on. */
function oracle(syms: string[]): number {
  // LAG RULE: exactly one confirmation next to any 404/outage is a retryable failure.
  const confirmations = syms.filter((s) => s === "C1" || s === "C2").length;
  if (confirmations === 1 && syms.some((s) => s === "X" || s === "U")) return 2;
  const known = syms.filter((s) => s !== "U");
  const nOut = syms.length - known.length;
  const confirm = known.filter((s) => s === "C1" || s === "C2").length;
  const outcomes = new Set<number>();
  for (let mask = 0; mask < 1 << nOut; mask++) {
    let extra = 0;
    for (let b = 0; b < nOut; b++) if (mask & (1 << b)) extra++;
    outcomes.add(confirm + extra >= 2 ? 1 : 0);
  }
  return outcomes.size === 1 ? [...outcomes][0] : 2;
}

describe("aggregate vs semantic oracle (all 216 source combinations)", () => {
  const combos: string[][] = [];
  for (const a of KEYS) for (const b of KEYS) for (const c of KEYS) combos.push([a, b, c]);
  it.each(combos)("%s %s %s", (a, b, c) => {
    const p = aggregate([SYM[a], SYM[b], SYM[c]], EV);
    expect(p.verdict).toBe(oracle([a, b, c]));
    expect(p.evidence_hash).toBe(EV);
  });
});

describe("lag rule (single confirmation + 404/outage)", () => {
  it.each([
    ["C2", "X", "X"], ["C1", "X", "X"], ["X", "C2", "X"], ["X", "X", "C2"],
    ["C2", "X", "U"], ["C2", "U", "U"], ["C2", "S", "X"], ["C2", "M", "X"], ["S", "X", "C1"],
  ])("%s %s %s -> QUORUM_FAILURE", (a, b, c) => {
    const p = aggregate([SYM[a], SYM[b], SYM[c]], EV);
    expect(p.verdict).toBe(2);
    expect(p.tier).toBe(0);
    expect(p.published_ts).toBe(0);
  });
  it.each([
    ["C2", "S", "S"], ["C2", "M", "S"], ["C1", "M", "M"],
  ])("%s %s %s (everyone answered cleanly) -> still dismissed", (a, b, c) => {
    expect(aggregate([SYM[a], SYM[b], SYM[c]], EV).verdict).toBe(0);
  });
  it.each([["X", "X", "X"], ["X", "X", "U"], ["S", "S", "X"]])("%s %s %s (no confirmation) -> dismissed", (a, b, c) => {
    expect(aggregate([SYM[a], SYM[b], SYM[c]], EV).verdict).toBe(0);
  });
});

describe("aggregate details", () => {
  it("spec case: CONFIRMED + 404 + OUTAGE is a retryable quorum failure", () => {
    expect(aggregate([SYM.C2, SYM.X, SYM.U], EV).verdict).toBe(2);
  });
  it("two confirmations survive an outage", () => {
    const p = aggregate([SYM.C2, SYM.C2, SYM.U], EV);
    expect(p.verdict).toBe(1);
    expect(p.source_count).toBe(2);
  });
  it("2-source tier is the conservative minimum", () => {
    expect(aggregate([mkOk(1), mkOk(2), SYM.X], EV).tier).toBe(1);
  });
  it("3-source tier is the median", () => {
    expect(aggregate([mkOk(1), mkOk(2), mkOk(2)], EV).tier).toBe(2);
    expect(aggregate([mkOk(1), mkOk(1), mkOk(2)], EV).tier).toBe(1);
  });
  it("published_ts is the earliest confirming record", () => {
    const p = aggregate([mkOk(2, { publishedTs: 30 }), mkOk(2, { publishedTs: 10 }), mkOk(2, { publishedTs: 20 })], EV);
    expect(p.published_ts).toBe(10);
  });
  it("revoked / remediated records never confirm", () => {
    for (const status of ["FALSE_POSITIVE_REVOKED", "REMEDIATED"]) {
      const s = mkOk(2, { status });
      expect(isConfirming(s, EV)).toBe(false);
      expect(aggregate([s, s, s], EV).verdict).toBe(0);
    }
  });
  it("a mismatched evidence hash never confirms", () => {
    expect(isConfirming(SYM.M, EV)).toBe(false);
  });
  it("quorum failure carries tier 0 and no timestamp", () => {
    const p = aggregate([SYM.U, SYM.U, SYM.U], EV);
    expect(p).toMatchObject({ verdict: 2, tier: 0, published_ts: 0, source_count: 0 });
  });
});

describe("classifyResponse", () => {
  const rec = {
    target_id: "evil.com", tier: 2, status: "ACTIVE", evidence_hash: EV, published_ts: 1700000000,
    campaign_id: "c", brand_id: "b", first_seen_ts: 1,
  };
  it("maps 404/410 to NOT_FOUND", () => {
    expect(classifyResponse(404, null, "evil.com").kind).toBe("NOT_FOUND");
    expect(classifyResponse(410, null, "evil.com").kind).toBe("NOT_FOUND");
  });
  it.each([500, 502, 503, 429, 301, 403, 401, 204])("maps %d to OUTAGE", (code) => {
    expect(classifyResponse(code, null, "evil.com").kind).toBe("OUTAGE");
  });
  it("maps a missing status to OUTAGE", () => {
    expect(classifyResponse(null, null, "evil.com").kind).toBe("OUTAGE");
  });
  it("parses a valid record", () => {
    const s = classifyResponse(200, JSON.stringify(rec), "evil.com");
    expect(s).toMatchObject({ kind: "OK", tier: 2, status: "ACTIVE", evidenceHash: EV, publishedTs: 1700000000 });
  });
  it.each([
    ["not json", "{nope"],
    ["array", "[]"],
    ["null", "null"],
    ["wrong target", JSON.stringify({ ...rec, target_id: "other.com" })],
    ["bad tier", JSON.stringify({ ...rec, tier: 3 })],
    ["float tier", JSON.stringify({ ...rec, tier: 1.5 })],
    ["bad status", JSON.stringify({ ...rec, status: "PENDING" })],
    ["bad hash", JSON.stringify({ ...rec, evidence_hash: "zz" })],
    ["bad ts", JSON.stringify({ ...rec, published_ts: 0 })],
    ["oversized", JSON.stringify({ ...rec, pad: "x".repeat(9000) })],
    ["missing first_seen_ts", JSON.stringify({ ...rec, first_seen_ts: undefined })],
    ["missing campaign_id", JSON.stringify({ ...rec, campaign_id: undefined })],
    ["missing brand_id", JSON.stringify({ ...rec, brand_id: undefined })],
    ["float literal tier", JSON.stringify(rec).replace('"tier":2', '"tier":2.0')],
    ["future published_ts", JSON.stringify({ ...rec, published_ts: 4000000000 })],
  ])("200 + %s is an OUTAGE, never a 404", (_n, body) => {
    expect(classifyResponse(200, body, "evil.com").kind).toBe("OUTAGE");
  });
});

describe("fetchSource", () => {
  const ok = (body: unknown, status = 200) =>
    (async () => {
      const text = typeof body === "string" ? body : JSON.stringify(body);
      return { status, arrayBuffer: async () => new TextEncoder().encode(text).buffer } as unknown as Response;
    }) as typeof fetch;
  it("builds the feed URL from base + slug", () => {
    expect(feedUrl("https://h.example/x/", "evil.com")).toBe("https://h.example/x/evil.com.json");
  });
  it("never throws on network failure", async () => {
    const boom = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;
    const s = await fetchSource("https://h.example/", "evil.com", boom);
    expect(s.kind).toBe("OUTAGE");
  });
  it("maps a 404", async () => {
    expect((await fetchSource("https://h.example/", "evil.com", ok("", 404))).kind).toBe("NOT_FOUND");
  });
  it("parses a good body", async () => {
    const body = { target_id: "evil.com", tier: 1, status: "ACTIVE", evidence_hash: EV, published_ts: 5, first_seen_ts: 1, campaign_id: "c", brand_id: "b" };
    expect((await fetchSource("https://h.example/", "evil.com", ok(body))).kind).toBe("OK");
  });
});
