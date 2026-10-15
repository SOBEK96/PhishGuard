import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { classifyResponse } from "../src/lib/aggregate";
import { FloatLiteral, parseStrictJson } from "../src/lib/strictJson";

interface Vector {
  name: string;
  status: number;
  body: string;
  expect: "OK" | "NOT_FOUND" | "OUTAGE";
  tier: number | null;
}

const file = JSON.parse(
  readFileSync(path.resolve(__dirname, "../../tests/vectors/feed_parity.json"), "utf8"),
) as { target: string; max_ts: number; vectors: Vector[] };

describe("Python <-> TypeScript feed parity (shared golden vectors)", () => {
  it("has a meaningful corpus", () => {
    expect(file.vectors.length).toBeGreaterThanOrEqual(80);
  });

  it.each(file.vectors.map((v) => [v.name, v] as const))("%s", (_name, v) => {
    const bytes = new TextEncoder().encode(v.body); // production bodies are bytes
    const out = classifyResponse(v.status, bytes, file.target, file.max_ts);
    expect(out.kind).toBe(v.expect);
    if (v.expect === "OK" && out.kind === "OK") expect(out.tier).toBe(v.tier);
  });

  it("agrees on 100% of vectors", () => {
    const mismatches = file.vectors.filter((v) => {
      const out = classifyResponse(v.status, new TextEncoder().encode(v.body), file.target, file.max_ts);
      return out.kind !== v.expect;
    });
    expect(mismatches.map((m) => m.name)).toEqual([]);
  });
});

describe("parseStrictJson", () => {
  it("keeps the int / float distinction", () => {
    expect(parseStrictJson("2")).toBe(2);
    expect(parseStrictJson("2.0")).toBeInstanceOf(FloatLiteral);
    expect(parseStrictJson("2e0")).toBeInstanceOf(FloatLiteral);
    expect(parseStrictJson("-0")).toBe(0);
  });
  it("returns bigint beyond the safe range", () => {
    expect(parseStrictJson("99999999999999999999")).toBe(99999999999999999999n);
  });
  it.each(["", "{", "[1,]", "{\"a\":1,}", "01", "NaN", "Infinity", "\u0000", "'a'", "{\"a\":1} x", "[1 2]", "\"\t\""])(
    "rejects %j",
    (t) => expect(() => parseStrictJson(t)).toThrow(),
  );
  it("last duplicate key wins", () => {
    expect(parseStrictJson('{"a":1,"a":2}')).toEqual({ a: 2 });
  });
  it("decodes escapes", () => {
    expect(parseStrictJson('"\\u00e9\\n\\"x"')).toBe('é\n"x');
  });
  it("limits nesting depth", () => {
    expect(() => parseStrictJson("[".repeat(200) + "]".repeat(200))).toThrow();
  });
});
