import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  commitment,
  commitmentPreimage,
  isAddress,
  isEvidenceHash,
  isValidLabel,
  isValidTargetId,
  normalizeTarget,
  validateReport,
} from "../src/lib/validation";

describe("isValidTargetId", () => {
  it.each(["uniswap-claim-airdrop.com", "a.b", "abc", "0xdeadbeef", "x".repeat(128), "sub.domain.example.org", "1inch-claim.io"])(
    "accepts %s",
    (s) => expect(isValidTargetId(s)).toBe(true),
  );
  it.each([
    "", "ab", "x".repeat(129), "UPPER.com", "has space.com", "a/b.com", "a..b.com", ".lead.com", "trail.com.",
    "-lead.com", "trail-.com", "a?b.com", "a#b.com", "http://evil.com", "a@b.com", "a:b.com", "tab\t.com",
  ])("rejects %j", (s) => expect(isValidTargetId(s)).toBe(false));
  it.each([null, undefined, 5, {}, []])("rejects non-string %j", (v) => expect(isValidTargetId(v)).toBe(false));
});

describe("labels, hashes, addresses", () => {
  it.each([["permit2-airdrop-2026q4", true], ["a_b-c", true], ["", false], ["Has.Dot", false], ["x".repeat(65), false]])(
    "label %j -> %s",
    (s, ok) => expect(isValidLabel(s)).toBe(ok),
  );
  it.each([["a".repeat(64), true], ["A".repeat(64), false], ["a".repeat(63), false], ["g".repeat(64), false], ["", false]])(
    "hash %j -> %s",
    (s, ok) => expect(isEvidenceHash(s)).toBe(ok),
  );
  it.each([["0x" + "a".repeat(40), true], ["0x" + "A".repeat(40), true], ["0x123", false], ["a".repeat(42), false], ["", false]])(
    "address %j -> %s",
    (s, ok) => expect(isAddress(s)).toBe(ok),
  );
});

describe("normalizeTarget", () => {
  it.each([
    ["HTTPS://Uniswap-Claim-Airdrop.COM/claim?x=1#y", "uniswap-claim-airdrop.com"],
    ["evil.com:443", "evil.com"],
    ["  evil.com  ", "evil.com"],
    ["http://user:pw@evil.com/path", "evil.com"],
    ["evil.com.", "evil.com"],
    ["sub.evil.com/a/b", "sub.evil.com"],
    ["ftp://files.evil.org", "files.evil.org"],
  ])("%j -> %j", (input, out) => expect(normalizeTarget(input)).toBe(out));
  it.each(["", "   ", "not a domain", "a..b.com", "-bad.com", "//", "https://"])("returns null for %j", (input) => {
    expect(normalizeTarget(input)).toBeNull();
  });
});

describe("commitment", () => {
  const attrs = { targetId: "uniswap-claim-airdrop.com", campaignId: "permit2-airdrop-2026q4", brandId: "uniswap", firstSeenTs: 1790000000 };
  it("matches the contract preimage and SHA-256", async () => {
    expect(commitmentPreimage(attrs)).toBe("phishguard.v1|uniswap-claim-airdrop.com|permit2-airdrop-2026q4|uniswap|1790000000");
    const expected = createHash("sha256").update(commitmentPreimage(attrs)).digest("hex");
    expect(await commitment(attrs)).toBe(expected);
  });
  it("equals the value pinned in the deployed fixtures", async () => {
    expect(await commitment(attrs)).toBe("e703e5c6ef0cf8d1a358411cb4bd4143ec312adbc6e74b569e85e91d29b98e47");
  });
  it("changes with every attribute", async () => {
    const base = await commitment(attrs);
    expect(await commitment({ ...attrs, targetId: "other.com" })).not.toBe(base);
    expect(await commitment({ ...attrs, campaignId: "x" })).not.toBe(base);
    expect(await commitment({ ...attrs, brandId: "x" })).not.toBe(base);
    expect(await commitment({ ...attrs, firstSeenTs: 1 })).not.toBe(base);
  });
});

describe("validateReport", () => {
  const ok = { targetId: "evil.com", campaignId: "c1", brandId: "b1", firstSeenTs: 100, bondWei: 10n ** 16n };
  const min = 10n ** 16n;
  it("accepts a well-formed report", () => expect(validateReport(ok, min)).toBeNull());
  it("rejects each bad field with a message", () => {
    expect(validateReport({ ...ok, targetId: "Bad Target" }, min)).toMatch(/Target/);
    expect(validateReport({ ...ok, campaignId: "" }, min)).toMatch(/Campaign/);
    expect(validateReport({ ...ok, brandId: "A B" }, min)).toMatch(/Brand/);
    expect(validateReport({ ...ok, firstSeenTs: -1 }, min)).toMatch(/first_seen/);
    expect(validateReport({ ...ok, firstSeenTs: 1.5 }, min)).toMatch(/first_seen/);
    expect(validateReport({ ...ok, bondWei: min - 1n }, min)).toMatch(/Bond/);
  });
});
