import { describe, expect, it } from "vitest";
import { bpsToPercent, formatDuration, formatGen, parseGen, ratioBps, shortAddress, shortHash, toBigInt } from "../src/lib/format";

describe("formatGen", () => {
  it.each([
    ["0", "0.0000"],
    ["1", "0.0000"],
    ["10000000000000000", "0.0100"],
    ["500000000000000000", "0.5000"],
    ["1000000000000000000", "1.0000"],
    ["1234567890000000000", "1.2345"],
    ["999999999999999999", "0.9999"],
    ["123000000000000000000", "123.0000"],
  ])("%s wei -> %s GEN", (wei, out) => {
    expect(formatGen(wei)).toBe(out);
  });
  it("truncates, never rounds up", () => {
    expect(formatGen("19999999999999999")).toBe("0.0199");
  });
  it("supports custom decimals and bigint input", () => {
    expect(formatGen(10n ** 18n, 2)).toBe("1.00");
    expect(formatGen(10n ** 18n, 0)).toBe("1");
  });
  it("handles negatives", () => {
    expect(formatGen(-(10n ** 18n))).toBe("-1.0000");
  });
});

describe("parseGen", () => {
  it.each([
    ["0.01", 10n ** 16n],
    ["1", 10n ** 18n],
    ["0.5", 5n * 10n ** 17n],
    ["0.000000000000000001", 1n],
    ["12.345", 12345n * 10n ** 15n],
  ])("%s -> %s", (s, wei) => {
    expect(parseGen(s)).toBe(wei);
  });
  it.each(["", "abc", "-1", "1e5", "1.2.3", "0.0000000000000000001", " ", "1,5", "0x10"])("rejects %j", (s) => {
    expect(() => parseGen(s)).toThrow();
  });
  it("round-trips with formatGen at 18 decimals", () => {
    expect(formatGen(parseGen("3.141592653589793238"), 18)).toBe("3.141592653589793238");
  });
});

describe("toBigInt", () => {
  it("accepts strings, numbers, bigint, nullish", () => {
    expect(toBigInt("42")).toBe(42n);
    expect(toBigInt(7)).toBe(7n);
    expect(toBigInt(9n)).toBe(9n);
    expect(toBigInt(null)).toBe(0n);
    expect(toBigInt(undefined)).toBe(0n);
    expect(toBigInt("")).toBe(0n);
  });
  it("rejects floats and junk", () => {
    expect(() => toBigInt(1.5)).toThrow();
    expect(() => toBigInt("1.5")).toThrow();
    expect(() => toBigInt("abc")).toThrow();
  });
});

describe("basis points", () => {
  it.each([
    [0, "0.00%"],
    [1, "0.01%"],
    [2000, "20.00%"],
    [9999, "99.99%"],
    [10000, "100.00%"],
  ])("%d bps -> %s", (bps, out) => {
    expect(bpsToPercent(bps)).toBe(out);
  });
  it.each([-1, 10001, 1.5, NaN])("rejects %s", (bps) => {
    expect(() => bpsToPercent(bps)).toThrow();
  });
  it("ratioBps is integer, floored and clamped", () => {
    expect(ratioBps(1n, 3n)).toBe(3333);
    expect(ratioBps(0n, 0n)).toBe(0);
    expect(ratioBps(5n, 2n)).toBe(10000);
    expect(Number.isInteger(ratioBps(2n, 7n))).toBe(true);
  });
});

describe("display helpers", () => {
  it("shortens hashes and addresses", () => {
    expect(shortHash("a".repeat(64))).toBe("aaaaaaaa…aaaaaa");
    expect(shortHash("abc")).toBe("abc");
    expect(shortAddress("0x" + "ab".repeat(20))).toBe("0xabab…abab");
    expect(shortAddress("not-an-address")).toBe("not-an-address");
  });
  it.each([
    [0, "0s"],
    [59, "59s"],
    [61, "1m 1s"],
    [3661, "1h 1m 1s"],
    [90061, "1d 1h 1m"],
    [-5, "0s"],
  ])("formatDuration(%d) = %s", (s, out) => {
    expect(formatDuration(s)).toBe(out);
  });
});
