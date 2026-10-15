import { describe, expect, it } from "vitest";
import { clearFor, getFor, normalizeAccount, scope, select, setFor } from "../src/lib/scoped";

const A = "0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaa";
const B = "0xBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbb";

describe("account-scoped state", () => {
  it("normalizes case and nullish", () => {
    expect(normalizeAccount(A)).toBe(A.toLowerCase());
    expect(normalizeAccount(null)).toBe("");
    expect(normalizeAccount(undefined)).toBe("");
  });
  it("returns the value for the owning account (case-insensitive)", () => {
    expect(select(scope(A, 5), A.toLowerCase(), 0)).toBe(5);
  });
  it("returns empty for a different account immediately", () => {
    expect(select(scope(A, 5), B, 0)).toBe(0);
  });
  it("returns empty while no account is connected", () => {
    expect(select(scope(A, 5), null, 0)).toBe(0);
    expect(select(scope(A, 5), "", 0)).toBe(0);
  });
  it("returns empty for missing state", () => {
    expect(select<number>(null, A, -1)).toBe(-1);
    expect(select<number>(undefined, A, -1)).toBe(-1);
  });
  it("keyed banners are isolated per account", () => {
    let banners: Record<string, string> = {};
    banners = setFor(banners, A, "tx a pending");
    banners = setFor(banners, B, "tx b done");
    expect(getFor(banners, A)).toBe("tx a pending");
    expect(getFor(banners, B)).toBe("tx b done");
    banners = clearFor(banners, A);
    expect(getFor(banners, A)).toBeUndefined();
    expect(getFor(banners, B)).toBe("tx b done");
  });
  it("setFor does not mutate the input map", () => {
    const m = { x: 1 };
    setFor(m, A, 2);
    expect(m).toEqual({ x: 1 });
  });
});
