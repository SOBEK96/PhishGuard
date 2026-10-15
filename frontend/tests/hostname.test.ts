import { describe, expect, it } from "vitest";
import { parentChain, PUBLIC_SUFFIXES } from "../src/lib/hostname";

describe("parentChain (mirror of contract._parent_chain)", () => {
  it.each([
    ["evil.com", []],
    ["a.evil.com", ["evil.com"]],
    ["a.b.evil.com", ["b.evil.com", "evil.com"]],
    ["shop.evil.co.uk", ["evil.co.uk"]],
    ["evil.co.uk", []],
    ["x.y.scam.github.io", ["y.scam.github.io", "scam.github.io"]],
    ["localhost-ish", []],
    ["0xdeadbeef", []],
  ])("%s -> %j", (host, chain) => expect(parentChain(host)).toEqual(chain));
  it("never yields a bare TLD or a public suffix", () => {
    for (const h of ["a.b.c.com", "x.co.uk", "q.github.io"]) {
      for (const p of parentChain(h)) {
        expect(p.includes(".")).toBe(true);
        expect(PUBLIC_SUFFIXES).not.toContain(p);
      }
    }
  });
});
