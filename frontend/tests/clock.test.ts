import { describe, expect, it } from "vitest";
import { MonotonicClock } from "../src/lib/clock";

function mk() {
  let local = 1_000_000;
  const clock = new MonotonicClock(() => local);
  return { clock, advance: (ms: number) => (local += ms) };
}

describe("MonotonicClock", () => {
  it("has no chain time before the first observation", () => {
    const { clock } = mk();
    expect(clock.hasChainTime).toBe(false);
    expect(clock.now()).toBe(0);
  });
  it("tracks the first observation and advances with local time", () => {
    const { clock, advance } = mk();
    expect(clock.observe(1000)).toBe(true);
    expect(clock.now()).toBe(1000);
    advance(5000);
    expect(clock.now()).toBe(1005);
  });
  it("ignores older chain timestamps (failed/stale poll never rewinds)", () => {
    const { clock, advance } = mk();
    clock.observe(2000);
    advance(10_000);
    expect(clock.now()).toBe(2010);
    expect(clock.observe(1500)).toBe(false);
    expect(clock.now()).toBe(2010);
  });
  it("ignores equal timestamps", () => {
    const { clock } = mk();
    clock.observe(2000);
    expect(clock.observe(2000)).toBe(false);
  });
  it("accepts a newer timestamp and never decreases now()", () => {
    const { clock, advance } = mk();
    clock.observe(1000);
    advance(100_000); // projected 1100
    const before = clock.now();
    clock.observe(1050); // newer than 1000 but behind the projection
    expect(clock.now()).toBeGreaterThanOrEqual(before);
  });
  it.each([0, -5, NaN, Infinity])("rejects bogus observation %s", (v) => {
    const { clock } = mk();
    expect(clock.observe(v)).toBe(false);
    expect(clock.hasChainTime).toBe(false);
  });
  it("remaining() counts down and bottoms out at 0", () => {
    const { clock, advance } = mk();
    clock.observe(1000);
    expect(clock.remaining(1060)).toBe(60);
    advance(30_000);
    expect(clock.remaining(1060)).toBe(30);
    advance(60_000);
    expect(clock.remaining(1060)).toBe(0);
  });
  it("a failed poll between ticks does not rewind a countdown", () => {
    const { clock, advance } = mk();
    clock.observe(1000);
    advance(20_000);
    const r1 = clock.remaining(1100);
    clock.observe(900); // stale replica
    expect(clock.remaining(1100)).toBeLessThanOrEqual(r1);
  });
});
