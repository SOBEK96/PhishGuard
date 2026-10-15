import { describe, expect, it } from "vitest";
import { SerialLoader } from "../src/lib/serialLoader";

describe("SerialLoader", () => {
  it("loads items serially in order", async () => {
    const order: string[] = [];
    const l = new SerialLoader<number>(async (id) => {
      order.push(id);
      return id.length;
    });
    const snap = await l.load(["a", "bb", "ccc"]);
    expect(order).toEqual(["a", "bb", "ccc"]);
    expect(snap.values).toEqual({ a: 1, bb: 2, ccc: 3 });
    expect(snap.failedIds).toEqual([]);
    expect(snap.loading).toBe(false);
    expect(snap.completedAt).not.toBeNull();
  });

  it("records failures per item and keeps the rest", async () => {
    const l = new SerialLoader<string>(async (id) => {
      if (id === "bad") throw new Error("rpc 500");
      return id.toUpperCase();
    });
    const snap = await l.load(["ok", "bad", "fine"]);
    expect(snap.values).toEqual({ ok: "OK", fine: "FINE" });
    expect(snap.failedIds).toEqual(["bad"]);
    expect(snap.errors.bad).toBe("rpc 500");
  });

  it("retains the previous value when a later poll fails (no silent blanking)", async () => {
    let fail = false;
    const l = new SerialLoader<number>(async () => {
      if (fail) throw new Error("down");
      return 7;
    });
    await l.load(["x"]);
    fail = true;
    const snap = await l.load(["x"]);
    expect(snap.values.x).toBe(7);
    expect(snap.failedIds).toEqual(["x"]);
  });

  it("clears the failure once the item loads again", async () => {
    let fail = true;
    const l = new SerialLoader<number>(async () => {
      if (fail) throw new Error("down");
      return 1;
    });
    await l.load(["x"]);
    fail = false;
    const snap = await l.load(["x"]);
    expect(snap.failedIds).toEqual([]);
    expect(snap.values.x).toBe(1);
  });

  it("drops items that are no longer wanted", async () => {
    const l = new SerialLoader<number>(async () => 1);
    await l.load(["a", "b"]);
    const snap = await l.load(["b"]);
    expect(Object.keys(snap.values)).toEqual(["b"]);
  });

  it("a newer load supersedes an in-flight one", async () => {
    const gates: Record<string, () => void> = {};
    const l = new SerialLoader<string>(
      (id) =>
        new Promise((resolve) => {
          gates[id] = () => resolve(id);
        }),
    );
    const first = l.load(["slow"]);
    await Promise.resolve();
    l.reset();
    const second = l.load(["fast"]);
    await Promise.resolve();
    gates.fast();
    await second;
    gates.slow?.();
    await first;
    const snap = l.snapshot();
    expect(snap.values).toEqual({ fast: "fast" });
  });

  it("reset() clears values, errors and loading", async () => {
    const l = new SerialLoader<number>(async () => {
      throw new Error("x");
    });
    await l.load(["a"]);
    l.reset();
    const s = l.snapshot();
    expect(s.values).toEqual({});
    expect(s.failedIds).toEqual([]);
    expect(s.loading).toBe(false);
    expect(s.completedAt).toBeNull();
  });

  it("surfaces non-Error rejections as strings", async () => {
    const l = new SerialLoader<number>(async () => {
      throw "plain string";
    });
    const s = await l.load(["a"]);
    expect(s.errors.a).toBe("plain string");
  });
});
