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

describe("SerialLoader single-flight (audit P05)", () => {
  const deferred = <V>() => {
    let resolve!: (v: V) => void;
    const promise = new Promise<V>((r) => (resolve = r));
    return { promise, resolve };
  };

  it("a polling tick never cancels a scan in progress; the tail is still loaded", async () => {
    const gates = Array.from({ length: 5 }, () => deferred<number>());
    const started: string[] = [];
    const l = new SerialLoader<number>((id) => {
      started.push(id);
      return gates[Number(id)].promise;
    });
    const ids = ["0", "1", "2", "3", "4"];
    const first = l.load(ids);
    for (let i = 0; i < 3; i++) {
      gates[i].resolve(i + 1);
      await Promise.resolve();
      await Promise.resolve();
    }
    // slow RPC: id "3" is still pending when the next poll tick arrives
    const tick = l.load(ids);
    expect(l.busy).toBe(true);
    gates[3].resolve(4);
    gates[4].resolve(5);
    const snap = await first;
    await tick;
    expect(snap.values).toEqual({ "0": 1, "1": 2, "2": 3, "3": 4, "4": 5 });
    expect(snap.failedIds).toEqual([]);
    expect(started.slice(0, 5)).toEqual(ids);
  });

  it("coalesces many overlapping ticks into exactly one follow-up pass", async () => {
    let calls = 0;
    const g = deferred<number>();
    const l = new SerialLoader<number>(async () => {
      calls++;
      if (calls === 1) return g.promise;
      return calls;
    });
    const p1 = l.load(["a"]);
    l.load(["a"]);
    l.load(["a"]);
    l.load(["a"]);
    g.resolve(1);
    await p1;
    expect(calls).toBe(2); // 1 in-flight pass + 1 coalesced follow-up, not 4
  });

  it("the follow-up pass uses the LATEST requested id list", async () => {
    const g = deferred<string>();
    let first = true;
    const l = new SerialLoader<string>(async (id) => {
      if (first) {
        first = false;
        return g.promise;
      }
      return id;
    });
    const p = l.load(["a"]);
    l.load(["a", "b"]);
    l.load(["a", "b", "c"]);
    g.resolve("a");
    const snap = await p;
    expect(Object.keys(snap.values).sort()).toEqual(["a", "b", "c"]);
  });

  it("publishes progressively and marks completion", async () => {
    const seen: number[] = [];
    const l = new SerialLoader<number>(async (id) => Number(id));
    let lastLoading = true;
    await l.load(["1", "2", "3"], undefined, (s) => {
      seen.push(Object.keys(s.values).length);
      lastLoading = s.loading;
    });
    expect(seen[0]).toBe(1);
    expect(Math.max(...seen)).toBe(3);
    expect(lastLoading).toBe(false);
  });

  it("per-item errors survive a coalesced follow-up pass", async () => {
    const l = new SerialLoader<number>(async (id) => {
      if (id === "bad") throw new Error("boom");
      return 1;
    });
    const p = l.load(["ok", "bad"]);
    l.load(["ok", "bad"]);
    const snap = await p;
    expect(snap.failedIds).toEqual(["bad"]);
    expect(snap.values.ok).toBe(1);
  });

  it("reset() abandons an in-flight pass and a new load starts fresh", async () => {
    const g = deferred<string>();
    const l = new SerialLoader<string>(async (id) => (id === "old" ? g.promise : id));
    const stale = l.load(["old"]);
    l.reset();
    expect(l.busy).toBe(false);
    const fresh = await l.load(["new"]);
    g.resolve("old");
    await stale;
    expect(l.snapshot().values).toEqual({ new: "new" });
    expect(fresh.values).toEqual({ new: "new" });
  });
});
