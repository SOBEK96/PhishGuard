/** Integer-only formatting: no floats ever touch money or basis points. */

const WEI = 10n ** 18n;

export function toBigInt(v: string | number | bigint | null | undefined): bigint {
  if (v === null || v === undefined || v === "") return 0n;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("unsafe integer");
    return BigInt(v);
  }
  if (!/^-?\d+$/.test(v)) throw new Error(`not an integer string: ${v}`);
  return BigInt(v);
}

/** wei -> "0.0123" GEN with truncation (never rounds up a balance). */
export function formatGen(wei: string | number | bigint, decimals = 4): string {
  const v = toBigInt(wei);
  const neg = v < 0n;
  const abs = neg ? -v : v;
  const whole = abs / WEI;
  const frac = (abs % WEI).toString().padStart(18, "0").slice(0, decimals);
  const out = decimals > 0 ? `${whole}.${frac}` : `${whole}`;
  return neg ? `-${out}` : out;
}

/** "0.01" -> 10000000000000000n. Rejects more than 18 decimals and non-numerics. */
export function parseGen(input: string): bigint {
  const s = input.trim();
  if (!/^\d+(\.\d{1,18})?$/.test(s)) throw new Error("invalid GEN amount");
  const [w, f = ""] = s.split(".");
  return BigInt(w) * WEI + BigInt(f.padEnd(18, "0"));
}

/** basis points -> "20.00%" using integer math only. */
export function bpsToPercent(bps: number): string {
  if (!Number.isInteger(bps) || bps < 0 || bps > 10000) throw new Error("bps out of range");
  const whole = Math.floor(bps / 100);
  const frac = String(bps % 100).padStart(2, "0");
  return `${whole}.${frac}%`;
}

/** share of `part` in `total` as integer basis points (floor). */
export function ratioBps(part: bigint, total: bigint): number {
  if (total <= 0n) return 0;
  const r = (part * 10000n) / total;
  return Number(r > 10000n ? 10000n : r);
}

export function shortHash(h: string, head = 8, tail = 6): string {
  if (h.length <= head + tail + 1) return h;
  return `${h.slice(0, head)}…${h.slice(-tail)}`;
}

export function shortAddress(a: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) return a;
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}
