/**
 * Monotone chain clock. Chain timestamps are observed from reads; a failed or
 * stale poll must never rewind a countdown. `now()` advances with the local
 * clock between observations and only ever moves forward.
 */
export class MonotonicClock {
  private chainTs = 0;
  private observedAtLocal = 0;
  private last = 0;

  constructor(private readonly localNow: () => number = () => Date.now()) {}

  /** Record a chain timestamp (seconds). Older or equal readings are ignored. */
  observe(chainTsSeconds: number): boolean {
    if (!Number.isFinite(chainTsSeconds) || chainTsSeconds <= 0) return false;
    const ts = Math.floor(chainTsSeconds);
    if (ts <= this.chainTs) return false;
    this.chainTs = ts;
    this.observedAtLocal = this.localNow();
    return true;
  }

  private projected(): number {
    if (this.chainTs === 0) return 0;
    return this.chainTs + Math.floor((this.localNow() - this.observedAtLocal) / 1000);
  }

  /** Current best estimate of chain time in seconds; never decreases. */
  now(): number {
    const p = this.projected();
    if (p > this.last) this.last = p;
    return this.last;
  }

  /** Seconds until `target` (0 once reached), against the monotone clock. */
  remaining(targetTs: number): number {
    const n = this.now();
    if (n === 0) return Math.max(0, targetTs);
    return Math.max(0, targetTs - n);
  }

  get hasChainTime(): boolean {
    return this.chainTs !== 0;
  }
}
