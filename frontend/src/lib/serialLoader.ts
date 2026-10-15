/**
 * Serial loader with per-item failure retention.
 *
 * - Items load one at a time (RPC friendly, deterministic ordering).
 * - A failed item keeps its previous value and is recorded in `failedIds`, so a
 *   partial outage never blanks (or silently "succeeds" over) good data.
 * - A newer `load()` supersedes an older in-flight one: late results from the
 *   older generation are dropped instead of overwriting fresh state.
 */
export interface LoaderSnapshot<T> {
  values: Record<string, T>;
  failedIds: string[];
  errors: Record<string, string>;
  loading: boolean;
  generation: number;
  completedAt: number | null;
}

export class SerialLoader<T> {
  private values: Record<string, T> = {};
  private errors: Record<string, string> = {};
  private loading = false;
  private generation = 0;
  private completedAt: number | null = null;

  constructor(private readonly fetchOne: (id: string) => Promise<T>) {}

  snapshot(): LoaderSnapshot<T> {
    return {
      values: { ...this.values },
      failedIds: Object.keys(this.errors).sort(),
      errors: { ...this.errors },
      loading: this.loading,
      generation: this.generation,
      completedAt: this.completedAt,
    };
  }

  /** Drop everything (used when the active account changes). */
  reset(): void {
    this.generation += 1;
    this.values = {};
    this.errors = {};
    this.loading = false;
    this.completedAt = null;
  }

  async load(ids: string[], now: () => number = () => Date.now()): Promise<LoaderSnapshot<T>> {
    const gen = ++this.generation;
    this.loading = true;
    const wanted = new Set(ids);
    for (const id of Object.keys(this.values)) if (!wanted.has(id)) delete this.values[id];
    for (const id of Object.keys(this.errors)) if (!wanted.has(id)) delete this.errors[id];

    for (const id of ids) {
      if (gen !== this.generation) return this.snapshot(); // superseded
      try {
        const v = await this.fetchOne(id);
        if (gen !== this.generation) return this.snapshot();
        this.values[id] = v;
        delete this.errors[id];
      } catch (e) {
        if (gen !== this.generation) return this.snapshot();
        this.errors[id] = e instanceof Error ? e.message : String(e);
        // previous value (if any) is deliberately retained
      }
    }
    if (gen === this.generation) {
      this.loading = false;
      this.completedAt = now();
    }
    return this.snapshot();
  }
}
