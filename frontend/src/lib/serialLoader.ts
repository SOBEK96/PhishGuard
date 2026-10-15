/**
 * Single-flight serial loader with per-item failure retention.
 *
 * - Items load one at a time (RPC friendly, deterministic ordering).
 * - A polling tick NEVER cancels a scan in progress: a `load()` that arrives
 *   while one is running is coalesced into exactly one follow-up pass that
 *   starts after the current pass has completed. A slow RPC can therefore delay
 *   a refresh but can never starve the tail of the list.
 * - Only `reset()` (account switch) discards in-flight work; late results from
 *   the discarded run are dropped instead of overwriting fresh state.
 * - A failed item keeps its previous value and is recorded in `failedIds`, so a
 *   partial outage never blanks (or silently "succeeds" over) good data.
 * - Values are published progressively through `onProgress`, with `loading`
 *   telling the UI whether the snapshot is complete.
 */
export interface LoaderSnapshot<T> {
  values: Record<string, T>;
  failedIds: string[];
  errors: Record<string, string>;
  loading: boolean;
  generation: number;
  completedAt: number | null;
}

interface Run<T> {
  queued: string[] | null;
  promise: Promise<LoaderSnapshot<T>>;
}

export class SerialLoader<T> {
  private values: Record<string, T> = {};
  private errors: Record<string, string> = {};
  private loading = false;
  private generation = 0;
  private completedAt: number | null = null;
  private current: Run<T> | null = null;

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

  /** True while a scan is running. */
  get busy(): boolean {
    return this.current !== null;
  }

  /** Drop everything (used when the active account changes). */
  reset(): void {
    this.generation += 1;
    this.values = {};
    this.errors = {};
    this.loading = false;
    this.completedAt = null;
    this.current = null; // the discarded run exits at its next generation check
  }

  load(
    ids: string[],
    now: () => number = () => Date.now(),
    onProgress?: (s: LoaderSnapshot<T>) => void,
  ): Promise<LoaderSnapshot<T>> {
    if (this.current) {
      // Coalesce: never interrupt the scan in flight; run once more afterwards.
      this.current.queued = ids;
      return this.current.promise;
    }
    const run: Run<T> = { queued: null, promise: undefined as unknown as Promise<LoaderSnapshot<T>> };
    this.current = run;
    run.promise = this.drain(run, ids, now, onProgress).finally(() => {
      if (this.current === run) this.current = null;
    });
    return run.promise;
  }

  private async drain(
    run: Run<T>,
    first: string[],
    now: () => number,
    onProgress?: (s: LoaderSnapshot<T>) => void,
  ): Promise<LoaderSnapshot<T>> {
    let ids = first;
    for (;;) {
      const gen = this.generation;
      await this.pass(gen, ids, now, onProgress);
      if (gen !== this.generation) return this.snapshot(); // reset(): abandon
      if (run.queued) {
        ids = run.queued;
        run.queued = null;
        continue;
      }
      return this.snapshot();
    }
  }

  private async pass(
    gen: number,
    ids: string[],
    now: () => number,
    onProgress?: (s: LoaderSnapshot<T>) => void,
  ): Promise<void> {
    this.loading = true;
    const wanted = new Set(ids);
    for (const id of Object.keys(this.values)) if (!wanted.has(id)) delete this.values[id];
    for (const id of Object.keys(this.errors)) if (!wanted.has(id)) delete this.errors[id];

    for (const id of ids) {
      if (gen !== this.generation) return;
      try {
        const v = await this.fetchOne(id);
        if (gen !== this.generation) return;
        this.values[id] = v;
        delete this.errors[id];
      } catch (e) {
        if (gen !== this.generation) return;
        this.errors[id] = e instanceof Error ? e.message : String(e);
        // previous value (if any) is deliberately retained
      }
      onProgress?.(this.snapshot());
    }
    if (gen === this.generation) {
      this.loading = false;
      this.completedAt = now();
      onProgress?.(this.snapshot());
    }
  }
}
