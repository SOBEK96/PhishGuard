/**
 * Account-scoped keyed state. Every user panel stores `{ account, value }` and
 * reads through `select`, so a stale value from the previous wallet can never
 * render for the new one -- even for a frame.
 */
export interface Scoped<T> {
  account: string;
  value: T;
}

export function normalizeAccount(a: string | null | undefined): string {
  return (a ?? "").toLowerCase();
}

export function scope<T>(account: string | null | undefined, value: T): Scoped<T> {
  return { account: normalizeAccount(account), value };
}

export function select<T>(state: Scoped<T> | null | undefined, account: string | null | undefined, empty: T): T {
  if (!state) return empty;
  const a = normalizeAccount(account);
  if (a === "" || state.account !== a) return empty;
  return state.value;
}

/** Keyed map helper for tx banners: `{ [account]: banner }`. */
export function setFor<T>(map: Record<string, T>, account: string, value: T): Record<string, T> {
  return { ...map, [normalizeAccount(account)]: value };
}

export function getFor<T>(map: Record<string, T>, account: string | null | undefined): T | undefined {
  return map[normalizeAccount(account)];
}

export function clearFor<T>(map: Record<string, T>, account: string): Record<string, T> {
  const next = { ...map };
  delete next[normalizeAccount(account)];
  return next;
}
