"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { MonotonicClock } from "./clock";
import {
  ensureChain,
  getProvider,
  readClaimable,
  readFeeds,
  readClient,
  readPool,
  readTarget,
  readTargetIndex,
  type EthereumProvider,
} from "./contract";
import { SerialLoader, type LoaderSnapshot } from "./serialLoader";
import { clearFor, getFor, normalizeAccount, scope, select, setFor, type Scoped } from "./scoped";
import type { FeedSource, PoolState, TargetStatus } from "./types";

export interface TxBanner {
  kind: "pending" | "success" | "error";
  label: string;
  hash?: string;
  message?: string;
}

const POLL_MS = 20000;

export function useDashboard() {
  const [account, setAccount] = useState<string>("");
  const [pool, setPool] = useState<PoolState | null>(null);
  const [feeds, setFeeds] = useState<FeedSource[]>([]);
  const [targets, setTargets] = useState<LoaderSnapshot<TargetStatus> | null>(null);
  const [claimable, setClaimable] = useState<Scoped<string> | null>(null);
  const [banners, setBanners] = useState<Record<string, TxBanner>>({});
  const [poolError, setPoolError] = useState<string | null>(null);
  const [syncedAt, setSyncedAt] = useState<number | null>(null);
  const [tick, setTick] = useState(0);
  const clock = useRef(new MonotonicClock());
  const loader = useRef(
    new SerialLoader<TargetStatus>(async (id) => {
      const client = await readClient();
      return readTarget(client, id);
    }),
  );
  const accountRef = useRef("");

  const refresh = useCallback(async () => {
    try {
      const client = await readClient();
      const p = await readPool(client);
      setPool(p);
      setPoolError(null);
      const f = await readFeeds(client).catch(() => null);
      if (f) setFeeds(f);
      const ids = await readTargetIndex(client, p.target_count);
      const snap = await loader.current.load(ids);
      setTargets(snap);
      // Anchor the monotone clock on the freshest target timestamps we can see.
      for (const t of Object.values(snap.values)) {
        if (t.report_ts > 0) clock.current.observe(t.report_ts);
      }
      clock.current.observe(Math.floor(Date.now() / 1000));
      const acct = accountRef.current;
      if (acct) {
        const c = await readClaimable(client, acct).catch(() => null);
        // Drop the answer if the wallet changed while the read was in flight.
        if (c !== null && accountRef.current === acct) setClaimable(scope(acct, c));
      }
      setSyncedAt(Date.now());
    } catch (e) {
      setPoolError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  // Account lifecycle: accountsChanged immediately clears every per-account panel.
  useEffect(() => {
    const provider = getProvider();
    if (!provider) return;
    const onAccounts = (accts: unknown) => {
      const next = Array.isArray(accts) && typeof accts[0] === "string" ? normalizeAccount(accts[0]) : "";
      accountRef.current = next;
      setAccount(next);
      setClaimable(null);
      setBanners({});
      if (next) void refresh();
    };
    provider.on?.("accountsChanged", onAccounts);
    void provider
      .request({ method: "eth_accounts" })
      .then(onAccounts)
      .catch(() => undefined);
    return () => provider.removeListener?.("accountsChanged", onAccounts);
  }, [refresh]);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => {
      void refresh();
    }, POLL_MS);
    const c = setInterval(() => setTick((n) => n + 1), 1000);
    return () => {
      clearInterval(t);
      clearInterval(c);
    };
  }, [refresh]);

  const connect = useCallback(async (): Promise<void> => {
    const provider: EthereumProvider | null = getProvider();
    if (!provider) throw new Error("No EIP-1193 wallet found. Install MetaMask or Rabby.");
    const accts = (await provider.request({ method: "eth_requestAccounts" })) as string[];
    await ensureChain(provider);
    const next = normalizeAccount(accts[0]);
    accountRef.current = next;
    setAccount(next);
    setClaimable(null);
    void refresh();
  }, [refresh]);

  const setBanner = useCallback((acct: string, b: TxBanner | null) => {
    setBanners((m) => (b ? setFor(m, acct, b) : clearFor(m, acct)));
  }, []);

  const now = useMemo(() => {
    void tick;
    return clock.current.now() || Math.floor(Date.now() / 1000);
  }, [tick]);

  return {
    account,
    pool,
    feeds,
    targets,
    claimable: select(claimable, account, "0"),
    banner: getFor(banners, account) ?? null,
    poolError,
    syncedAt,
    now,
    connect,
    refresh,
    setBanner,
  };
}

export type Dashboard = ReturnType<typeof useDashboard>;
