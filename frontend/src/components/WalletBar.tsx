"use client";

import { useState } from "react";
import { ShieldAlert, Wallet } from "lucide-react";
import { shortAddress } from "@/lib/format";
import type { Dashboard } from "@/lib/useDashboard";

export default function WalletBar({ d }: { d: Dashboard }) {
  const [error, setError] = useState<string | null>(null);
  return (
    <header className="border-b border-edge bg-carbon/80 px-4 py-3 backdrop-blur">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-7 w-7 text-radar" />
          <div>
            <h1 className="text-base font-bold tracking-wide">PHISHGUARD</h1>
            <p className="sig text-[11px] text-mute">decentralized drainer triage oracle - GenLayer Studio Next</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {d.pool && <span className="sig hidden text-xs text-mute sm:inline">{d.pool.total_reports} reports - {d.pool.target_count} targets</span>}
          <button
            onClick={() => {
              setError(null);
              d.connect().catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
            }}
            className="sig inline-flex min-h-11 items-center gap-2 rounded border border-radar/60 bg-radar/10 px-4 text-sm text-radar"
          >
            <Wallet className="h-4 w-4" />
            {d.account ? shortAddress(d.account) : "Connect wallet"}
          </button>
        </div>
      </div>
      {error && <p className="mx-auto mt-2 max-w-6xl text-sm text-threat">{error}</p>}
    </header>
  );
}
