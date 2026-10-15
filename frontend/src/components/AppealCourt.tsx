"use client";

import { useState } from "react";
import { Gavel } from "lucide-react";
import Panel from "./Panel";
import TierBadge from "./TierBadge";
import TxBannerView from "./TxBannerView";
import { appeal, reevaluate } from "@/lib/contract";
import { formatDuration, formatGen, parseGen } from "@/lib/format";
import { normalizeTarget } from "@/lib/validation";
import type { Dashboard } from "@/lib/useDashboard";

export default function AppealCourt({ d }: { d: Dashboard }) {
  const [target, setTarget] = useState("");
  const [bond, setBond] = useState("0.01");
  const [busy, setBusy] = useState(false);
  const minAppeal = d.pool ? BigInt(d.pool.min_appeal_bond) : 10n ** 16n;
  const listed = Object.values(d.targets?.values ?? {}).filter((t) => t.status === "BLACKLISTED" || t.status === "QUARANTINED");

  async function run(kind: "appeal" | "reevaluate", id: string) {
    if (!d.account) return;
    const acct = d.account;
    const slug = normalizeTarget(id);
    if (!slug) {
      d.setBanner(acct, { kind: "error", label: "Invalid target" });
      return;
    }
    setBusy(true);
    d.setBanner(acct, { kind: "pending", label: kind === "appeal" ? "Filing appeal" : "Re-evaluating", message: "Waiting for consensus…" });
    try {
      const onHash = (h: string) => d.setBanner(acct, { kind: "pending", label: "Sent", hash: h });
      const res =
        kind === "appeal"
          ? await appeal(acct, slug, parseGen(bond), minAppeal, onHash)
          : await reevaluate(acct, slug, onHash);
      d.setBanner(acct, { kind: "success", label: kind === "appeal" ? "Appeal decided" : "Re-evaluation decided", hash: res.hash });
      await d.refresh();
    } catch (e) {
      d.setBanner(acct, { kind: "error", label: "Failed", message: e instanceof Error ? e.message.slice(0, 220) : String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel id="appeals" title="Appeal court - false-positive recourse" icon={<Gavel className="h-4 w-4" />}>
      <p className="mb-3 text-sm text-mute">
        Anyone can challenge a listing. It succeeds only if at least two feeds now publish a <b>newer</b> record that revokes (false positive) or
        remediates the target. A failed appeal bond goes to the locked slash reserve, never to the governor.
      </p>
      <div className="grid gap-2 sm:grid-cols-[1fr_140px_auto]">
        <input
          aria-label="Target to appeal"
          className="sig min-h-11 rounded border border-edge bg-carbon px-3 text-sm outline-none focus:border-radar"
          placeholder="blacklisted-domain.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <input
          aria-label="Appeal bond in GEN"
          className="sig min-h-11 rounded border border-edge bg-carbon px-3 text-sm outline-none focus:border-radar"
          value={bond}
          onChange={(e) => setBond(e.target.value)}
        />
        <button
          disabled={busy || !d.account}
          onClick={() => void run("appeal", target)}
          className="min-h-11 rounded border border-caution/60 bg-caution/10 px-5 text-sm font-semibold text-caution disabled:opacity-40"
        >
          Post appeal bond
        </button>
      </div>
      <p className="mt-1 text-[11px] text-mute">Minimum appeal bond {formatGen(minAppeal)} GEN</p>
      <TxBannerView banner={d.banner} />

      <div className="mt-5 text-[11px] uppercase tracking-wider text-mute">Active listings</div>
      {listed.length === 0 ? (
        <p className="mt-2 text-sm text-mute">No active listings.</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {listed.map((t) => {
            const left = Math.max(0, t.quarantine_until - d.now);
            return (
              <li key={t.target_id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-edge bg-carbon/70 p-3">
                <div>
                  <div className="sig text-sm">{t.target_id}</div>
                  <div className="mt-1 flex items-center gap-2">
                    <TierBadge tier={t.tier} />
                    {t.status === "QUARANTINED" && (
                      <span className="sig text-[11px] text-mute">{left > 0 ? `watch ends in ${formatDuration(left)}` : "watch elapsed"}</span>
                    )}
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => setTarget(t.target_id)} className="min-h-11 rounded border border-edge px-3 text-xs text-mute">
                    Select
                  </button>
                  {t.status === "QUARANTINED" && left === 0 && (
                    <button
                      disabled={busy || !d.account}
                      onClick={() => void run("reevaluate", t.target_id)}
                      className="min-h-11 rounded border border-radar/60 px-3 text-xs text-radar disabled:opacity-40"
                    >
                      Re-evaluate
                    </button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
