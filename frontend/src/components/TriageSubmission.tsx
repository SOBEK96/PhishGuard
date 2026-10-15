"use client";

import { useEffect, useMemo, useState } from "react";
import { Siren } from "lucide-react";
import Panel from "./Panel";
import TxBannerView from "./TxBannerView";
import { reportTarget } from "@/lib/contract";
import { formatDuration, formatGen, parseGen, shortHash } from "@/lib/format";
import { commitment, normalizeTarget, validateReport } from "@/lib/validation";
import { DEMO_TARGET } from "@/lib/deployment";
import { STATUS_COPY } from "@/lib/tier";
import type { Dashboard } from "@/lib/useDashboard";
import type { TargetStatus } from "@/lib/types";

export default function TriageSubmission({ d }: { d: Dashboard }) {
  const [target, setTarget] = useState(DEMO_TARGET);
  const [campaign, setCampaign] = useState("permit2-airdrop-2026q4");
  const [brand, setBrand] = useState("uniswap");
  const [firstSeen, setFirstSeen] = useState("1790000000");
  const [bond, setBond] = useState("0.01");
  const [hash, setHash] = useState("");
  const [busy, setBusy] = useState(false);

  const slug = normalizeTarget(target) ?? "";
  const minBond = d.pool ? BigInt(d.pool.min_report_bond) : 10n ** 16n;

  const parsed = useMemo(() => {
    let bondWei = 0n;
    try {
      bondWei = parseGen(bond);
    } catch {
      return { error: "Bond must be a GEN amount like 0.01", bondWei, ts: 0 };
    }
    const ts = /^\d+$/.test(firstSeen) ? Number(firstSeen) : -1;
    const error = validateReport({ targetId: slug, campaignId: campaign, brandId: brand, firstSeenTs: ts, bondWei }, minBond);
    return { error, bondWei, ts };
  }, [bond, firstSeen, slug, campaign, brand, minBond]);

  useEffect(() => {
    let live = true;
    if (parsed.ts < 0 || !slug) {
      setHash("");
      return;
    }
    void commitment({ targetId: slug, campaignId: campaign, brandId: brand, firstSeenTs: parsed.ts }).then((h) => {
      if (live) setHash(h);
    });
    return () => {
      live = false;
    };
  }, [slug, campaign, brand, parsed.ts]);

  const mine: TargetStatus[] = Object.values(d.targets?.values ?? {}).filter(
    (t) => d.account !== "" && t.reporter.toLowerCase() === d.account,
  );

  async function submit() {
    if (!d.account) return;
    const acct = d.account;
    if (parsed.error) {
      d.setBanner(acct, { kind: "error", label: "Invalid report", message: parsed.error });
      return;
    }
    setBusy(true);
    d.setBanner(acct, { kind: "pending", label: "Submitting report", message: "Signing, then waiting for validator consensus…" });
    try {
      const res = await reportTarget(
        acct,
        { targetId: slug, campaignId: campaign, brandId: brand, firstSeenTs: parsed.ts },
        parsed.bondWei,
        minBond,
        (h) => d.setBanner(acct, { kind: "pending", label: "Report sent", hash: h, message: "Awaiting consensus…" }),
      );
      d.pin(slug);
      d.setBanner(acct, { kind: "success", label: "Report accepted", hash: res.hash, message: `${res.verdict.status}/${res.verdict.consensus}` });
      await d.refresh();
    } catch (e) {
      d.setBanner(acct, { kind: "error", label: "Report failed", message: e instanceof Error ? e.message.slice(0, 220) : String(e) });
    } finally {
      setBusy(false);
    }
  }

  const field = "sig min-h-11 w-full rounded border border-edge bg-carbon px-3 text-sm outline-none focus:border-radar";
  const label = "text-[11px] uppercase tracking-wider text-mute";

  return (
    <Panel id="triage" title="Triage desk - staked report" icon={<Siren className="h-4 w-4" />}>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="sm:col-span-2">
          <span className={label}>Target domain</span>
          <input className={field} value={target} onChange={(e) => setTarget(e.target.value)} />
          <span className="sig mt-1 block text-[11px] text-mute">canonical slug: {slug || "invalid"}</span>
        </label>
        <label>
          <span className={label}>Campaign id</span>
          <input className={field} value={campaign} onChange={(e) => setCampaign(e.target.value.toLowerCase())} />
        </label>
        <label>
          <span className={label}>Protected brand id</span>
          <input className={field} value={brand} onChange={(e) => setBrand(e.target.value.toLowerCase())} />
        </label>
        <label>
          <span className={label}>first_seen_ts (unix)</span>
          <input className={field} inputMode="numeric" value={firstSeen} onChange={(e) => setFirstSeen(e.target.value)} />
        </label>
        <label>
          <span className={label}>Bond (GEN) - min {formatGen(minBond, 4)}</span>
          <input className={field} inputMode="decimal" value={bond} onChange={(e) => setBond(e.target.value)} />
        </label>
      </div>

      <div className="mt-3 rounded border border-edge bg-carbon/70 p-3 text-xs">
        <div className={label}>Evidence commitment (SHA-256 of canonical attributes)</div>
        <div className="sig mt-1 break-all text-radar">{hash || "-"}</div>
        <div className="mt-2 grid gap-1 text-mute sm:grid-cols-2">
          <span>Slashed if feeds say safe or unknown: <b className="text-threat">full bond to locked reserve</b></span>
          <span>Outage or lag: <b className="text-safe">bond intact, retry</b></span>
          <span>Tier 1: <b className="text-caution">refund, 48h watch</b></span>
          <span>Tier 2: <b className="text-threat">refund + bounty after 24h cooldown</b></span>
        </div>
      </div>

      {parsed.error && <p className="mt-3 text-sm text-caution">{parsed.error}</p>}
      <button
        onClick={() => void submit()}
        disabled={busy || !d.account || parsed.error !== null}
        className="mt-3 min-h-11 w-full rounded border border-threat/60 bg-threat/10 px-5 text-sm font-semibold text-threat hover:bg-threat/20 disabled:opacity-40 sm:w-auto"
      >
        {d.account ? (busy ? "Awaiting consensus…" : "Stake bond & submit report") : "Connect wallet to report"}
      </button>
      <TxBannerView banner={d.banner} />

      {mine.length > 0 && (
        <div className="mt-5">
          <div className={label}>Your reports</div>
          <ul className="mt-2 space-y-2">
            {mine.map((t) => {
              const left = Math.max(0, t.vest_at - d.now);
              return (
                <li key={t.target_id} className="rounded border border-edge bg-carbon/70 p-3 text-sm">
                  <div className="sig flex flex-wrap justify-between gap-2">
                    <span>{t.target_id}</span>
                    <span>{t.status}</span>
                  </div>
                  <div className="mt-1 text-xs text-mute">{STATUS_COPY[t.status]}</div>
                  {t.status === "BLACKLISTED" && (BigInt(t.bond_held) > 0n || BigInt(t.bounty_reserved) > 0n) && (
                    <div className="sig mt-1 text-xs">
                      vesting {formatGen(BigInt(t.bond_held) + BigInt(t.bounty_reserved))} GEN -{" "}
                      {left > 0 ? `unlocks in ${formatDuration(left)}` : "ready to claim"}
                    </div>
                  )}
                  <div className="sig mt-1 text-[11px] text-mute">evidence {shortHash(t.evidence_hash)}</div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </Panel>
  );
}
