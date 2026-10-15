"use client";

import { useCallback, useState } from "react";
import { Radar } from "lucide-react";
import Panel from "./Panel";
import TierBadge from "./TierBadge";
import { aggregate, fetchSource, VERDICT_LABEL } from "@/lib/aggregate";
import { readClient, readSafety } from "@/lib/contract";
import { normalizeTarget } from "@/lib/validation";
import { DEMO_TARGET } from "@/lib/deployment";
import { shortHash } from "@/lib/format";
import type { FeedSource, SafetyCheck, SourceOutcome, TierNumber } from "@/lib/types";

const OUTCOME_COLOR: Record<string, string> = { OK: "#10B981", NOT_FOUND: "#F59E0B", OUTAGE: "#EF4444" };

interface Scan {
  target: string;
  outcomes: SourceOutcome[];
  expectedHash: string;
  safety: SafetyCheck | null;
  safetyError: string | null;
}

function describe(o: SourceOutcome): string {
  if (o.kind === "OK") return `${o.status} - tier ${o.tier}`;
  if (o.kind === "NOT_FOUND") return "404 - no record (lag or fabricated)";
  return `OUTAGE - ${o.reason}`;
}

export default function ThreatRadar({ feeds }: { feeds: FeedSource[] }) {
  const [input, setInput] = useState(DEMO_TARGET);
  const [busy, setBusy] = useState(false);
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    const target = normalizeTarget(input);
    if (!target) {
      setError("Enter a domain slug such as uniswap-claim-airdrop.com");
      return;
    }
    if (feeds.length !== 3) {
      setError("Feed sources are not loaded yet.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const outcomes = await Promise.all(feeds.map((f) => fetchSource(f.base_url, target)));
      const first = outcomes.find((o): o is Extract<SourceOutcome, { kind: "OK" }> => o.kind === "OK");
      const expectedHash = first?.evidenceHash ?? "";
      let safety: SafetyCheck | null = null;
      let safetyError: string | null = null;
      try {
        safety = await readSafety(await readClient(), target);
      } catch (e) {
        safetyError = e instanceof Error ? e.message : String(e);
      }
      setScan({ target, outcomes, expectedHash, safety, safetyError });
    } finally {
      setBusy(false);
    }
  }, [input, feeds]);

  const payload = scan && scan.expectedHash ? aggregate(scan.outcomes, scan.expectedHash) : null;

  return (
    <Panel id="radar" title="Threat radar - 3-host quorum" icon={<Radar className="h-4 w-4" />}>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          aria-label="Target domain"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void run()}
          className="sig min-h-11 flex-1 rounded border border-edge bg-carbon px-3 text-sm outline-none focus:border-radar"
          placeholder="uniswap-claim-airdrop.com"
        />
        <button
          onClick={() => void run()}
          disabled={busy}
          className="min-h-11 rounded border border-radar/60 bg-radar/10 px-5 text-sm font-semibold text-radar hover:bg-radar/20 disabled:opacity-50"
        >
          {busy ? "Scanning…" : "Scan feeds"}
        </button>
      </div>
      {error && <p className="mt-2 text-sm text-threat">{error}</p>}

      <div className="mt-4 grid gap-4 lg:grid-cols-[260px_1fr]">
        <svg viewBox="0 0 240 240" role="img" aria-label="Three-feed threat radar" className="mx-auto w-full max-w-[260px]">
          <circle cx="120" cy="120" r="110" fill="#0f1523" stroke="#1f2a40" />
          <circle cx="120" cy="120" r="75" fill="none" stroke="#1f2a40" />
          <circle cx="120" cy="120" r="40" fill="none" stroke="#1f2a40" />
          <path d="M120 10 V230 M10 120 H230" stroke="#1f2a40" />
          <g className="radar-sweep">
            <path d="M120 120 L120 10 A110 110 0 0 1 198 42 Z" fill="rgba(6,182,212,0.18)" />
          </g>
          {feeds.map((f, i) => {
            const angle = (-90 + i * 120) * (Math.PI / 180);
            const x = Math.round(120 + 78 * Math.cos(angle));
            const y = Math.round(120 + 78 * Math.sin(angle));
            const o = scan?.outcomes[i];
            const c = o ? OUTCOME_COLOR[o.kind] : "#06B6D4";
            return (
              <g key={f.slot}>
                <circle cx={x} cy={y} r="13" fill={`${c}33`} stroke={c} strokeWidth="2" />
                <text x={x} y={y + 4} textAnchor="middle" fontSize="12" fill={c} fontFamily="monospace">
                  {f.slot}
                </text>
              </g>
            );
          })}
          <circle cx="120" cy="120" r="5" fill="#06B6D4" />
        </svg>

        <div className="space-y-2">
          {feeds.map((f, i) => {
            const o = scan?.outcomes[i];
            return (
              <div key={f.slot} className="rounded border border-edge bg-carbon/70 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="sig text-sm font-semibold text-ink">
                    Slot {f.slot} <span className="text-mute">- {f.host}</span>
                  </span>
                  <span className="sig text-[11px] text-mute">operator {f.operator}</span>
                </div>
                <div className="sig mt-1 text-xs" style={{ color: o ? OUTCOME_COLOR[o.kind] : "#8a97ad" }}>
                  {o ? describe(o) : "awaiting scan"}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {scan && (
        <div className="mt-4 grid gap-3 rounded border border-edge bg-carbon/70 p-3 text-sm sm:grid-cols-2">
          <div>
            <div className="text-xs uppercase tracking-wider text-mute">Quorum inspector (client mirror of _aggregate)</div>
            {payload ? (
              <ul className="sig mt-1 space-y-0.5 text-xs">
                <li>
                  verdict: <b>{VERDICT_LABEL[payload.verdict]}</b>
                </li>
                <li>
                  tier: <TierBadge tier={payload.tier as TierNumber} />
                </li>
                <li>source_count: {payload.source_count}</li>
                <li>published_ts: {payload.published_ts}</li>
                <li>evidence: {shortHash(payload.evidence_hash)}</li>
              </ul>
            ) : (
              <p className="mt-1 text-xs text-mute">No feed carries a record for this target, so there is no evidence commitment to test.</p>
            )}
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-mute">On-chain firewall state</div>
            {scan.safety ? (
              <div className="mt-1 space-y-1 text-xs">
                <TierBadge tier={scan.safety.tier} />
                <div className="sig">
                  {scan.safety.status} - {scan.safety.verdict}
                </div>
              </div>
            ) : (
              <p className="mt-1 text-xs text-caution">Read failed: {scan.safetyError}</p>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}
