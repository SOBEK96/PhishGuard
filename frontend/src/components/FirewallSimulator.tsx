"use client";

import { useState } from "react";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import Panel from "./Panel";
import TierBadge from "./TierBadge";
import { readClient, readSafety } from "@/lib/contract";
import { normalizeTarget } from "@/lib/validation";
import { parentChain } from "@/lib/hostname";
import { DEMO_TARGET } from "@/lib/deployment";
import type { SafetyCheck } from "@/lib/types";

const ACTIONS = [
  { id: "permit2", label: "Permit2 signature", detail: "permitTransferFrom(token, amount, spender)" },
  { id: "seaport", label: "Seaport listing", detail: "fulfillAdvancedOrder(order, criteria)" },
  { id: "approve", label: "ERC-20 approve", detail: "approve(spender, type(uint256).max)" },
] as const;

export default function FirewallSimulator() {
  const [target, setTarget] = useState(DEMO_TARGET);
  const [action, setAction] = useState<(typeof ACTIONS)[number]["id"]>("permit2");
  const [result, setResult] = useState<SafetyCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function simulate() {
    const slug = normalizeTarget(target);
    if (!slug) {
      setError("Enter a valid domain.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setResult(await readSafety(await readClient(), slug));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const act = ACTIONS.find((a) => a.id === action)!;
  const tone = result?.verdict === "BLOCK" ? "#EF4444" : result?.verdict === "WARN" ? "#F59E0B" : "#10B981";

  return (
    <Panel id="firewall" title="Wallet firewall simulator" icon={<ShieldCheck className="h-4 w-4" />}>
      <p className="mb-3 text-sm text-mute">
        A router or smart account calls <span className="sig text-radar">assert_target_safe(target_id)</span> before it forwards funds. The call
        reverts on <span className="text-threat">TIER_2_DRAINER</span> and warns on <span className="text-caution">TIER_1_SUSPICIOUS</span>.
      </p>
      <div className="flex flex-wrap gap-2">
        {ACTIONS.map((a) => (
          <button
            key={a.id}
            onClick={() => setAction(a.id)}
            className={`min-h-11 rounded border px-3 text-sm ${action === a.id ? "border-radar bg-radar/10 text-radar" : "border-edge text-mute"}`}
          >
            {a.label}
          </button>
        ))}
      </div>
      <div className="mt-3 flex flex-col gap-2 sm:flex-row">
        <input
          aria-label="Counterparty domain"
          className="sig min-h-11 flex-1 rounded border border-edge bg-carbon px-3 text-sm outline-none focus:border-radar"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <button
          onClick={() => void simulate()}
          disabled={busy}
          className="min-h-11 rounded border border-radar/60 bg-radar/10 px-5 text-sm font-semibold text-radar disabled:opacity-50"
        >
          {busy ? "Checking…" : "Simulate signature"}
        </button>
      </div>
      {error && <p className="mt-2 text-sm text-threat">{error}</p>}

      {result && (
        <div className="mt-4 rounded-lg border p-4" style={{ borderColor: `${tone}66`, background: `${tone}10` }}>
          <div className="flex items-center gap-2" style={{ color: tone }}>
            {result.verdict === "BLOCK" ? <ShieldAlert className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5" />}
            <b className="sig">
              {result.verdict === "BLOCK" ? "TRANSACTION BLOCKED" : result.verdict === "WARN" ? "PROCEED WITH CAUTION" : "TRANSACTION ALLOWED"}
            </b>
          </div>
          <div className="sig mt-2 text-xs text-mute">
            {act.label}: {act.detail} - counterparty {result.target_id}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <TierBadge tier={result.tier} />
            <span className="sig text-xs">{result.status}</span>
            {!result.known && <span className="text-xs text-mute">unlisted - default allow (UNASSESSED, not verified safe)</span>}
          </div>
          {result.inherited && (
            <div className="sig mt-2 text-xs" style={{ color: tone }}>
              inherited from parent domain <b>{result.matched_target}</b> - a listing covers every subdomain beneath it
            </div>
          )}
          {!result.inherited && parentChain(result.target_id).length > 0 && (
            <div className="sig mt-2 text-[11px] text-mute">
              parents checked: {parentChain(result.target_id).join(" > ")}
            </div>
          )}
        </div>
      )}

      <pre className="sig mt-4 overflow-x-auto rounded border border-edge bg-carbon p-3 text-[11px] leading-relaxed text-mute">
{`# any GenLayer contract / smart account
guard = gl.get_contract_at(PHISHGUARD)
verdict = guard.view().assert_target_safe(target_id)  # reverts on TIER_2
if verdict == "WARN":
    require_user_confirmation()`}
      </pre>
    </Panel>
  );
}
