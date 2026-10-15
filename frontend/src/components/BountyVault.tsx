"use client";

import { useState } from "react";
import { Vault } from "lucide-react";
import Panel from "./Panel";
import TxBannerView from "./TxBannerView";
import { claimPayout, claimSettlement, fundPool, withdrawShares } from "@/lib/contract";
import { lockBreakdown, redeemableAssets, validateRedeem } from "@/lib/vault";
import { bpsToPercent, formatGen, parseGen, ratioBps } from "@/lib/format";
import type { Dashboard } from "@/lib/useDashboard";

function Meter({ label, value, bps, color }: { label: string; value: string; bps: number; color: string }) {
  return (
    <div>
      <div className="flex justify-between text-xs">
        <span className="text-mute">{label}</span>
        <span className="sig">{value} GEN</span>
      </div>
      <div className="mt-1 h-2 rounded bg-carbon">
        <div className="h-2 rounded" style={{ width: `${Math.max(2, bps / 100)}%`, background: color }} />
      </div>
    </div>
  );
}

export default function BountyVault({ d }: { d: Dashboard }) {
  const [deposit, setDeposit] = useState("0.05");
  const [redeem, setRedeem] = useState("");
  const [busy, setBusy] = useState(false);
  const p = d.pool;

  async function run(label: string, fn: (acct: string, onHash: (h: string) => void) => Promise<{ hash: string }>) {
    if (!d.account) return;
    const acct = d.account;
    setBusy(true);
    d.setBanner(acct, { kind: "pending", label, message: "Waiting for consensus…" });
    try {
      const res = await fn(acct, (h) => d.setBanner(acct, { kind: "pending", label, hash: h }));
      d.setBanner(acct, { kind: "success", label: `${label} confirmed`, hash: res.hash });
      await d.refresh();
    } catch (e) {
      d.setBanner(acct, { kind: "error", label: `${label} failed`, message: e instanceof Error ? e.message.slice(0, 220) : String(e) });
    } finally {
      setBusy(false);
    }
  }

  if (!p) {
    return (
      <Panel id="vault" title="Bounty vault" icon={<Vault className="h-4 w-4" />}>
        <p className="text-sm text-mute">Waiting for the first pool read…</p>
      </Panel>
    );
  }
  const total = BigInt(p.balance) > 0n ? BigInt(p.balance) : 1n;
  const capUsedBps = ratioBps(BigInt(p.epoch_paid), BigInt(p.epoch_cap) > 0n ? BigInt(p.epoch_cap) : 1n);
  const claimable = BigInt(d.claimable);
  const held = BigInt(d.shares);
  const totalShares = BigInt(p.total_shares);
  const freePool = BigInt(p.bounty_pool);
  const lock = lockBreakdown(p);
  const redeemAll = redeemableAssets(held, totalShares, freePool);
  let redeemShares = 0n;
  let redeemParseError: string | null = null;
  try {
    redeemShares = redeem.trim() === "" ? 0n : parseGen(redeem);
  } catch {
    redeemParseError = "Enter a share amount like 0.05";
  }
  const redeemError = redeem.trim() === "" ? null : (redeemParseError ?? validateRedeem(redeemShares, held, totalShares, freePool));
  const redeemOut = redeemError ? 0n : redeemableAssets(redeemShares, totalShares, freePool);

  return (
    <Panel id="vault" title="Bounty vault & slash reserve" icon={<Vault className="h-4 w-4" />}
      aside={<span className={`sig text-xs ${p.solvent ? "text-safe" : "text-threat"}`}>{p.solvent ? "SOLVENT" : "INSOLVENT"}</span>}>
      <div className="space-y-3">
        <Meter label="Bounty pool (free)" value={formatGen(p.bounty_pool)} bps={ratioBps(BigInt(p.bounty_pool), total)} color="#06B6D4" />
        <Meter label="Reserved bounties (vesting)" value={formatGen(p.reserved_bounty)} bps={ratioBps(BigInt(p.reserved_bounty), total)} color="#10B981" />
        <Meter label="Held reporter bonds" value={formatGen(p.held_bonds)} bps={ratioBps(BigInt(p.held_bonds), total)} color="#F59E0B" />
        <Meter label="Locked slash reserve (never governor)" value={formatGen(p.locked_slash_reserve)} bps={ratioBps(BigInt(p.locked_slash_reserve), total)} color="#EF4444" />
      </div>

      <div className="mt-4 rounded border border-edge bg-carbon/70 p-3 text-xs">
        <div className="flex justify-between">
          <span className="text-mute">Epoch bounty cap ({bpsToPercent(p.max_epoch_bounty_bps)} of pool)</span>
          <span className="sig">
            {formatGen(p.epoch_paid)} / {formatGen(p.epoch_cap)} GEN
          </span>
        </div>
        <div className="mt-1 h-2 rounded bg-obsidian">
          <div className="h-2 rounded bg-radar" style={{ width: `${Math.max(1, capUsedBps / 100)}%` }} />
        </div>
        <div className="sig mt-2 text-[11px] text-mute">
          fixed tier-2 bounty {formatGen(p.tier2_bounty)} GEN - epoch {p.epoch} - {p.total_reports} reports
        </div>
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-[1fr_auto]">
        <input
          aria-label="Deposit in GEN"
          className="sig min-h-11 rounded border border-edge bg-carbon px-3 text-sm outline-none focus:border-radar"
          value={deposit}
          onChange={(e) => setDeposit(e.target.value)}
        />
        <button
          disabled={busy || !d.account}
          onClick={() => void run("Fund pool", (a, h) => fundPool(a, parseGen(deposit), h))}
          className="min-h-11 rounded border border-radar/60 bg-radar/10 px-5 text-sm font-semibold text-radar disabled:opacity-40"
        >
          Fund bounty pool
        </button>
      </div>
      <div className="mt-2 flex flex-wrap gap-2">
        <button
          disabled={busy || !d.account || claimable === 0n}
          onClick={() => void run("Claim payout", (a, h) => claimPayout(a, h))}
          className="min-h-11 rounded border border-safe/60 bg-safe/10 px-5 text-sm font-semibold text-safe disabled:opacity-40"
        >
          Claim {formatGen(d.claimable)} GEN
        </button>
        {Object.values(d.targets?.values ?? {})
          .filter((t) => d.account !== "" && t.reporter.toLowerCase() === d.account && (BigInt(t.bond_held) > 0n || BigInt(t.bounty_reserved) > 0n) && t.vest_at <= d.now)
          .map((t) => (
            <button
              key={t.target_id}
              disabled={busy}
              onClick={() => void run("Claim settlement", (a, h) => claimSettlement(a, t.target_id, h))}
              className="min-h-11 rounded border border-caution/60 px-4 text-xs text-caution"
            >
              Vest {t.target_id}
            </button>
          ))}
      </div>
      <div className="mt-5 rounded border border-edge bg-carbon/70 p-3">
        <div className="text-[11px] uppercase tracking-wider text-mute">Redeem vault shares</div>
        <div className="mt-2 grid gap-1 text-xs sm:grid-cols-2">
          <span className="text-mute">
            Your shares: <b className="sig text-ink">{formatGen(d.shares, 6)}</b>
          </span>
          <span className="text-mute">
            Redeemable now: <b className="sig text-safe">{formatGen(redeemAll, 6)} GEN</b>
          </span>
        </div>
        <div className="mt-2 grid gap-2 sm:grid-cols-[1fr_auto_auto]">
          <input
            aria-label="Shares to redeem"
            className="sig min-h-11 rounded border border-edge bg-obsidian px-3 text-sm outline-none focus:border-radar"
            placeholder="shares (e.g. 0.05)"
            value={redeem}
            onChange={(e) => setRedeem(e.target.value)}
          />
          <button
            type="button"
            disabled={held === 0n}
            onClick={() => setRedeem(formatGen(held, 18))}
            className="min-h-11 rounded border border-edge px-4 text-xs text-mute disabled:opacity-40"
          >
            Max
          </button>
          <button
            disabled={busy || !d.account || redeem.trim() === "" || redeemError !== null}
            onClick={() => void run("Redeem shares", (a, h) => withdrawShares(a, redeemShares, h))}
            className="min-h-11 rounded border border-radar/60 bg-radar/10 px-5 text-sm font-semibold text-radar disabled:opacity-40"
          >
            Redeem
          </button>
        </div>
        {redeemError && <p className="mt-1 text-xs text-caution">{redeemError}</p>}
        {!redeemError && redeemShares > 0n && (
          <p className="sig mt-1 text-xs text-mute">
            you receive {formatGen(redeemOut, 6)} GEN into your claimable balance - then press <b>Claim</b> above (2 steps).
          </p>
        )}
        <ul className="sig mt-3 space-y-0.5 text-[11px] text-mute">
          <li>free liquidity (redeemable): {formatGen(lock.freeLiquidity, 6)} GEN</li>
          <li>locked - reserved bounties (vesting): {formatGen(lock.reservedBounties, 6)} GEN</li>
          <li>locked - held reporter bonds: {formatGen(lock.heldBonds, 6)} GEN</li>
          <li>locked - slash reserve: {formatGen(lock.slashReserve, 6)} GEN</li>
          <li>share floor: {lock.deadShares.toString()} dead shares can never be redeemed</li>
        </ul>
      </div>
      <TxBannerView banner={d.banner} />
    </Panel>
  );
}
