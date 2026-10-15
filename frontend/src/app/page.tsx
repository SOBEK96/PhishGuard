"use client";

import AppealCourt from "@/components/AppealCourt";
import BountyVault from "@/components/BountyVault";
import FirewallSimulator from "@/components/FirewallSimulator";
import Footer from "@/components/Footer";
import ProtocolExplainer from "@/components/ProtocolExplainer";
import SyncAlert from "@/components/SyncAlert";
import ThreatRadar from "@/components/ThreatRadar";
import TriageSubmission from "@/components/TriageSubmission";
import WalletBar from "@/components/WalletBar";
import { useDashboard } from "@/lib/useDashboard";

export default function Page() {
  const d = useDashboard();
  return (
    <>
      <WalletBar d={d} />
      <SyncAlert
        poolError={d.poolError}
        failedIds={d.targets?.failedIds ?? []}
        errors={d.targets?.errors ?? {}}
        loading={d.targets?.loading ?? d.pool === null}
        syncedAt={d.syncedAt}
      />
      <main className="mx-auto max-w-6xl space-y-5 px-4 py-6">
        <section className="rounded-lg border border-edge bg-panel/60 p-5">
          <h2 className="text-xl font-bold sm:text-2xl">
            Decentralized triage for wallet drainers <span className="text-radar">before</span> they sign.
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-mute">
            Three independent threat-intel hosts, a 2-of-3 validator quorum, staked reporters, and an on-chain firewall any wallet or router can
            query. No closed blocklists, no silent censorship - every classification is appealable.
          </p>
          <div className="sig mt-3 flex flex-wrap gap-2 text-[11px]">
            <span className="rounded border border-safe/40 px-2 py-1 text-safe">TIER_0_SAFE</span>
            <span className="rounded border border-caution/40 px-2 py-1 text-caution">TIER_1_SUSPICIOUS</span>
            <span className="rounded border border-threat/40 px-2 py-1 text-threat">TIER_2_DRAINER</span>
          </div>
        </section>
        <ThreatRadar feeds={d.feeds} />
        <div className="grid gap-5 lg:grid-cols-2">
          <TriageSubmission d={d} />
          <FirewallSimulator />
        </div>
        <div className="grid gap-5 lg:grid-cols-2">
          <AppealCourt d={d} />
          <BountyVault d={d} />
        </div>
        <ProtocolExplainer />
      </main>
      <Footer />
    </>
  );
}
