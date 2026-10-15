import { Fingerprint, Network, Scale, ShieldCheck } from "lucide-react";
import Panel from "./Panel";

const CARDS = [
  {
    icon: Network,
    title: "3 hosts, 3 operators, 2-of-3",
    body:
      "Validators read three commit-pinned feeds on distinct hostnames and distinct operators. An outage or a lagging 404 can never become a slash: if an unreachable feed could still complete the quorum, the result is a retryable QUORUM_FAILURE with the bond intact.",
  },
  {
    icon: Fingerprint,
    title: "Evidence is a commitment",
    body:
      "Reporters never supply a URL. They commit to SHA-256(target, campaign, brand, first_seen); the contract recomputes it and only counts feed records carrying the same hash. Provenance gates the bounty - no self-manufactured domains.",
  },
  {
    icon: Scale,
    title: "No governor conflict of interest",
    body:
      "Slashed bonds sit in a locked reserve and flow back to the bounty pool or to appeal challengers. The governor can rotate feeds (7-day timelock) and register brands, but no code path lets it move a single wei.",
  },
  {
    icon: ShieldCheck,
    title: "Integer-only, firewall-ready",
    body:
      "No floats anywhere: ratios are basis points, money is wei. Any router can call assert_target_safe(target_id) - it reverts on TIER_2_DRAINER and warns on TIER_1_SUSPICIOUS. False positives are recoverable by appeal against newer feed revisions.",
  },
] as const;

export default function ProtocolExplainer() {
  return (
    <Panel id="protocol" title="Protocol design">
      <div className="grid gap-3 sm:grid-cols-2">
        {CARDS.map(({ icon: Icon, title, body }) => (
          <article key={title} className="rounded border border-edge bg-carbon/70 p-4">
            <Icon className="mb-2 h-5 w-5 text-radar" />
            <h3 className="text-sm font-semibold text-ink">{title}</h3>
            <p className="mt-1 text-sm leading-relaxed text-mute">{body}</p>
          </article>
        ))}
      </div>
    </Panel>
  );
}
