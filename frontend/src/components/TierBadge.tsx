import { TIER_COLOR, TIER_NAME } from "@/lib/tier";
import type { TierNumber } from "@/lib/types";

export default function TierBadge({ tier }: { tier: TierNumber }) {
  const c = TIER_COLOR[tier];
  return (
    <span
      className="sig inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-semibold"
      style={{ color: c, borderColor: `${c}66`, background: `${c}14` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
      {TIER_NAME[tier]}
    </span>
  );
}
