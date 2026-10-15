import { CheckCircle2, ExternalLink, Loader2, XCircle } from "lucide-react";
import { explorerTx } from "@/lib/deployment";
import type { TxBanner } from "@/lib/useDashboard";

export default function TxBannerView({ banner }: { banner: TxBanner | null }) {
  if (!banner) return null;
  const tone =
    banner.kind === "success" ? "border-safe/40 text-safe" : banner.kind === "error" ? "border-threat/40 text-threat" : "border-radar/40 text-radar";
  return (
    <div role="status" className={`mt-3 rounded border bg-carbon px-3 py-2 text-sm ${tone}`}>
      {banner.kind === "pending" && <Loader2 className="mr-2 inline h-4 w-4 animate-spin" />}
      {banner.kind === "success" && <CheckCircle2 className="mr-2 inline h-4 w-4" />}
      {banner.kind === "error" && <XCircle className="mr-2 inline h-4 w-4" />}
      <span className="font-semibold">{banner.label}</span>
      {banner.message ? <span className="ml-2 opacity-90">{banner.message}</span> : null}
      {banner.hash ? (
        <a className="sig ml-3 inline-flex items-center gap-1 underline" href={explorerTx(banner.hash)} target="_blank" rel="noreferrer">
          {banner.hash.slice(0, 10)}… <ExternalLink className="h-3 w-3" />
        </a>
      ) : null}
    </div>
  );
}
