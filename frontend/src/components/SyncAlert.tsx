import { AlertTriangle, CheckCircle2, Loader2 } from "lucide-react";

interface Props {
  poolError: string | null;
  failedIds: string[];
  errors: Record<string, string>;
  loading: boolean;
  syncedAt: number | null;
}

/**
 * Honest RPC sync banner: a partial read failure is surfaced by name instead of
 * being masked by whatever stale data is still on screen.
 */
export default function SyncAlert({ poolError, failedIds, errors, loading, syncedAt }: Props) {
  if (poolError) {
    return (
      <div role="alert" className="border-b border-threat/40 bg-threat/10 px-4 py-2 text-sm text-threat">
        <AlertTriangle className="mr-2 inline h-4 w-4" />
        RPC read failed - showing last known state. <span className="sig opacity-80">{poolError.slice(0, 160)}</span>
      </div>
    );
  }
  if (failedIds.length > 0) {
    return (
      <div role="alert" className="border-b border-caution/40 bg-caution/10 px-4 py-2 text-sm text-caution">
        <AlertTriangle className="mr-2 inline h-4 w-4" />
        Partial sync: {failedIds.length} target read{failedIds.length === 1 ? "" : "s"} failed and retained their last
        value:{" "}
        <span className="sig">
          {failedIds.map((id) => `${id} (${(errors[id] ?? "error").slice(0, 40)})`).join(", ")}
        </span>
      </div>
    );
  }
  return (
    <div className="border-b border-edge bg-carbon/60 px-4 py-1.5 text-xs text-mute">
      {loading ? (
        <>
          <Loader2 className="mr-2 inline h-3 w-3 animate-spin" />
          Syncing with Studio Next...
        </>
      ) : (
        <>
          <CheckCircle2 className="mr-2 inline h-3 w-3 text-safe" />
          In sync{syncedAt ? ` - ${new Date(syncedAt).toLocaleTimeString()}` : ""}
        </>
      )}
    </div>
  );
}
