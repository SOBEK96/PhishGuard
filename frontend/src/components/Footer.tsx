import { ExternalLink } from "lucide-react";
import { CONTRACT_ADDRESS, EXPLORER_URL, REPO_URL, explorerAddress } from "@/lib/deployment";
import { shortAddress } from "@/lib/format";

export default function Footer() {
  return (
    <footer className="mt-10 border-t border-edge px-4 py-6 text-xs text-mute">
      <div className="mx-auto flex max-w-6xl flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <a
          href={explorerAddress(CONTRACT_ADDRESS)}
          target="_blank"
          rel="noreferrer"
          className="sig inline-flex items-center gap-2 rounded border border-radar/40 bg-radar/10 px-3 py-2 text-radar"
        >
          <span className="h-2 w-2 rounded-full bg-safe" />
          PhishGuard {shortAddress(CONTRACT_ADDRESS)}
          <ExternalLink className="h-3 w-3" />
        </a>
        <div className="flex flex-wrap gap-4">
          <a className="underline" href={EXPLORER_URL} target="_blank" rel="noreferrer">
            Studio Next explorer
          </a>
          <a className="underline" href={REPO_URL} target="_blank" rel="noreferrer">
            Source - SOBEK96/PhishGuard
          </a>
          <span className="sig">chain 61997</span>
        </div>
      </div>
    </footer>
  );
}
