/**
 * GenLayer SDK integration (EIP-1193 wallet signing + RPC reads).
 *
 * Writes always go through the SDK fee path (estimateTransactionFeesForWrite)
 * and are only reported successful after the strict receipt gate in receipt.ts.
 * genlayer-js is imported lazily so static export / SSR never touches it.
 */
import { CHAIN_ID, CONTRACT_ADDRESS, RPC_URL } from "./deployment";
import { assertReceipt, type ReceiptVerdict } from "./receipt";
import { parseFeeds, parsePool, parseSafety, parseTarget, parseVestEntry } from "./parse";
import {
  commitment,
  isValidLabel,
  isValidTargetId,
  validateReport,
  type Attributes,
} from "./validation";
import type { FeedSource, PoolState, SafetyCheck, TargetStatus, VestEntry } from "./types";

type Hex = `0x${string}`;
// The SDK client is large and structurally typed by viem; we only use a narrow slice.
/* eslint-disable @typescript-eslint/no-explicit-any */
export type SdkClient = any;

export interface EthereumProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, handler: (...a: unknown[]) => void): void;
  removeListener?(event: string, handler: (...a: unknown[]) => void): void;
}

export function getProvider(): EthereumProvider | null {
  if (typeof window === "undefined") return null;
  const eth = (window as unknown as { ethereum?: EthereumProvider }).ethereum;
  return eth ?? null;
}

export async function readClient(): Promise<SdkClient> {
  const sdk = await import("genlayer-js");
  const shipped = (sdk.chains as Record<string, any>).studioDevnet;
  const chain = { ...shipped, rpcUrls: { default: { http: [RPC_URL] } } };
  return sdk.createClient({ chain, endpoint: RPC_URL } as any);
}

export async function walletClient(account: string): Promise<SdkClient> {
  const sdk = await import("genlayer-js");
  const shipped = (sdk.chains as Record<string, any>).studioDevnet;
  const chain = { ...shipped, rpcUrls: { default: { http: [RPC_URL] } } };
  return sdk.createClient({ chain, endpoint: RPC_URL, account: account as Hex } as any);
}

/** Ask the wallet to switch to (or add) GenLayer Studio Next. */
export async function ensureChain(provider: EthereumProvider): Promise<void> {
  const chainIdHex = `0x${CHAIN_ID.toString(16)}`;
  try {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainIdHex }] });
  } catch (e) {
    const code = (e as { code?: number }).code;
    if (code !== 4902) throw e;
    await provider.request({
      method: "wallet_addEthereumChain",
      params: [
        {
          chainId: chainIdHex,
          chainName: "GenLayer Studio Next",
          nativeCurrency: { name: "GEN", symbol: "GEN", decimals: 18 },
          rpcUrls: [RPC_URL],
        },
      ],
    });
  }
}

async function call(client: SdkClient, functionName: string, args: unknown[] = []): Promise<unknown> {
  return client.readContract({ address: CONTRACT_ADDRESS as Hex, functionName, args });
}

export async function readPool(client: SdkClient): Promise<PoolState> {
  return parsePool(await call(client, "get_pool_state"));
}

export async function readFeeds(client: SdkClient): Promise<FeedSource[]> {
  return parseFeeds(await call(client, "get_feed_sources"));
}

export async function readTarget(client: SdkClient, targetId: string): Promise<TargetStatus> {
  if (!isValidTargetId(targetId)) throw new Error("invalid target id");
  return parseTarget(await call(client, "get_target_status", [targetId]));
}

export async function readSafety(client: SdkClient, targetId: string): Promise<SafetyCheck> {
  if (!isValidTargetId(targetId)) throw new Error("invalid target id");
  return parseSafety(await call(client, "check_transaction_safety", [targetId]));
}

export async function readClaimable(client: SdkClient, owner: string): Promise<string> {
  const v = await call(client, "claimable_of", [owner.toLowerCase()]);
  if (typeof v !== "string" || !/^\d+$/.test(v)) throw new Error("claimable: bad shape");
  return v;
}

export async function readVestEntries(client: SdkClient, limit = 50): Promise<VestEntry[]> {
  const count = Number(await call(client, "get_vest_count"));
  const out: VestEntry[] = [];
  for (let i = Math.max(0, count - limit); i < count; i++) {
    out.push(parseVestEntry(await call(client, "get_vest_entry", [BigInt(i)])));
  }
  return out;
}

export async function readShares(client: SdkClient, owner: string): Promise<string> {
  const v = await call(client, "shares_of", [owner.toLowerCase()]);
  if (typeof v !== "string" || !/^\d+$/.test(v)) throw new Error("shares: bad shape");
  return v;
}

export async function readTargetIndex(client: SdkClient, count: number, limit = 50): Promise<string[]> {
  const ids: string[] = [];
  const start = Math.max(0, count - limit);
  for (let i = count - 1; i >= start; i--) {
    const v = await call(client, "get_target_id_by_index", [BigInt(i)]);
    if (typeof v === "string") ids.push(v);
  }
  return ids;
}

export interface WriteResult {
  hash: string;
  verdict: ReceiptVerdict;
}

export async function sendWrite(
  account: string,
  functionName: string,
  args: unknown[],
  value = 0n,
  onHash?: (hash: string) => void,
): Promise<WriteResult> {
  const client = await walletClient(account);
  const common = { account: account as Hex, address: CONTRACT_ADDRESS as Hex, functionName, args, value };
  // Official SDK gas / fee estimation -- never a hand-rolled constant.
  const fees = await client.estimateTransactionFeesForWrite(common);
  const hash: string = await client.writeContract({ ...common, fees });
  onHash?.(hash);
  const receipt = await client.waitForTransactionReceipt({ hash, waitUntil: "decided", retries: 200, interval: 3000 });
  const verdict = assertReceipt(functionName, receipt);
  return { hash, verdict };
}

export async function reportTarget(account: string, a: Attributes, bondWei: bigint, minBondWei: bigint, onHash?: (h: string) => void) {
  const err = validateReport({ ...a, bondWei }, minBondWei);
  if (err) throw new Error(err);
  const ev = await commitment(a);
  return sendWrite(account, "report_target", [a.targetId, ev, a.campaignId, a.brandId, BigInt(a.firstSeenTs)], bondWei, onHash);
}

export async function appeal(account: string, targetId: string, bondWei: bigint, minBondWei: bigint, onHash?: (h: string) => void) {
  if (!isValidTargetId(targetId)) throw new Error("invalid target id");
  if (bondWei < minBondWei) throw new Error("Appeal bond is below the minimum.");
  return sendWrite(account, "appeal_classification", [targetId], bondWei, onHash);
}

export async function claimSettlement(account: string, targetId: string, onHash?: (h: string) => void) {
  if (!isValidTargetId(targetId)) throw new Error("invalid target id");
  return sendWrite(account, "claim_settlement", [targetId], 0n, onHash);
}

export async function claimPayout(account: string, onHash?: (h: string) => void) {
  return sendWrite(account, "claim_payout", [], 0n, onHash);
}

export async function fundPool(account: string, valueWei: bigint, onHash?: (h: string) => void) {
  if (valueWei <= 0n) throw new Error("Deposit must be greater than zero.");
  return sendWrite(account, "fund_bounty_pool", [], valueWei, onHash);
}

export async function claimVested(account: string, entryId: number, onHash?: (h: string) => void) {
  if (!Number.isSafeInteger(entryId) || entryId < 0) throw new Error("invalid vest entry id");
  return sendWrite(account, "claim_vested", [BigInt(entryId)], 0n, onHash);
}

export async function withdrawShares(account: string, shareAmount: bigint, onHash?: (h: string) => void) {
  if (shareAmount <= 0n) throw new Error("Share amount must be greater than zero.");
  return sendWrite(account, "withdraw_pool_shares", [shareAmount], 0n, onHash);
}

export async function reevaluate(account: string, targetId: string, onHash?: (h: string) => void) {
  if (!isValidTargetId(targetId)) throw new Error("invalid target id");
  return sendWrite(account, "reevaluate_target", [targetId], 0n, onHash);
}

export function sanitizeLabel(s: string): string | null {
  const t = s.trim().toLowerCase();
  return isValidLabel(t) ? t : null;
}
