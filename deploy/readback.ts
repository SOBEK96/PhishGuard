/**
 * Paced readbacks for a deployed PhishGuard (Studio Next allows 30 RPC req/min).
 *   npx tsx readback.ts <contract> <target_id> [out.json]
 */
import { writeFileSync } from "node:fs";
import { createClient, chains } from "genlayer-js";

const [address, target, out] = process.argv.slice(2);
if (!address || !target) {
  console.error("usage: readback.ts <contract> <target_id> [out.json]");
  process.exit(2);
}
const RPC = process.env.PHISHGUARD_RPC_URL ?? "https://studio-next.genlayer.com/api";
const shipped = (chains as Record<string, any>).studioDevnet;
const client: any = createClient({ chain: { ...shipped, rpcUrls: { default: { http: [RPC] } } }, endpoint: RPC } as any);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const plain = (v: unknown) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x instanceof Map ? Object.fromEntries(x) : x)));

async function read(fn: string, args: unknown[] = []) {
  await sleep(2500);
  return plain(await client.readContract({ address, functionName: fn, args }));
}
async function outcome(fn: string, args: unknown[]) {
  try {
    return { reverted: false, value: await read(fn, args) };
  } catch (e) {
    return { reverted: true, error: String((e as Error)?.message ?? e).split("\n").slice(-2).join(" ").slice(0, 200) };
  }
}

const rb = {
  get_pool_state: await read("get_pool_state"),
  get_target_status: await read("get_target_status", [target]),
  get_feed_sources: await read("get_feed_sources"),
  check_transaction_safety: await read("check_transaction_safety", [target]),
  check_transaction_safety_subdomain: await read("check_transaction_safety", [`app.${target}`]),
  check_transaction_safety_deep_subdomain: await read("check_transaction_safety", [`claim.app.${target}`]),
  get_target_status_subdomain: await read("get_target_status", [`app.${target}`]),
  check_transaction_safety_unrelated: await read("check_transaction_safety", [`not${target}`]),
  assert_target_safe_exact: await outcome("assert_target_safe", [target]),
  assert_target_safe_subdomain: await outcome("assert_target_safe", [`app.${target}`]),
  get_vest_count: await read("get_vest_count"),
  get_governor: await read("get_governor"),
};
const text = JSON.stringify(rb, null, 2);
if (out) writeFileSync(out, text + "\n");
else console.log(text);
