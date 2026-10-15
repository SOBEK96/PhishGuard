/**
 * Live follow-up on the hardened deployment: exercises the mid-epoch cap fix.
 *   1. fund_bounty_pool (+TOPUP) from the deployer  -> epoch_cap must rise by 20% of the deposit
 *   2. report_target for a second fixture target from the reporter -> bounty must now reserve
 *   3. appends transactions + readbacks to deployments/studio-next.json
 *
 *   PHISHGUARD_KEYSTORE_PASSWORD=... npx tsx post_deploy.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Wallet } from "ethers";
import { createAccount, createClient, chains } from "genlayer-js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "deployments", "studio-next.json");
const RPC = "https://studio-next.genlayer.com/api";
const TOPUP = BigInt(process.env.PHISHGUARD_TOPUP_WEI ?? "40000000000000000");
const BOND = 10n ** 16n;
const T2 = { target_id: "opensea-seaport-mint.net", campaign_id: "seaport-hijack-2026q4", brand_id: "opensea", first_seen_ts: 1790200000 };

async function acct(name: string) {
  const pw = process.env.PHISHGUARD_KEYSTORE_PASSWORD;
  if (!pw) throw new Error("PHISHGUARD_KEYSTORE_PASSWORD is not set");
  const w = await Wallet.fromEncryptedJson(readFileSync(path.join(homedir(), ".genlayer", "keystores", `${name}.json`), "utf8"), pw);
  return createAccount(w.privateKey as `0x${string}`);
}
function client(account: unknown) {
  const s = (chains as Record<string, any>).studioDevnet;
  return createClient({ chain: { ...s, rpcUrls: { default: { http: [RPC] } } }, endpoint: RPC, account } as any) as any;
}
const plain = (v: unknown) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x instanceof Map ? Object.fromEntries(x) : x)));

async function write(c: any, account: any, address: string, fn: string, args: unknown[], value = 0n) {
  const fees = await c.estimateTransactionFeesForWrite({ account, address, functionName: fn, args, value });
  const hash = await c.writeContract({ account, address, functionName: fn, args, value, fees });
  const r = await c.waitForTransactionReceipt({ hash, waitUntil: "decided", retries: 200, interval: 3000 });
  const status = String(r.statusName ?? r.status_name ?? "");
  const exec = String(r.txExecutionResultName ?? "");
  const cons = String(r.resultName ?? r.result_name ?? "");
  if (!["ACCEPTED", "FINALIZED"].includes(status) || exec !== "FINISHED_WITH_RETURN" || cons !== "MAJORITY_AGREE") {
    throw new Error(`${fn}: ${status}/${exec}/${cons}`);
  }
  console.log(`  ${fn.padEnd(20)} ${hash}  ${status}/${cons}`);
  return { step: fn, hash, statusName: status, exec, result: cons };
}

const rec = JSON.parse(readFileSync(OUT, "utf8"));
const address: string = rec.contract_address;
const deployer = await acct("phishguard-deployer");
const reporter = await acct("phishguard-reporter");
const dC = client(deployer);
const rC = client(reporter);
const read = async (fn: string, args: unknown[] = []) => plain(await dC.readContract({ address, functionName: fn, args }));

const before = await read("get_pool_state");
const txs: Record<string, unknown>[] = [];
txs.push({ ...(await write(dC, deployer, address, "fund_bounty_pool", [], TOPUP)), step: `fund_bounty_pool(+${TOPUP} wei, mid-epoch top-up)` });
const mid = await read("get_pool_state");

const ev = createHash("sha256").update(`phishguard.v1|${T2.target_id}|${T2.campaign_id}|${T2.brand_id}|${T2.first_seen_ts}`).digest("hex");
txs.push({ ...(await write(rC, reporter, address, "report_target", [T2.target_id, ev, T2.campaign_id, T2.brand_id, BigInt(T2.first_seen_ts)], BOND)), step: "report_target(second target, 0.01 GEN bond)" });

const readbacks = {
  pool_before_topup: before,
  pool_after_topup: mid,
  get_pool_state: await read("get_pool_state"),
  get_target_status_second: await read("get_target_status", [T2.target_id]),
  check_transaction_safety_second_subdomain: await read("check_transaction_safety", [`pay.${T2.target_id}`]),
  check_transaction_safety_first: await read("check_transaction_safety", [rec.live_target.target_id]),
};
console.log(JSON.stringify(readbacks, null, 2));

rec.transactions.push(...txs);
rec.second_live_target = { ...T2, evidence_hash: ev };
rec.readbacks_after_topup = readbacks;
writeFileSync(OUT, JSON.stringify(rec, null, 2) + "\n");
