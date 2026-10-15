/**
 * Ad-hoc signed write against a deployed PhishGuard, with SDK fee estimation.
 *
 *   PHISHGUARD_KEYSTORE_PASSWORD=... npx tsx ops.ts <keystore-name> <contract> <method> [valueWei] [jsonArgs]
 *
 * e.g. npx tsx ops.ts phishguard-reporter 0x... claim_payout
 *      npx tsx ops.ts phishguard-reporter 0x... appeal_classification 10000000000000000 '["some-domain.com"]'
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { Wallet } from "ethers";
import { createAccount, createClient, chains } from "genlayer-js";

const [name, address, method, valueArg = "0", argsArg = "[]"] = process.argv.slice(2);
if (!name || !address || !method) {
  console.error("usage: ops.ts <keystore-name> <contract> <method> [valueWei] [jsonArgs]");
  process.exit(2);
}
const RPC = process.env.PHISHGUARD_RPC_URL ?? "https://studio-next.genlayer.com/api";
const password = process.env.PHISHGUARD_KEYSTORE_PASSWORD;
if (!password) throw new Error("PHISHGUARD_KEYSTORE_PASSWORD is not set");

const wallet = await Wallet.fromEncryptedJson(
  readFileSync(path.join(homedir(), ".genlayer", "keystores", `${name}.json`), "utf8"),
  password,
);
const account = createAccount(wallet.privateKey as `0x${string}`);
const shipped = (chains as Record<string, any>).studioDevnet;
const client: any = createClient({
  chain: { ...shipped, rpcUrls: { default: { http: [RPC] } } },
  endpoint: RPC,
  account,
} as any);

const args = (JSON.parse(argsArg) as unknown[]).map((a) =>
  typeof a === "string" && /^\d{10,}$/.test(a) ? BigInt(a) : a,
);
const value = BigInt(valueArg);
const fees = await client.estimateTransactionFeesForWrite({ account, address, functionName: method, args, value });
const hash = await client.writeContract({ account, address, functionName: method, args, value, fees });
const r: any = await client.waitForTransactionReceipt({ hash, waitUntil: "decided", retries: 200, interval: 3000 });
console.log(JSON.stringify({ hash, statusName: r.statusName, result: r.resultName, exec: r.txExecutionResultName }));
