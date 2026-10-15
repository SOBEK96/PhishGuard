/**
 * Autonomous Studio Next deployment for PhishGuard:
 *   deploy -> register brands -> seed bounty pool -> live report -> on-chain readbacks.
 *
 *   PHISHGUARD_KEYSTORE_PASSWORD=... npx tsx deploy_phish_guard.ts
 *
 * Keys are never written anywhere by this script. Both accounts are standard
 * ethers v3 keystores under ~/.genlayer/keystores (created with
 * `genlayer account create`); the password is read from the environment.
 *
 * Every write goes through the SDK's own fee path:
 *   estimateTransactionFeesForWrite(...)  -> writeContract({ fees })
 *   estimateTransactionFees({})           -> deployContract({ fees })
 * Studio Next has no FeeManager, so a write that sends no fee deposit is
 * rejected before it runs; the SDK derives the deposit from the live policy.
 *
 * Receipts are only accepted when they are decided (ACCEPTED / FINALIZED), the
 * execution result is FINISHED_WITH_RETURN and the validators voted
 * MAJORITY_AGREE -- a transaction that merely landed is not a success.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Wallet } from "ethers";
import { createAccount, createClient, chains } from "genlayer-js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const CONTRACT_PATH = path.join(ROOT, "contracts", "phish_guard.py");
const OUT_PATH = path.join(ROOT, "deployments", "studio-next.json");

const RPC_URL = process.env.PHISHGUARD_RPC_URL ?? "https://studio-next.genlayer.com/api";
const EXPLORER = "https://explorer-studio-next.genlayer.com";
const CHAIN_ID = 61997;
const FEED_SHA = process.env.PHISHGUARD_FEED_SHA ?? "7f7173bf44bc1b868733978b9675882b9f6ac7f8";
const GH = "SOBEK96/PhishGuard";

const FEEDS = {
  a: { url: `https://raw.githubusercontent.com/${GH}/${FEED_SHA}/deployments/mock_feeds/a/`, operator: "github.com" },
  b: { url: `https://cdn.jsdelivr.net/gh/${GH}@${FEED_SHA}/deployments/mock_feeds/b/`, operator: "jsdelivr.com" },
  c: { url: `https://raw.githack.com/${GH}/${FEED_SHA}/deployments/mock_feeds/c/`, operator: "githack.com" },
} as const;

const ATTO = 10n ** 18n;
// 0.5 GEN is the protocol-spec seed; override with PHISHGUARD_SEED_WEI when the funding account holds less.
const SEED = BigInt(process.env.PHISHGUARD_SEED_WEI ?? (ATTO / 2n).toString());
const BOND = ATTO / 100n; // 0.01 GEN

const BRANDS: [string, string][] = [
  ["uniswap", "app.uniswap.org"],
  ["opensea", "opensea.io"],
  ["rabby", "rabby.io"],
  ["aave", "app.aave.com"],
];

const LIVE_TARGET = {
  target_id: "uniswap-claim-airdrop.com",
  campaign_id: "permit2-airdrop-2026q4",
  brand_id: "uniswap",
  first_seen_ts: 1790000000,
};

type Json = Record<string, unknown>;

function sha256(s: string | Uint8Array): string {
  return createHash("sha256").update(s).digest("hex");
}

function commitment(t: typeof LIVE_TARGET): string {
  return sha256(`phishguard.v1|${t.target_id}|${t.campaign_id}|${t.brand_id}|${t.first_seen_ts}`);
}

async function loadAccount(name: string) {
  const password = process.env.PHISHGUARD_KEYSTORE_PASSWORD;
  if (!password) throw new Error("PHISHGUARD_KEYSTORE_PASSWORD is not set");
  const file = path.join(homedir(), ".genlayer", "keystores", `${name}.json`);
  const wallet = await Wallet.fromEncryptedJson(readFileSync(file, "utf8"), password);
  return createAccount(wallet.privateKey as `0x${string}`);
}

function makeClient(account: ReturnType<typeof createAccount>) {
  const shipped = (chains as Record<string, any>).studioDevnet;
  const chain = { ...shipped, rpcUrls: { default: { http: [RPC_URL] } } };
  return createClient({ chain, endpoint: RPC_URL, account } as any) as any;
}

/** Strict finality gate (decided + FINISHED_WITH_RETURN + MAJORITY_AGREE). */
function assertStrictReceipt(label: string, r: any): Json {
  const statusName = String(r?.statusName ?? r?.status_name ?? "");
  const decided = ["ACCEPTED", "FINALIZED"].includes(statusName) || [5, 7].includes(Number(r?.status));
  const exec = String(r?.txExecutionResultName ?? r?.consensus_data?.leader_receipt?.[0]?.execution_result ?? "");
  const finished = exec === "FINISHED_WITH_RETURN" || exec === "SUCCESS" || Number(r?.txExecutionResult) === 1;
  const result = String(r?.resultName ?? r?.result_name ?? "");
  const agreed = result === "MAJORITY_AGREE" || Number(r?.result) === 6;
  const summary = { label, statusName, exec, result, status: r?.status, txExecutionResult: r?.txExecutionResult };
  if (!decided) throw new Error(`${label}: not decided: ${JSON.stringify(summary)}`);
  if (!finished) throw new Error(`${label}: execution did not return: ${JSON.stringify(summary)}`);
  if (!agreed) throw new Error(`${label}: validators did not MAJORITY_AGREE: ${JSON.stringify(summary)}`);
  return summary;
}

function toJson(v: unknown): unknown {
  return JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x instanceof Map ? Object.fromEntries(x) : x)));
}

async function write(client: any, account: any, address: string, functionName: string, args: unknown[], value = 0n) {
  const fees = await client.estimateTransactionFeesForWrite({ account, address, functionName, args, value });
  const hash = await client.writeContract({ account, address, functionName, args, value, fees });
  const receipt = await client.waitForTransactionReceipt({ hash, waitUntil: "decided", retries: 200, interval: 3000 });
  const gate = assertStrictReceipt(functionName, receipt);
  console.log(`  ${functionName.padEnd(22)} ${hash}  ${gate.statusName}/${gate.result}`);
  return { hash, receipt, gate };
}

async function read(client: any, address: string, functionName: string, args: unknown[] = []) {
  return toJson(await client.readContract({ address, functionName, args }));
}

async function main() {
  const deployer = await loadAccount("phishguard-deployer");
  const reporter = await loadAccount("phishguard-reporter");
  const dClient = makeClient(deployer);
  const rClient = makeClient(reporter);
  console.log(`deployer ${deployer.address}\nreporter ${reporter.address}`);

  const dBal = (await dClient.getBalance({ address: deployer.address })) as bigint;
  const rBal = (await rClient.getBalance({ address: reporter.address })) as bigint;
  console.log(`balances: deployer=${dBal} reporter=${rBal}`);
  if (dBal < SEED) throw new Error(`deployer cannot cover the ${SEED} wei seed`);

  const code = new Uint8Array(readFileSync(CONTRACT_PATH));
  const sourceSha = sha256(code);
  console.log(`contract sha256 ${sourceSha}`);

  // --- deploy ---------------------------------------------------------------
  const deployFees = await dClient.estimateTransactionFees({});
  const deployHash = await dClient.deployContract({
    account: deployer,
    code,
    args: [FEEDS.a.url, FEEDS.a.operator, FEEDS.b.url, FEEDS.b.operator, FEEDS.c.url, FEEDS.c.operator],
    fees: deployFees,
  });
  const deployReceipt: any = await dClient.waitForTransactionReceipt({
    hash: deployHash,
    waitUntil: "decided",
    retries: 200,
    interval: 3000,
  });
  const deployGate = assertStrictReceipt("deploy", deployReceipt);
  const address: string =
    deployReceipt?.txDataDecoded?.contractAddress ??
    deployReceipt?.data?.contract_address ??
    deployReceipt?.contractAddress ??
    deployReceipt?.contract_address;
  if (!address) throw new Error(`no contract address in receipt: ${JSON.stringify(toJson(deployReceipt)).slice(0, 800)}`);
  console.log(`deployed at ${address}  (tx ${deployHash})`);

  const onchainCode: string = await dClient.getContractCode(address).catch(() => "");
  const deployedSha = onchainCode ? sha256(onchainCode) : null;

  // --- brand registry + pool seed ---------------------------------------------
  const txs: Record<string, unknown>[] = [{ step: "deploy", hash: deployHash, ...deployGate }];
  for (const [brand, domain] of BRANDS) {
    const r = await write(dClient, deployer, address, "register_brand", [brand, domain]);
    txs.push({ step: `register_brand:${brand}`, hash: r.hash, ...r.gate });
  }
  const seed = await write(dClient, deployer, address, "fund_bounty_pool", [], SEED);
  txs.push({ step: `fund_bounty_pool(${SEED} wei)`, hash: seed.hash, ...seed.gate });

  // --- live triage from the dedicated reporter ----------------------------------
  const ev = commitment(LIVE_TARGET);
  const rep = await write(
    rClient, reporter, address, "report_target",
    [LIVE_TARGET.target_id, ev, LIVE_TARGET.campaign_id, LIVE_TARGET.brand_id, BigInt(LIVE_TARGET.first_seen_ts)],
    BOND,
  );
  txs.push({ step: "report_target(0.01 GEN bond)", hash: rep.hash, ...rep.gate });

  // --- authoritative readbacks ----------------------------------------------------
  const readbacks = {
    get_pool_state: await read(dClient, address, "get_pool_state"),
    get_target_status: await read(dClient, address, "get_target_status", [LIVE_TARGET.target_id]),
    get_feed_sources: await read(dClient, address, "get_feed_sources"),
    check_transaction_safety: await read(dClient, address, "check_transaction_safety", [LIVE_TARGET.target_id]),
    get_governor: await read(dClient, address, "get_governor"),
    get_brand_uniswap: await read(dClient, address, "get_brand", ["uniswap"]),
  };
  console.log(JSON.stringify(readbacks, null, 2));

  mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  const out = {
    network: "studio-next",
    chain_id: CHAIN_ID,
    rpc_url: RPC_URL,
    explorer_url: `${EXPLORER}/address/${address}`,
    contract_address: address,
    deployer_address: deployer.address,
    reporter_address: reporter.address,
    source: "contracts/phish_guard.py",
    source_sha256: sourceSha,
    deployed_code_sha256: deployedSha,
    feed_pin: { repo: `https://github.com/${GH}`, commit: FEED_SHA, feeds: FEEDS },
    seed_wei: SEED.toString(),
    live_target: { ...LIVE_TARGET, evidence_hash: ev },
    deployed_at: new Date().toISOString(),
    transactions: txs,
    readbacks,
  };
  writeFileSync(OUT_PATH, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${path.relative(ROOT, OUT_PATH)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
