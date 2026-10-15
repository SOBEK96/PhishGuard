/**
 * Deployment configuration. The address is pinned from `deployment.json`
 * (written by the deploy script) and may be overridden per environment with
 * NEXT_PUBLIC_PHISHGUARD_ADDRESS.
 */
import deployment from "./deployment.json";

export const CHAIN_ID = 61997;
export const RPC_URL = process.env.NEXT_PUBLIC_GENLAYER_RPC_URL ?? "https://studio-next.genlayer.com/api";
export const EXPLORER_URL = "https://explorer-studio-next.genlayer.com";
export const REPO_URL = "https://github.com/SOBEK96/PhishGuard";

export const CONTRACT_ADDRESS: string =
  process.env.NEXT_PUBLIC_PHISHGUARD_ADDRESS ?? (deployment as { contract_address: string }).contract_address;

export const DEPLOYER_ADDRESS: string = (deployment as { deployer_address: string }).deployer_address;
export const DEMO_TARGET = "uniswap-claim-airdrop.com";

export function explorerAddress(address: string): string {
  return `${EXPLORER_URL}/address/${address}`;
}

export function explorerTx(hash: string): string {
  return `${EXPLORER_URL}/transactions/${hash}`;
}
