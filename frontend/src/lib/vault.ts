/** Share-redemption math, mirroring `withdraw_pool_shares` in the contract. */
import type { PoolState } from "./types";

/** Shares permanently held by nobody: the pool can never be fully redeemed. */
export const MIN_LOCKED_SHARES = 1000n;

/** GEN a holder receives for `shares`: floor(shares * freePool / totalShares). */
export function redeemableAssets(shares: bigint, totalShares: bigint, freePool: bigint): bigint {
  if (shares <= 0n || totalShares <= 0n || freePool <= 0n) return 0n;
  const out = (shares * freePool) / totalShares;
  return out > freePool ? freePool : out;
}

export interface LockBreakdown {
  freeLiquidity: bigint;
  reservedBounties: bigint;
  heldBonds: bigint;
  slashReserve: bigint;
  deadShares: bigint;
  outsideShares: bigint;
}

/** What is redeemable vs. what is locked, and why. */
export function lockBreakdown(pool: PoolState): LockBreakdown {
  const total = BigInt(pool.total_shares);
  return {
    freeLiquidity: BigInt(pool.bounty_pool),
    reservedBounties: BigInt(pool.reserved_bounty),
    heldBonds: BigInt(pool.held_bonds),
    slashReserve: BigInt(pool.locked_slash_reserve),
    deadShares: total === 0n ? 0n : MIN_LOCKED_SHARES,
    outsideShares: total > MIN_LOCKED_SHARES ? total - MIN_LOCKED_SHARES : 0n,
  };
}

/** Validate a redemption request; returns an error string or null. */
export function validateRedeem(request: bigint, held: bigint, totalShares: bigint, freePool: bigint): string | null {
  if (request <= 0n) return "Enter a share amount greater than zero.";
  if (request > held) return "You do not hold that many shares.";
  if (redeemableAssets(request, totalShares, freePool) <= 0n) return "That amount is too small to redeem any GEN right now.";
  return null;
}
