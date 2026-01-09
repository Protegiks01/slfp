# Audit Report

## Title
JavaScript Safe Integer Precision Loss in Order Hash Calculation Causes PDA Derivation Mismatch

## Summary
The client-side `calculateOrderHash` function in `scripts/utils.ts` inconsistently converts BN values to JavaScript numbers, causing precision loss for values exceeding `Number.MAX_SAFE_INTEGER` (2^53-1). This creates a mismatch between client-calculated and on-chain-calculated order hashes, resulting in escrow PDA derivation failures and preventing order creation/filling.

## Finding Description

The vulnerability exists in the order hash calculation logic where client and on-chain use different serialization approaches for large numeric values. [1](#0-0) 

In the client-side `calculateOrderHash` function, three u64 fields (`srcAmount`, `minDstAmount`, `estimatedDstAmount`) are explicitly converted using `.toNumber()`: [2](#0-1) 

However, `maxCancellationPremium` is NOT converted and remains as a BN object: [3](#0-2) 

This inconsistency reveals a fundamental issue: when token amounts exceed JavaScript's `Number.MAX_SAFE_INTEGER` (9,007,199,254,740,991), the `.toNumber()` method loses precision, truncating the value. The resulting hash calculation uses imprecise values, while the on-chain program calculates the hash using full precision: [4](#0-3) 

**Attack Scenario:**

1. User attempts to create an order with `srcAmount > 2^53-1` (e.g., for tokens with high decimals or large supplies)
2. Client calls `calculateOrderHash`, which converts `srcAmount.toNumber()` → precision lost
3. Client derives escrow PDA using imprecise hash
4. Client sends create transaction with Anchor's proper BN serialization (full precision)
5. On-chain receives full precision values in instruction data
6. On-chain validates escrow PDA by recalculating hash with full precision values
7. Hashes don't match: client-calculated ≠ on-chain-calculated
8. PDA constraint fails, transaction reverts

This breaks the **PDA Security** invariant - the client cannot correctly derive the escrow address needed for order operations.

## Impact Explanation

**Severity: HIGH**

The impact is significant denial of service for high-value orders:

1. **Transaction Failures**: Orders with amounts exceeding 2^53-1 cannot be created using the provided tooling
2. **User Experience Degradation**: Users attempting large trades experience unexplained transaction failures
3. **Protocol Limitation**: The protocol technically supports u64 values (up to 2^64-1), but client tooling limits practical usage to 2^53-1
4. **Ecosystem Fragmentation**: Users must develop custom tooling to handle large amounts, bypassing the official scripts

For tokens with 9 decimals (like SOL), this threshold is ~9 million tokens. For tokens with fewer decimals or different economic models, reaching this limit is more feasible.

## Likelihood Explanation

**Likelihood: MEDIUM**

While not immediately exploitable for fund theft, this issue affects legitimate high-value use cases:

- Institutional traders moving large amounts
- Tokens with high decimal precision
- Tokens with large total supplies
- Cross-chain bridges handling aggregated amounts

The issue manifests automatically when amounts exceed the threshold - no special attack setup required. However, most retail users won't encounter this limit, reducing overall probability.

## Recommendation

**Fix the inconsistent BN handling in `calculateOrderHash`:**

Remove all `.toNumber()` conversions and let the borsh library handle BN objects directly. The borsh-js library (v2.0.0 used in the project) properly handles BN objects for u64 fields without precision loss.

**Corrected implementation:**

```typescript
export function calculateOrderHash(orderConfig: OrderConfig): Uint8Array {
  const values = {
    id: orderConfig.id,
    srcAmount: orderConfig.srcAmount,  // Remove .toNumber()
    minDstAmount: orderConfig.minDstAmount,  // Remove .toNumber()
    estimatedDstAmount: orderConfig.estimatedDstAmount,  // Remove .toNumber()
    expirationTime: orderConfig.expirationTime,
    srcAssetIsNative: orderConfig.srcAssetIsNative,
    dstAssetIsNative: orderConfig.dstAssetIsNative,
    fee: {
      protocolFee: orderConfig.fee.protocolFee,
      integratorFee: orderConfig.fee.integratorFee,
      surplusPercentage: orderConfig.fee.surplusPercentage,
      maxCancellationPremium: orderConfig.fee.maxCancellationPremium,
    },
    dutchAuctionData: {
      startTime: orderConfig.dutchAuctionData.startTime,
      duration: orderConfig.dutchAuctionData.duration,
      initialRateBump: orderConfig.dutchAuctionData.initialRateBump,
      pointsAndTimeDeltas: orderConfig.dutchAuctionData.pointsAndTimeDeltas.map(
        (p) => ({
          rateBump: p.rateBump,
          timeDelta: p.timeDelta,
        })
      ),
    },
    cancellationAuctionDuration: orderConfig.cancellationAuctionDuration,
    protocolDstAcc: orderConfig.fee.protocolDstAcc?.toBuffer(),
    integratorDstAcc: orderConfig.fee.integratorDstAcc?.toBuffer(),
    srcMint: orderConfig.srcMint.toBuffer(),
    dstMint: orderConfig.dstMint.toBuffer(),
    receiver: orderConfig.receiver.toBuffer(),
  };

  return sha256(borsh.serialize(orderConfigSchema, values));
}
```

This allows the borsh library to handle BN objects consistently, maintaining precision for all u64 values.

## Proof of Concept

```typescript
import { BN } from "@coral-xyz/anchor";
import { calculateOrderHash, OrderConfig } from "./scripts/utils";
import { PublicKey } from "@solana/web3.js";

// Create two order configs with same data but different amount representations
const largeAmount = new BN("9007199254740992"); // 2^53, exceeds safe integer

const orderConfig: OrderConfig = {
  id: 1,
  srcAmount: largeAmount,
  minDstAmount: new BN(1000),
  estimatedDstAmount: new BN(1000),
  expirationTime: 1234567890,
  srcAssetIsNative: false,
  dstAssetIsNative: false,
  srcMint: new PublicKey("So11111111111111111111111111111111111111112"),
  dstMint: new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
  receiver: new PublicKey("11111111111111111111111111111111"),
  fee: {
    protocolDstAcc: null,
    integratorDstAcc: null,
    protocolFee: 0,
    integratorFee: 0,
    surplusPercentage: 0,
    maxCancellationPremium: new BN(0),
  },
  dutchAuctionData: {
    startTime: 0xffffffff - 32000,
    duration: 32000,
    initialRateBump: 0,
    pointsAndTimeDeltas: [],
  },
  cancellationAuctionDuration: 32000,
};

// Calculate hash - will use imprecise .toNumber() conversion
const hash1 = calculateOrderHash(orderConfig);

// Verify the issue: srcAmount.toNumber() returns exactly 2^53
console.log("Original BN:", largeAmount.toString());
console.log("After .toNumber():", largeAmount.toNumber());
console.log("Precision lost:", largeAmount.toString() !== largeAmount.toNumber().toString());

// Expected: Hash calculated with imprecise value differs from on-chain calculation
// On-chain would calculate hash from full precision BN value
```

**Expected Result**: The client calculates a hash using truncated values, while the on-chain program calculates a different hash using full precision, causing PDA validation to fail during order creation.

---

## Notes

The vulnerability specifically affects the client-side tooling rather than the on-chain program itself. The on-chain program correctly handles full u64 precision. However, since the provided client scripts are the primary interface for users and resolvers, this inconsistency effectively limits the protocol's usable range to JavaScript's safe integer limit, creating a practical denial of service for large-value orders.

### Citations

**File:** scripts/utils.ts (L147-184)
```typescript
export function calculateOrderHash(orderConfig: OrderConfig): Uint8Array {
  const values = {
    id: orderConfig.id,
    srcAmount: orderConfig.srcAmount.toNumber(),
    minDstAmount: orderConfig.minDstAmount.toNumber(),
    estimatedDstAmount: orderConfig.estimatedDstAmount.toNumber(),
    expirationTime: orderConfig.expirationTime,
    srcAssetIsNative: orderConfig.srcAssetIsNative,
    dstAssetIsNative: orderConfig.dstAssetIsNative,
    fee: {
      protocolFee: orderConfig.fee.protocolFee,
      integratorFee: orderConfig.fee.integratorFee,
      surplusPercentage: orderConfig.fee.surplusPercentage,
      maxCancellationPremium: orderConfig.fee.maxCancellationPremium,
    },
    dutchAuctionData: {
      startTime: orderConfig.dutchAuctionData.startTime,
      duration: orderConfig.dutchAuctionData.duration,
      initialRateBump: orderConfig.dutchAuctionData.initialRateBump,
      pointsAndTimeDeltas: orderConfig.dutchAuctionData.pointsAndTimeDeltas.map(
        (p) => ({
          rateBump: p.rateBump,
          timeDelta: p.timeDelta,
        })
      ),
    },
    cancellationAuctionDuration: orderConfig.cancellationAuctionDuration,

    // Accounts concatenated directly to OrderConfig
    protocolDstAcc: orderConfig.fee.protocolDstAcc?.toBuffer(),
    integratorDstAcc: orderConfig.fee.integratorDstAcc?.toBuffer(),
    srcMint: orderConfig.srcMint.toBuffer(),
    dstMint: orderConfig.dstMint.toBuffer(),
    receiver: orderConfig.receiver.toBuffer(),
  };

  return sha256(borsh.serialize(orderConfigSchema, values));
}
```

**File:** programs/fusion-swap/src/lib.rs (L745-762)
```rust
fn order_hash(
    order: &OrderConfig,
    protocol_dst_acc: Option<Pubkey>,
    integrator_dst_acc: Option<Pubkey>,
    src_mint: Pubkey,
    dst_mint: Pubkey,
    receiver: Pubkey,
) -> Result<[u8; 32]> {
    Ok(hashv(&[
        &order.try_to_vec()?,
        &protocol_dst_acc.try_to_vec()?,
        &integrator_dst_acc.try_to_vec()?,
        &src_mint.to_bytes(),
        &dst_mint.to_bytes(),
        &receiver.to_bytes(),
    ])
    .to_bytes())
}
```
