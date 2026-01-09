# Audit Report

## Title
JavaScript Number Precision Loss Causes Order Hash Mismatch and Denial of Service for Large Token Amounts

## Summary
The client-side order hash calculation in `scripts/utils.ts` converts BigNumber (BN) values to JavaScript numbers using `.toNumber()`, which loses precision for values exceeding `Number.MAX_SAFE_INTEGER` (2^53 - 1). This causes the client-computed hash to differ from the on-chain hash, resulting in PDA mismatch and transaction failures for orders with large token amounts. [1](#0-0) 

## Finding Description

The vulnerability stems from a type conversion mismatch between the client and on-chain hash calculations:

**Client-Side Hash Calculation:**
In the `calculateOrderHash` function, BN values are converted to JavaScript numbers before serialization: [2](#0-1) 

These values are then serialized as u64 according to the borsh schema: [3](#0-2) 

**On-Chain Hash Calculation:**
The on-chain program computes the hash by directly serializing the `OrderConfig` struct with native u64 types: [4](#0-3) 

**The Problem:**
- JavaScript's `Number` type uses IEEE 754 double-precision (64-bit float)
- It can only safely represent integers up to 2^53 - 1 (9,007,199,254,740,991)
- Solana's u64 can represent values up to 2^64 - 1 (18,446,744,073,709,551,615)
- When `.toNumber()` converts BN values exceeding `MAX_SAFE_INTEGER`, precision is lost
- The client serializes these imprecise values, producing an incorrect hash
- The on-chain program serializes the exact u64 values, producing the correct hash

**Attack Path:**
1. User attempts to create an order with `srcAmount`, `minDstAmount`, or `estimatedDstAmount` > 2^53 - 1
2. Client calls `calculateOrderHash()` which uses `.toNumber()`, losing precision
3. Client derives escrow PDA from the incorrect hash: `PDA_client`
4. Client submits transaction with `escrow = PDA_client`
5. Program validates the escrow PDA using the correct hash, expecting `PDA_onchain`
6. Anchor's PDA constraint fails because `PDA_client ≠ PDA_onchain` [5](#0-4) 

7. Transaction reverts with constraint violation

**Invariants Broken:**
- **Escrow Integrity**: Users cannot create valid escrows for large orders
- **Atomic Execution**: Operations fail before execution due to validation errors

## Impact Explanation

**Severity: Medium (Denial of Service)**

This vulnerability affects protocol usability for large orders:

1. **Order Creation DoS**: Orders with amounts > 2^53 - 1 base units cannot be created
2. **Token Decimal Impact**: 
   - For 9-decimal tokens (e.g., USDC): Limited to ~9 million tokens per order
   - For 6-decimal tokens: Limited to ~9 billion tokens
   - For tokens with more decimals, limits are even more restrictive
3. **Gas Waste**: Users attempting large orders will experience failed transactions and wasted gas fees
4. **Protocol Limitation**: Prevents institutional-size orders and high-value swaps

**Why Not Higher Severity:**
- No fund theft or unauthorized access occurs
- No existing orders can be compromised
- Users can work around by splitting large orders into multiple smaller ones
- The validation failure prevents any state corruption

## Likelihood Explanation

**Likelihood: Medium**

The issue will occur whenever:
- Users attempt to create orders with amounts exceeding 2^53 - 1 base units
- Resolvers try to fill such orders using the provided client scripts
- Any operation requiring hash calculation for large-amount orders

**Factors:**
- **Probability**: Moderate - large institutional orders or high-decimal tokens reach these limits
- **Complexity**: Low - any user can trigger by entering large amounts
- **Detection**: Difficult - users may not understand why transactions fail without clear error messages

## Recommendation

Replace `.toNumber()` with a method that preserves full u64 precision. Use `.toString()` or direct buffer conversion:

**Fixed Code for `scripts/utils.ts`:**

```typescript
export function calculateOrderHash(orderConfig: OrderConfig): Uint8Array {
  const values = {
    id: orderConfig.id,
    srcAmount: orderConfig.srcAmount,  // Keep as BN
    minDstAmount: orderConfig.minDstAmount,  // Keep as BN
    estimatedDstAmount: orderConfig.estimatedDstAmount,  // Keep as BN
    expirationTime: orderConfig.expirationTime,
    srcAssetIsNative: orderConfig.srcAssetIsNative,
    dstAssetIsNative: orderConfig.dstAssetIsNative,
    fee: {
      protocolFee: orderConfig.fee.protocolFee,
      integratorFee: orderConfig.fee.integratorFee,
      surplusPercentage: orderConfig.fee.surplusPercentage,
      maxCancellationPremium: orderConfig.fee.maxCancellationPremium,
    },
    // ... rest of the fields
  };

  return sha256(borsh.serialize(orderConfigSchema, values));
}
```

Ensure the borsh schema handles BN types correctly for u64 serialization without precision loss.

## Proof of Concept

**Reproduction Steps:**

1. Create an order with `srcAmount = new BN("10000000000000000")` (10 quadrillion)
2. This value exceeds `Number.MAX_SAFE_INTEGER`
3. Client computes hash using precision-lost value
4. Client derives escrow PDA from incorrect hash
5. Submit create transaction
6. Transaction fails with PDA constraint error

**Expected Behavior:**
```
Error: AnchorError caused by account: escrow. Error Code: ConstraintSeeds. 
Error Message: A seeds constraint was violated.
```

**Test Case:**
```typescript
import { BN } from "@coral-xyz/anchor";
import { calculateOrderHash } from "./scripts/utils";

// Value exceeding MAX_SAFE_INTEGER
const largeAmount = new BN("10000000000000000");

console.log("Original BN:", largeAmount.toString());
console.log("After .toNumber():", largeAmount.toNumber());
console.log("Precision lost:", largeAmount.toString() !== largeAmount.toNumber().toString());

// This will produce incorrect hash
const orderConfig = {
  id: 1,
  srcAmount: largeAmount,
  minDstAmount: largeAmount,
  estimatedDstAmount: largeAmount,
  // ... other fields
};

const hash = calculateOrderHash(orderConfig);
// Hash will be incorrect due to precision loss
```

**Notes**
This vulnerability demonstrates a critical mismatch between client-side JavaScript number handling and on-chain u64 arithmetic. While it doesn't directly lead to fund theft, it creates a significant protocol limitation that prevents legitimate large orders from being executed, qualifying as a Medium severity Denial of Service vulnerability.

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

**File:** scripts/utils.ts (L186-191)
```typescript
const orderConfigSchema = {
  struct: {
    id: "u32",
    srcAmount: "u64",
    minDstAmount: "u64",
    estimatedDstAmount: "u64",
```

**File:** programs/fusion-swap/src/lib.rs (L445-461)
```rust
    #[account(
        seeds = [
            "escrow".as_bytes(),
            maker.key().as_ref(),
            &order_hash(
                &order,
                protocol_dst_acc.clone().map(|acc| acc.key()),
                integrator_dst_acc.clone().map(|acc| acc.key()),
                src_mint.key(),
                dst_mint.key(),
                maker_receiver.key(),
            )?,
        ],
        bump,
    )]
    /// CHECK: check is not needed here as we never initialize the account
    escrow: UncheckedAccount<'info>,
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
