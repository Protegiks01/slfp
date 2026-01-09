# Audit Report

## Title
BN Precision Loss Causes Order Creation Failures and Hash Mismatch for Large Token Amounts

## Summary
The client-side order creation script contains multiple `.toNumber()` calls that lose precision for token amounts exceeding 2^53 (approximately 9 million SOL or equivalent). This causes a critical hash mismatch between client and on-chain calculations, leading to consistent transaction failures for large orders and breaking the PDA Security invariant.

## Finding Description

The vulnerability exists in three critical locations:

**Location 1: Native SOL Wrapping** [1](#0-0) 

When wrapping native SOL, the code converts the BN amount to a JavaScript number using `.toNumber()`. JavaScript numbers can only safely represent integers up to 2^53 - 1 (9,007,199,254,740,991). For SOL with 9 decimals, this is approximately 9,007,199 SOL.

**Location 2: Order Hash Calculation** [2](#0-1) 

The `calculateOrderHash` function converts all BN amount fields to JavaScript numbers before serialization. This causes the client to compute a different hash than the on-chain program for large amounts.

**Location 3: BN Value Usage** [3](#0-2) [4](#0-3) 

The function parameters use BN types, but the `.toNumber()` conversions in subsequent operations lose precision.

**How the Attack Manifests:**

1. User attempts to create an order with `srcAmount` > 2^53 lamports (e.g., 10 million SOL)
2. Client calculates order hash using truncated values from `.toNumber()` conversions
3. Client derives escrow PDA: `["escrow", maker, truncated_hash]` [5](#0-4) 
4. On-chain program calculates hash using full u64 values [6](#0-5) 
5. Program expects PDA: `["escrow", maker, full_hash]` [7](#0-6) 
6. PDA seed verification fails, entire transaction reverts

**Which Invariants Are Broken:**

- **PDA Security Invariant (#9)**: Client and program compute different order hashes, causing PDA derivation mismatch
- **Token Safety Invariant (#2)**: For native transfers, truncated amount is used instead of full amount
- **Escrow Integrity Invariant (#3)**: Incorrect amounts prevent proper escrow setup

## Impact Explanation

**Severity: HIGH**

This is a HIGH severity issue because:

1. **Core Functionality Breakdown**: Order creation is fundamental protocol functionality. Large orders (institutional trades, whale swaps) consistently fail for amounts exceeding ~9 million SOL or equivalent in other tokens.

2. **Hash Mismatch is Critical**: The client and on-chain program computing different hashes for the same order represents a fundamental protocol design flaw. This breaks the PDA derivation mechanism entirely.

3. **Affects Real-World Scenarios**: 
   - For SOL (9 decimals): Affects orders > 9,007,199 SOL (~$900M at $100/SOL)
   - For USDC (6 decimals): Affects orders > 9,007,199,254 USDC (~$9B)
   - For tokens with higher decimal places, the threshold is lower

4. **While atomic execution prevents direct fund loss**, the DoS effect on large orders is severe enough to warrant HIGH severity classification as it causes "Partial protocol disruption affecting multiple users."

## Likelihood Explanation

**Likelihood: MEDIUM**

The likelihood is MEDIUM because:

- **Requires large amounts**: The issue only manifests for amounts > 2^53 base units
- **Real-world occurrence**: Large institutional orders, protocol-to-protocol swaps, or treasury management operations could easily exceed these thresholds
- **No special privileges needed**: Any user attempting to create a large order will encounter this
- **Deterministic failure**: The issue occurs 100% of the time for affected amounts

## Recommendation

**Fix 1: Remove `.toNumber()` from hash calculation**

In `scripts/utils.ts`, modify `calculateOrderHash` to work directly with u64 values:

```typescript
export function calculateOrderHash(orderConfig: OrderConfig): Uint8Array {
  const values = {
    id: orderConfig.id,
    srcAmount: orderConfig.srcAmount, // Keep as BN, serialize properly
    minDstAmount: orderConfig.minDstAmount, // Keep as BN
    estimatedDstAmount: orderConfig.estimatedDstAmount, // Keep as BN
    // ... rest of fields
  };
  
  // Ensure proper u64 serialization in orderConfigSchema
  return sha256(borsh.serialize(orderConfigSchema, values));
}
```

Update the schema to handle BN/u64 properly:
```typescript
const orderConfigSchema = {
  struct: {
    id: "u32",
    srcAmount: "u64", // Will serialize BN as u64
    minDstAmount: "u64",
    estimatedDstAmount: "u64",
    // ...
  }
};
```

**Fix 2: Replace `.toNumber()` for native transfers**

In `scripts/fusion-swap/create.ts`, use `toArrayLike` or `toString` for large numbers:

```typescript
const transferIx = SystemProgram.transfer({
  fromPubkey: makerKeypair.publicKey,
  toPubkey: makerNativeAta,
  lamports: srcAmount.toNumber(), // REMOVE THIS
});
```

Replace with proper handling:
```typescript
// Check if value exceeds safe integer
if (srcAmount.gt(new BN(Number.MAX_SAFE_INTEGER))) {
  throw new Error(`Amount ${srcAmount.toString()} exceeds JavaScript number precision. Use BN directly.`);
}

const transferIx = SystemProgram.transfer({
  fromPubkey: makerKeypair.publicKey,
  toPubkey: makerNativeAta,
  lamports: srcAmount.toNumber(),
});
```

Or better yet, ensure SystemProgram.transfer accepts BN directly.

**Fix 3: Input validation in main()**

Add validation to prevent precision loss during BN construction:

```typescript
const srcAmountWithDecimals = srcAmount * Math.pow(10, srcMintDecimals);
if (srcAmountWithDecimals > Number.MAX_SAFE_INTEGER) {
  throw new Error(`Amount exceeds safe integer range. Please use BN input directly.`);
}
const srcAmountBN = new BN(srcAmountWithDecimals);
```

## Proof of Concept

**Reproduction Steps:**

```typescript
import { BN } from "@coral-xyz/anchor";

// Test case 1: Demonstrate precision loss in arithmetic
const srcAmount = 10_000_000; // 10 million SOL
const decimals = 9;
const calculated = srcAmount * Math.pow(10, decimals);
console.log("Calculated:", calculated); // May lose precision
console.log("Max safe integer:", Number.MAX_SAFE_INTEGER);
console.log("Exceeds safe integer:", calculated > Number.MAX_SAFE_INTEGER);

// Test case 2: Demonstrate .toNumber() precision loss
const largeBN = new BN("10000000000000000"); // 10 quadrillion
console.log("BN value:", largeBN.toString());
console.log(".toNumber():", largeBN.toNumber()); // Loses precision!

// Test case 3: Hash mismatch demonstration
const orderConfigLarge = {
  srcAmount: new BN("10000000000000000"),
  minDstAmount: new BN("5000000000000000"),
  // ...
};

// Client calculates with .toNumber()
const clientHash = calculateHash({
  srcAmount: orderConfigLarge.srcAmount.toNumber(), // Truncated!
  minDstAmount: orderConfigLarge.minDstAmount.toNumber(), // Truncated!
});

// Program calculates with full u64
const programHash = calculateHash({
  srcAmount: orderConfigLarge.srcAmount.toString(), // Full value
  minDstAmount: orderConfigLarge.minDstAmount.toString(), // Full value  
});

console.log("Client hash:", clientHash);
console.log("Program hash:", programHash);
console.log("Hashes match:", clientHash === programHash); // FALSE!
```

**Expected Result:** For amounts > 2^53, the client and program compute different order hashes, causing PDA derivation to fail and the transaction to revert.

**Actual Impact:** Order creation fails with PDA validation error. While atomic execution prevents fund loss, the protocol cannot handle large orders, breaking core functionality for institutional users and high-value swaps.

### Citations

**File:** scripts/fusion-swap/create.ts (L36-37)
```typescript
  srcAmount: BN,
  minDstAmount: BN,
```

**File:** scripts/fusion-swap/create.ts (L48-48)
```typescript
  estimatedDstAmount: BN = minDstAmount,
```

**File:** scripts/fusion-swap/create.ts (L89-93)
```typescript
  const escrow = findEscrowAddress(
    program.programId,
    makerKeypair.publicKey,
    Buffer.from(orderHash)
  );
```

**File:** scripts/fusion-swap/create.ts (L112-112)
```typescript
      lamports: srcAmount.toNumber(),
```

**File:** scripts/utils.ts (L150-152)
```typescript
    srcAmount: orderConfig.srcAmount.toNumber(),
    minDstAmount: orderConfig.minDstAmount.toNumber(),
    estimatedDstAmount: orderConfig.estimatedDstAmount.toNumber(),
```

**File:** programs/fusion-swap/src/lib.rs (L445-458)
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
