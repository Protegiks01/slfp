# Audit Report

## Title
Incomplete Type Reconstruction in Fill Script Causes Order Hash Mismatch and Transaction Failure

## Summary
The `fill.ts` script fails to properly reconstruct `BN` and `PublicKey` objects from the saved `order.json` file, leading to runtime errors and transaction failures when attempting to fill orders created via the `create.ts` script.

## Finding Description

When an order is created using `create.ts`, the order configuration containing `BN` (BigNumber) and `PublicKey` objects is serialized to JSON and saved to `order.json`. [1](#0-0) 

The `BN` and `PublicKey` classes have `toJSON()` methods that convert them to hex strings and base58 strings respectively during JSON serialization. However, when the order configuration is loaded back in `fill.ts`, only a subset of these serialized values are properly reconstructed back to their respective object types. [2](#0-1) 

Specifically, the following fields inside the `fee` object are NOT reconstructed:
- `fee.maxCancellationPremium` (remains a hex string instead of `BN`)
- `fee.protocolDstAcc` (remains a base58 string instead of `PublicKey`, if not null)
- `fee.integratorDstAcc` (remains a base58 string instead of `PublicKey`, if not null)

When `calculateOrderHash()` is called with this malformed configuration, it attempts to call `.toBuffer()` on the string values of `protocolDstAcc` and `integratorDstAcc`, which causes a runtime error since strings don't have a `.toBuffer()` method. [3](#0-2) 

Even when these fields are null (as in the default configuration), the `maxCancellationPremium` issue persists, potentially causing incorrect borsh serialization at line 183.

## Impact Explanation

**Severity: Medium (Operational Impact, Not Security Critical)**

This issue breaks the intended workflow where users create orders and save them to JSON files for later filling. While this is a HIGH severity bug from an operational perspective, it is **Medium severity from a security perspective** because:

1. **No Fund Loss**: The script fails with a runtime error BEFORE any transaction is sent to the chain, so no funds are at risk
2. **No Unauthorized Access**: The bug doesn't bypass any access controls or allow unauthorized operations
3. **No Protocol Invariant Violation**: This is a client-side bug that doesn't affect the on-chain protocol security
4. **Detectable Failure**: Users will immediately see the error and know the operation failed

The impact is limited to:
- Broken user workflow when using saved order files
- Inability to use the `order.json` file created by `create.ts` in `fill.ts`
- Poor user experience requiring manual parameter re-entry

## Likelihood Explanation

**Likelihood: High**

This bug will occur in 100% of cases where a user:
1. Creates an order using `create.ts` 
2. Saves the order configuration to `order.json`
3. Attempts to use that saved file with `fill.ts`

The bug is deterministic and unavoidable in the current implementation. However, the impact is limited because:
- The error occurs immediately at script execution time
- No on-chain transaction is attempted with incorrect data
- Users can work around this by manually entering order parameters

## Recommendation

Reconstruct ALL object types when loading the order configuration in `fill.ts`, not just the top-level fields:

```typescript
const orderConfig = {
  ...orderConfigs.full,
  srcAmount: new BN(orderConfigs.full.srcAmount, "hex"),
  minDstAmount: new BN(orderConfigs.full.minDstAmount, "hex"),
  estimatedDstAmount: new BN(orderConfigs.full.estimatedDstAmount, "hex"),
  srcMint: new PublicKey(orderConfigs.full.srcMint),
  dstMint: new PublicKey(orderConfigs.full.dstMint),
  receiver: new PublicKey(orderConfigs.full.receiver),
  fee: {
    ...orderConfigs.full.fee,
    maxCancellationPremium: new BN(orderConfigs.full.fee.maxCancellationPremium, "hex"),
    protocolDstAcc: orderConfigs.full.fee.protocolDstAcc 
      ? new PublicKey(orderConfigs.full.fee.protocolDstAcc) 
      : null,
    integratorDstAcc: orderConfigs.full.fee.integratorDstAcc 
      ? new PublicKey(orderConfigs.full.fee.integratorDstAcc) 
      : null,
  }
};

const reducedOrderConfig = {
  ...orderConfigs.reduced,
  srcAmount: new BN(orderConfigs.reduced.srcAmount, "hex"),
  minDstAmount: new BN(orderConfigs.reduced.minDstAmount, "hex"),
  estimatedDstAmount: new BN(orderConfigs.reduced.estimatedDstAmount, "hex"),
  fee: {
    ...orderConfigs.reduced.fee,
    maxCancellationPremium: new BN(orderConfigs.reduced.fee.maxCancellationPremium, "hex"),
  }
};
```

## Proof of Concept

**Reproduction Steps:**

1. Run `create.ts` with any valid parameters to create an order
2. Observe that `order.json` is created with serialized BN and PublicKey values
3. Run `fill.ts` and point it to the saved `order.json` file
4. Observe runtime error when `calculateOrderHash()` attempts to call `.toBuffer()` on string values

**Example Error:**
```
TypeError: orderConfig.fee.protocolDstAcc.toBuffer is not a function
    at calculateOrderHash (utils.ts:176)
```

Or if `protocolDstAcc` is null:
```
Error in borsh serialization due to incorrect type for maxCancellationPremium
```

**Note**: This is a client-side operational bug, not an on-chain security vulnerability. No funds are at risk as the error occurs before any blockchain transaction is submitted.

### Citations

**File:** scripts/fusion-swap/create.ts (L81-86)
```typescript
  const orderConfigs = {
    full: orderConfig,
    reduced: reducedOrderConfig,
  };

  fs.writeFileSync("order.json", JSON.stringify(orderConfigs));
```

**File:** scripts/fusion-swap/fill.ts (L100-116)
```typescript
  const orderConfigs = JSON.parse(fs.readFileSync(orderFilePath));

  const orderConfig = {
    ...orderConfigs.full,
    srcAmount: new BN(orderConfigs.full.srcAmount, "hex"),
    minDstAmount: new BN(orderConfigs.full.minDstAmount, "hex"),
    estimatedDstAmount: new BN(orderConfigs.full.estimatedDstAmount, "hex"),
    srcMint: new PublicKey(orderConfigs.full.srcMint),
    dstMint: new PublicKey(orderConfigs.full.dstMint),
    receiver: new PublicKey(orderConfigs.full.receiver),
  };
  const reducedOrderConfig = {
    ...orderConfigs.reduced,
    srcAmount: new BN(orderConfigs.reduced.srcAmount, "hex"),
    minDstAmount: new BN(orderConfigs.reduced.minDstAmount, "hex"),
    estimatedDstAmount: new BN(orderConfigs.reduced.estimatedDstAmount, "hex"),
  };
```

**File:** scripts/utils.ts (L147-183)
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
```
