# Audit Report

## Title
Asymmetric Native SOL Validation Allows DoS on Legitimate Order Fills

## Summary
The `create` function's validation logic for native SOL orders is asymmetric, allowing orders to be created with `dst_mint = native_mint` but `dst_asset_is_native = false`. This causes legitimate fill attempts to fail with `MissingMakerDstAta` error when resolvers reasonably assume native SOL transfers don't require an ATA, resulting in a DoS condition.

## Finding Description

The validation in the `create` function enforces only one direction of the native SOL constraint: [1](#0-0) 

This check validates: "If `dst_asset_is_native` is `true`, then `dst_mint` MUST be `native_mint`"

However, it does NOT enforce the reverse: "If `dst_mint` is `native_mint`, then `dst_asset_is_native` MUST be `true`"

This asymmetry allows creating orders where:
- `dst_mint = native_mint::id()` (the native SOL mint)
- `dst_asset_is_native = false` (treated as wrapped SOL token)

**Attack Scenario:**

1. An attacker (or confused user) creates an order with `dst_mint = native_mint` and `dst_asset_is_native = false`, which passes validation.

2. A legitimate resolver sees `dst_mint = native_mint` and reasonably assumes this is a native SOL order that uses direct transfers to `maker_receiver`.

3. The resolver calls `fill` without providing `maker_dst_ata` (passing `None`), expecting native SOL transfer logic.

4. In the `fill` function, the code checks `order.dst_asset_is_native` (which is `false`) and enters the token transfer branch: [2](#0-1) 

5. At the token transfer branch, the code attempts to access `maker_dst_ata` and throws `MissingMakerDstAta` when it's `None`: [3](#0-2) 

6. The error is defined as error code 6003: [4](#0-3) 

This exact scenario is demonstrated in the test suite: [5](#0-4) 

The test shows an escrow created with `dstMint: splToken.NATIVE_MINT` (implicitly with default `dstAssetIsNative: false`), and when filling with `makerDstAta: null`, the transaction correctly fails with `MissingMakerDstAta` error.

## Impact Explanation

**Severity: Medium**

This vulnerability causes a DoS condition affecting order fills:

1. **Failed Transactions**: Legitimate resolvers attempting to fill native mint orders will experience transaction failures, wasting compute units and transaction fees.

2. **Operational Confusion**: Resolvers must distinguish between:
   - True native SOL orders (`dst_asset_is_native = true`)
   - Wrapped SOL orders masquerading as native (`dst_mint = native_mint` but `dst_asset_is_native = false`)

3. **Delayed Order Execution**: Orders may remain unfilled longer than expected as resolvers encounter failures and must retry with correct account configuration.

4. **User Experience Degradation**: Order creators may unknowingly create confusing orders, and resolvers waste resources attempting to fill them.

While no direct fund loss occurs (all transactions are atomic and rollback on failure), the operational disruption qualifies as Medium severity under the DoS category: "DoS attacks affecting specific operations."

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to occur because:

1. **Easy to Trigger**: Any order creator can accidentally create such orders, especially when using default values in client libraries. The test utils show `dstAssetIsNative: false` as the default: [6](#0-5) 

2. **Reasonable Assumption**: Resolvers seeing `dst_mint = native_mint` will reasonably assume native SOL transfer logic applies, leading them to omit `maker_dst_ata`.

3. **No Visual Indicator**: The fill script doesn't check the `dst_asset_is_native` flag before constructing accounts: [7](#0-6) 

The script uses `accountsPartial`, meaning it relies on manual account provision without programmatic checks for the native flag.

4. **Already Demonstrated**: The existence of a specific test case for this scenario indicates it's a known edge case that can occur in practice.

## Recommendation

Enforce bidirectional validation to ensure `dst_mint` and `dst_asset_is_native` are consistent:

```rust
require!(
    (ctx.accounts.dst_mint.key() == native_mint::id()) == order.dst_asset_is_native,
    FusionError::InconsistentNativeDstTrait
);
```

This ensures:
- If `dst_mint` is `native_mint`, then `dst_asset_is_native` MUST be `true`
- If `dst_asset_is_native` is `true`, then `dst_mint` MUST be `native_mint`

Apply the same fix to the source asset validation at line 51-54:

```rust
require!(
    (ctx.accounts.src_mint.key() == native_mint::id()) == order.src_asset_is_native,
    FusionError::InconsistentNativeSrcTrait
);
```

## Proof of Concept

The vulnerability is already demonstrated in the existing test suite. To reproduce:

1. Create an order with:
   ```typescript
   {
     dstMint: splToken.NATIVE_MINT,
     dstAssetIsNative: false  // Inconsistent configuration
   }
   ```

2. Attempt to fill the order without providing `maker_dst_ata`:
   ```typescript
   await program.methods
     .fill(order, amount)
     .accounts({
       // ... other accounts
       makerDstAta: null  // Resolver assumes native transfer
     })
     .rpc()
   ```

3. The transaction fails with error code 6003: `MissingMakerDstAta`

The exact reproduction is shown in the test case: [5](#0-4) 

This test explicitly creates the problematic configuration and demonstrates the error, confirming the vulnerability exists in production code.

**Notes**

The protocol intentionally supports both native SOL (unwrapped) and wrapped SOL (wSOL as SPL token) as valid assets. However, the validation logic fails to prevent ambiguous configurations where the destination mint is the native mint but the `dst_asset_is_native` flag is set to `false`. This creates unnecessary confusion and operational failures for resolvers who must correctly identify which transfer mechanism to use based on both the mint address AND the boolean flag, rather than relying on the mint address alone as a clear indicator.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L56-59)
```rust
        require!(
            ctx.accounts.dst_mint.key() == native_mint::id() || !order.dst_asset_is_native,
            FusionError::InconsistentNativeDstTrait
        );
```

**File:** programs/fusion-swap/src/lib.rs (L202-228)
```rust
        let mut params = if order.dst_asset_is_native {
            UniTransferParams::NativeTransfer {
                from: ctx.accounts.taker.to_account_info(),
                to: ctx.accounts.maker_receiver.to_account_info(),
                amount: maker_dst_amount,
                program: ctx.accounts.system_program.clone(),
            }
        } else {
            UniTransferParams::TokenTransfer {
                from: ctx
                    .accounts
                    .taker_dst_ata
                    .as_ref()
                    .ok_or(FusionError::MissingTakerDstAta)?
                    .to_account_info(),
                authority: ctx.accounts.taker.to_account_info(),
                to: ctx
                    .accounts
                    .maker_dst_ata
                    .as_ref()
                    .ok_or(FusionError::MissingMakerDstAta)?
                    .to_account_info(),
                mint: *ctx.accounts.dst_mint.clone(),
                amount: maker_dst_amount,
                program: ctx.accounts.dst_token_program.clone(),
            }
        };
```

**File:** programs/fusion-swap/src/error.rs (L11-12)
```rust
    #[msg("Missing maker dst ata")]
    MissingMakerDstAta,
```

**File:** tests/suits/fusion-swap.ts (L2069-2094)
```typescript
    it("Fails to execute the trade if maker_dst_acc is missing", async () => {
      const escrow = await state.createEscrow({
        escrowProgram: program,
        payer,
        provider,
        orderConfig: {
          dstMint: splToken.NATIVE_MINT,
        },
      });

      await expect(
        program.methods
          .fill(escrow.reducedOrderConfig, state.defaultSrcAmount)
          .accounts(
            state.buildAccountsDataForFill({
              escrow: escrow.escrow,
              escrowSrcAta: escrow.ata,
              dstMint: splToken.NATIVE_MINT,
              makerDstAta: null,
              takerDstAta:
                state.bob.atas[splToken.NATIVE_MINT.toString()].address,
            })
          )
          .signers([state.bob.keypair])
          .rpc()
      ).to.be.rejectedWith("Error Code: MissingMakerDstAta");
```

**File:** tests/utils/utils.ts (L395-396)
```typescript
      srcAssetIsNative: false,
      dstAssetIsNative: false,
```

**File:** scripts/fusion-swap/fill.ts (L67-85)
```typescript
  const fillIx = await program.methods
    .fill(reducedOrderConfig, new BN(amount * Math.pow(10, srcMintDecimals)))
    .accountsPartial({
      taker: takerKeypair.publicKey,
      resolverAccess,
      maker,
      makerReceiver: orderConfig.receiver,
      srcMint: orderConfig.srcMint,
      dstMint: orderConfig.dstMint,
      escrow,
      escrowSrcAta,
      takerSrcAta,
      protocolDstAcc: orderConfig.fee.protocolDstAcc,
      integratorDstAcc: orderConfig.fee.integratorDstAcc,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
      dstTokenProgram: splToken.TOKEN_PROGRAM_ID,
    })
    .signers([takerKeypair])
    .instruction();
```
