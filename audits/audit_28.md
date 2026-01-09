# Audit Report

## Title
Missing Native ATA Creation Causes Transaction Failure for SOL-Based Order Creation

## Summary
The `create()` function in `scripts/fusion-swap/create.ts` fails to create the maker's native SOL Associated Token Account (ATA) before attempting to wrap SOL. This causes transaction failures for any maker who doesn't already have a native SOL ATA when trying to create orders with NATIVE_MINT as the source token.

## Finding Description

The vulnerability exists in the SOL wrapping logic of the order creation script. [1](#0-0) 

The code only computes the ATA address using `getAssociatedTokenAddress()` but never creates the account if it doesn't exist. [2](#0-1) 

When the transaction executes:
1. `SystemProgram.transfer()` sends SOL to the computed ATA address, creating a system-owned account at that address [3](#0-2) 
2. `createSyncNativeInstruction()` attempts to sync native tokens, but fails because the account is owned by System Program, not Token Program [4](#0-3) 

This breaks the **Token Safety** invariant: "Token transfers must be properly authorized and accounted for" - the script doesn't properly prepare token accounts before attempting token operations.

In contrast, the test suite correctly creates ATAs before wrapping by using `createAssociatedTokenAccount()`. [5](#0-4) 

The test's `prepareNativeTokens` function assumes the ATA already exists because it was created upfront. [6](#0-5) 

## Impact Explanation

**High Severity** - This constitutes partial protocol disruption affecting multiple users:

- Any maker without an existing native SOL ATA cannot create orders with NATIVE_MINT as the source token
- First-time protocol users are disproportionately affected
- The transaction fails with unclear error messages, degrading user experience
- This prevents legitimate protocol usage and order creation, a core protocol feature

The Solana program itself correctly handles native transfers when `src_asset_is_native` is true by transferring directly from maker to escrow. [7](#0-6) 

However, the script's default behavior (`srcAssetIsNative: false`) attempts to wrap SOL first, triggering this bug. [8](#0-7) 

## Likelihood Explanation

**High Likelihood** - This will occur whenever:
- A maker without a pre-existing native SOL ATA attempts to create an order with NATIVE_MINT as srcMint
- The default `srcAssetIsNative: false` parameter is used
- Common scenario for new users or users trading wSOL for the first time

## Recommendation

Add an instruction to create the ATA if it doesn't exist before attempting the SOL transfer. Use `createAssociatedTokenAccountIdempotentInstruction` which safely handles both cases (account exists or doesn't exist):

```typescript
if (srcMint == splToken.NATIVE_MINT) {
  // Wrap SOL to wSOL
  const makerNativeAta = await splToken.getAssociatedTokenAddress(
    splToken.NATIVE_MINT,
    makerKeypair.publicKey
  );

  // Create ATA if it doesn't exist (idempotent)
  const createAtaIx = splToken.createAssociatedTokenAccountIdempotentInstruction(
    makerKeypair.publicKey, // payer
    makerNativeAta,
    makerKeypair.publicKey, // owner
    splToken.NATIVE_MINT
  );
  tx.add(createAtaIx);

  const transferIx = SystemProgram.transfer({
    fromPubkey: makerKeypair.publicKey,
    toPubkey: makerNativeAta,
    lamports: srcAmount.toNumber(),
  });
  tx.add(transferIx);

  tx.add(splToken.createSyncNativeInstruction(makerNativeAta));
}
```

## Proof of Concept

**Reproduction Steps:**

1. Create a fresh Solana keypair (maker) with no existing native SOL ATA
2. Fund the keypair with sufficient SOL for transaction fees + order amount
3. Run the create script with:
   - `srcMint = NATIVE_MINT` (So11111111111111111111111111111111111111112)
   - `srcAmount = 1000000000` (1 SOL)
   - Any valid `dstMint`
4. Observe transaction failure at the `createSyncNativeInstruction` step

**Expected Result:** Transaction succeeds, order created with wrapped SOL

**Actual Result:** Transaction fails because `createSyncNativeInstruction` expects a token account but finds a system account

**Error:** The sync native instruction will fail with a program error indicating the account is not owned by Token Program.

## Notes

This vulnerability only affects the client-side script, not the on-chain program logic. The Solana program correctly handles both native SOL transfers (`src_asset_is_native = true`) and wrapped SOL transfers (`src_asset_is_native = false`). The issue lies in the script's preparation of wrapped SOL tokens before invoking the program.

### Citations

**File:** scripts/fusion-swap/create.ts (L43-44)
```typescript
  srcAssetIsNative: boolean = false,
  dstAssetIsNative: boolean = false,
```

**File:** scripts/fusion-swap/create.ts (L102-117)
```typescript
  if (srcMint == splToken.NATIVE_MINT) {
    // Wrap SOL to wSOL
    const makerNativeAta = await splToken.getAssociatedTokenAddress(
      splToken.NATIVE_MINT,
      makerKeypair.publicKey
    );

    const transferIx = SystemProgram.transfer({
      fromPubkey: makerKeypair.publicKey,
      toPubkey: makerNativeAta,
      lamports: srcAmount.toNumber(),
    });
    tx.add(transferIx);

    tx.add(splToken.createSyncNativeInstruction(makerNativeAta));
  }
```

**File:** tests/utils/utils.ts (L555-561)
```typescript
      const pubkey = await tokenLibrary.createAssociatedTokenAccount(
        connection,
        payer,
        token,
        keypair.publicKey,
        ...extraArgs
      );
```

**File:** tests/utils/utils.ts (L617-648)
```typescript
async function prepareNativeTokens({
  amount,
  user,
  provider,
  payer,
}: {
  amount: anchor.BN;
  user: User;
  provider: anchor.AnchorProvider | BanksClient;
  payer: anchor.web3.Keypair;
}) {
  const ata = user.atas[splToken.NATIVE_MINT.toString()].address;
  const wrapTransaction = new Transaction().add(
    anchor.web3.SystemProgram.transfer({
      fromPubkey: user.keypair.publicKey,
      toPubkey: ata,
      lamports: amount.toNumber(),
    }),
    splToken.createSyncNativeInstruction(ata)
  );
  if (provider instanceof anchor.AnchorProvider) {
    await sendAndConfirmTransaction(provider.connection, wrapTransaction, [
      payer,
      user.keypair,
    ]);
  } else {
    wrapTransaction.recentBlockhash = (await provider.getLatestBlockhash())[0];
    wrapTransaction.sign(payer);
    wrapTransaction.sign(user.keypair);
    await provider.processTransaction(wrapTransaction);
  }
}
```

**File:** programs/fusion-swap/src/lib.rs (L101-115)
```rust
        if order.src_asset_is_native {
            // Wrap SOL to wSOL
            uni_transfer(&UniTransferParams::NativeTransfer {
                from: ctx.accounts.maker.to_account_info(),
                to: ctx.accounts.escrow_src_ata.to_account_info(),
                amount: order.src_amount,
                program: ctx.accounts.system_program.clone(),
            })?;

            anchor_spl::token::sync_native(CpiContext::new(
                ctx.accounts.src_token_program.to_account_info(),
                anchor_spl::token::SyncNative {
                    account: ctx.accounts.escrow_src_ata.to_account_info(),
                },
            ))
```
