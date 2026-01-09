# Audit Report

## Title
Insufficient SOL Balance Check After Native SOL Wrapping Prevents Order Cancellation

## Summary
The `create()` function in `scripts/fusion-swap/create.ts` wraps native SOL without validating that the maker retains sufficient SOL balance to pay for future transaction fees, specifically for order cancellation. This can leave makers temporarily unable to cancel their orders until they add more SOL to their account.

## Finding Description

The vulnerability exists in the order creation flow when handling native SOL: [1](#0-0) 

When a maker creates an order to swap native SOL (wrapped to wSOL), the script transfers `srcAmount` lamports from the maker's account without checking if sufficient SOL remains for:
1. Completing the current transaction (rent for escrow ATA + transaction fees)
2. Paying transaction fees for future operations like cancellation

The create transaction costs include:
- **Escrow ATA rent**: ~2,039,280 lamports (0.00203928 SOL) [2](#0-1) 
- **Transaction fees**: ~5,000 lamports (0.000005 SOL) minimum
- **Total**: ~2,044,280 lamports (0.00204428 SOL)

Later, when the maker attempts to cancel the order: [3](#0-2) 

The cancel operation requires the maker to have SOL to pay transaction fees upfront. While the escrow closure returns rent to the maker: [4](#0-3) 

The maker needs SOL **before** the transaction executes to pay for the transaction fees themselves. If the maker has insufficient SOL, the cancel transaction fails, locking them out of canceling their own order.

**Example Scenario:**
1. Maker has 1.0025 SOL total
2. Creates order to swap 1.0 SOL (native)
3. Script wraps 1.0 SOL, leaving 0.0025 SOL
4. Transaction costs 0.00204428 SOL, leaving ~0.00045 SOL
5. Later, cancel transaction requires ~0.000005+ SOL
6. While maker has enough for a minimal cancel, any increase in compute costs or priority fees renders cancellation impossible

## Impact Explanation

**Severity: Low**

This is classified as Low severity because:
- **No permanent fund loss**: Tokens remain safely in escrow
- **Temporary denial of service**: Maker temporarily cannot cancel but funds are not lost
- **Workarounds exist**: Maker can add more SOL to account and then cancel
- **Order expiration**: Eventually, the order expires and can be closed by a resolver
- **Rent recovery**: When escrow is closed, maker receives back the rent-exempt balance

The issue affects user experience and control over their own orders but does not result in token theft, permanent loss, or protocol-level damage.

## Likelihood Explanation

**Likelihood: Medium**

This issue will occur whenever:
- A user creates a native SOL order AND
- Their total SOL balance is close to the order amount (within ~0.003 SOL margin) AND
- They attempt to cancel before the order is filled or expires

This is a realistic scenario for users who:
- Want to swap most of their SOL holdings
- Are operating on minimal balances
- Don't understand the fee structure

While not guaranteed to occur in every transaction, it's a common enough edge case that affects real users.

## Recommendation

Add a balance validation check in the `create.ts` script before wrapping native SOL:

```typescript
// After line 108 in create.ts
if (srcMint == splToken.NATIVE_MINT) {
  // Wrap SOL to wSOL
  const makerNativeAta = await splToken.getAssociatedTokenAddress(
    splToken.NATIVE_MINT,
    makerKeypair.publicKey
  );

  // NEW: Check maker has enough SOL for operation + future fees
  const makerBalance = await connection.getBalance(makerKeypair.publicKey);
  const escrowAtaRent = await connection.getMinimumBalanceForRentExemption(
    splToken.ACCOUNT_SIZE
  );
  const estimatedTxFee = 10000; // 0.00001 SOL buffer for transaction fees
  const minimumReserve = 5000; // 0.000005 SOL minimum for future cancel
  
  const totalRequired = srcAmount.toNumber() + escrowAtaRent + estimatedTxFee + minimumReserve;
  
  if (makerBalance < totalRequired) {
    throw new Error(
      `Insufficient SOL balance. Need ${totalRequired / 1e9} SOL but have ${makerBalance / 1e9} SOL. ` +
      `Please ensure you have at least ${(totalRequired - srcAmount.toNumber()) / 1e9} SOL extra for fees and future cancellation.`
    );
  }

  const transferIx = SystemProgram.transfer({
    fromPubkey: makerKeypair.publicKey,
    toPubkey: makerNativeAta,
    lamports: srcAmount.toNumber(),
  });
  tx.add(transferIx);

  tx.add(splToken.createSyncNativeInstruction(makerNativeAta));
}
```

This ensures makers retain sufficient SOL to cancel their orders later.

## Proof of Concept

**Reproduction Steps:**

1. Create a test maker account with exactly 1.0025 SOL
2. Attempt to create an order swapping 1.0 native SOL for another token
3. Order creation succeeds, but maker is left with ~0.00045 SOL
4. Attempt to cancel the order
5. If network fees increase or compute costs are higher than minimal, cancellation fails with "insufficient funds for transaction"

**Detailed Test Scenario:**

```typescript
// Initial state
// Maker account: 1.0025 SOL (1,002,500,000 lamports)
// Order amount: 1.0 SOL (1,000,000,000 lamports)

// After wrapping (lines 109-116 of create.ts):
// Maker main account: 0.0025 SOL (2,500,000 lamports)
// Maker wSOL ATA: 1.0 SOL (1,000,000,000 lamports)

// After create transaction:
// Transaction costs: ~2,044,280 lamports (escrow rent + fees)
// Maker remaining: ~455,720 lamports (0.00045572 SOL)
// Escrow: 1.0 wSOL

// When attempting cancel:
// Required: ~5,000+ lamports for transaction
// Available: ~455,720 lamports
// Result: Should succeed with minimal fees
// BUT: If fees increase due to priority fees or compute, may fail

// Edge case - if maker had exactly 1.00204428 SOL:
// After create: ~0 lamports remaining
// Cancel attempt: FAILS - insufficient funds for transaction
```

**Notes:**
- The exact point of failure depends on network congestion and priority fees
- Makers operating on very thin margins (< 0.001 SOL remaining) are at risk
- The issue is exacerbated during high network activity when transaction costs increase

### Citations

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

**File:** programs/fusion-swap/src/lib.rs (L329-342)
```rust
        close_account(CpiContext::new_with_signer(
            ctx.accounts.src_token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.escrow_src_ata.to_account_info(),
                destination: ctx.accounts.maker.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            &[&[
                "escrow".as_bytes(),
                ctx.accounts.maker.key().as_ref(),
                &order_hash,
                &[ctx.bumps.escrow],
            ]],
        ))
```

**File:** programs/fusion-swap/src/lib.rs (L469-476)
```rust
    #[account(
        init,
        payer = maker,
        associated_token::mint = src_mint,
        associated_token::authority = escrow,
        associated_token::token_program = src_token_program,
    )]
    escrow_src_ata: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** scripts/fusion-swap/cancel.ts (L45-62)
```typescript
  const cancelIx = await program.methods
    .cancel(orderHashBytes, srcAssetIsNative)
    .accountsPartial({
      maker: makerKeypair.publicKey,
      srcMint,
      escrow,
      escrowSrcAta,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
    })
    .signers([makerKeypair])
    .instruction();

  const tx = new Transaction().add(cancelIx);

  const signature = await sendAndConfirmTransaction(connection, tx, [
    makerKeypair,
  ]);
  console.log(`Transaction signature ${signature}`);
```
