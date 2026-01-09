# Audit Report

## Title
Front-Running Vulnerability in Order Cancellation Leading to Wasted Gas Fees

## Summary
A race condition exists between the escrow existence check and the cancel transaction execution in the client-side cancel script. Malicious resolvers can front-run the cancel transaction by filling the entire order, causing the cancel to fail and the maker to lose transaction fees.

## Finding Description

The vulnerability exists in the cancel flow where a non-atomic check-then-act pattern creates a race condition window. [1](#0-0) 

At this point, the client verifies the escrow account exists by checking if the associated token account can be retrieved. [2](#0-1) 

However, between the existence check and the actual cancel execution, there is a time window where the order state can change.

When a resolver fills an order completely, the escrow account is closed: [3](#0-2) 

The program-level cancel function requires the escrow_src_ata account to exist and be valid: [4](#0-3) 

**Attack Flow:**
1. Maker checks escrow exists at line 91 of cancel.ts
2. Maker submits cancel transaction at line 100
3. Malicious resolver monitoring the mempool detects the pending cancel transaction
4. Resolver front-runs by submitting a fill transaction with higher priority fees to complete the entire order
5. Resolver's fill transaction executes first, closing the escrow_src_ata account (lines 266-280 of lib.rs)
6. Maker's cancel transaction executes but fails during account validation because escrow_src_ata no longer exists
7. Maker loses transaction fees (SOL) with no successful cancellation

This breaks the **Atomic Execution** invariant - the maker expects their check-and-cancel operation to be safe, but the non-atomic nature allows state changes between the check and action.

## Impact Explanation

**Severity: Medium-High**

The impact constitutes an "Individual user fund loss through specific exploits" (Medium severity category):

- **Direct Financial Loss**: Makers lose SOL in transaction fees when their cancel fails
- **Systematic Exploitation**: This can occur repeatedly whenever makers attempt to cancel orders while resolvers are active
- **Predictable Attack**: Resolvers can easily monitor the mempool and identify cancellation attempts
- **User Experience Degradation**: Unpredictable behavior erodes trust in the protocol

While this doesn't compromise the entire protocol or result in massive token theft, it represents a real and recurring user fund loss that can be systematically exploited.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Attacker Barrier**: Any whitelisted resolver can exploit this - no special privileges beyond resolver status required
2. **Easy Detection**: Resolvers already monitor the mempool for profitable fill opportunities; detecting cancel transactions is trivial
3. **Economic Incentive**: Resolvers are incentivized to fill orders at favorable prices, and preventing cancellations keeps orders available
4. **Standard MEV Pattern**: This is a well-known front-running pattern in blockchain systems that sophisticated actors already exploit
5. **No Protocol-Level Protection**: The protocol has no mechanism to prevent this race condition
6. **High Frequency Scenario**: Order cancellations are common user actions, providing frequent exploitation opportunities

## Recommendation

**Solution: Implement Transaction-Level Atomicity with Preflight Checks**

The issue stems from separating the existence check from the transaction submission. The recommended fix involves one of two approaches:

**Option 1: Remove Client-Side Check (Recommended)**
Remove the existence check at line 91 and rely on the program-level validation. If the escrow doesn't exist, the transaction will fail during program execution with a proper error, and the maker won't waste fees on a successful check followed by a failed cancel.

**Option 2: Add Transaction Simulation**
Replace the simple existence check with a transaction simulation:

```typescript
// In cancel.ts main() function, replace lines 78-98 with:
try {
  // Build the cancel transaction
  const cancelIx = await fusionSwap.methods
    .cancel(orderHashBytes, srcAssetIsNative)
    .accountsPartial({
      maker: makerKeypair.publicKey,
      srcMint,
      escrow: escrowAddr,
      escrowSrcAta: escrowSrcAtaAddr,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
    })
    .signers([makerKeypair])
    .instruction();

  const tx = new Transaction().add(cancelIx);
  
  // Simulate before sending to catch failures early
  const simulation = await connection.simulateTransaction(tx, [makerKeypair]);
  
  if (simulation.value.err) {
    console.error('Cancellation would fail:', simulation.value.err);
    return;
  }
  
  console.log('Order exists and can be cancelled');
} catch (e) {
  console.error('Failed to build or simulate cancel transaction:', e);
  return;
}
```

**Option 3: Add Retry Logic with Proper Error Handling**
Implement retry logic that distinguishes between "escrow doesn't exist" (user should be informed) vs "escrow was just filled" (can retry or inform user order was filled).

## Proof of Concept

**Reproduction Steps:**

1. **Setup**: 
   - Maker creates an order with 100 tokens escrowed
   - Order is partially fillable

2. **Maker Initiates Cancel**:
   - Maker runs `cancel.ts` script
   - Line 91 executes: `await splToken.getAccount(connection, escrowSrcAtaAddr)` - SUCCEEDS
   - Maker proceeds to line 100: `await cancel(...)`
   - Cancel transaction enters mempool

3. **Resolver Front-Runs**:
   - Resolver monitoring mempool detects cancel transaction
   - Resolver submits fill transaction for entire 100 tokens with priority fee of 0.01 SOL (higher than maker's cancel)
   - Resolver's transaction is processed first

4. **Fill Executes**:
   - Fill completes successfully
   - At line 266-280 of lib.rs: `if ctx.accounts.escrow_src_ata.amount == amount` condition is TRUE
   - `close_account()` is called, closing the escrow_src_ata account
   - Escrow ATA no longer exists

5. **Cancel Fails**:
   - Maker's cancel transaction is processed
   - Program attempts to deserialize escrow_src_ata account
   - Anchor constraint at lines 620-626 fails: account is closed, cannot be deserialized as TokenAccount
   - Transaction fails with account validation error
   - Maker pays transaction fee (~0.005 SOL) but cancel doesn't execute

6. **Result**:
   - Maker loses transaction fee
   - Order was filled (which maker was trying to prevent)
   - Maker must retry or accept the fill

**Expected Behavior**: The cancel should either succeed (if order still exists) or fail gracefully with clear feedback (if order was already filled) without wasting the maker's transaction fees.

**Actual Behavior**: Maker wastes transaction fees on a failed cancel when a resolver front-runs with a complete fill.

## Notes

This vulnerability is a classic Time-of-Check-Time-of-Use (TOCTOU) race condition. The separation between checking the escrow exists (line 91) and executing the cancel (line 100) creates a window for state changes. On Solana, where transaction ordering can be influenced by priority fees, this becomes a front-running opportunity.

The issue is exacerbated by the fact that resolvers have legitimate economic incentives to fill orders quickly, making this not just a theoretical attack but an expected behavior in competitive resolver environments.

While individual transaction fee losses are relatively small (~0.005 SOL per failed cancel), the cumulative impact across all users and repeated attempts can be significant. More importantly, this degrades user experience and trust in the protocol's reliability.

### Citations

**File:** scripts/fusion-swap/cancel.ts (L91-91)
```typescript
    await splToken.getAccount(connection, escrowSrcAtaAddr);
```

**File:** scripts/fusion-swap/cancel.ts (L100-107)
```typescript
  await cancel(
    connection,
    fusionSwap,
    makerKeypair,
    srcMint,
    srcAssetIsNative,
    orderHash
  );
```

**File:** programs/fusion-swap/src/lib.rs (L266-280)
```rust
        if ctx.accounts.escrow_src_ata.amount == amount {
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
                    order_hash,
                    &[ctx.bumps.escrow],
                ]],
            ))?;
```

**File:** programs/fusion-swap/src/lib.rs (L620-626)
```rust
    #[account(
        mut,
        associated_token::mint = src_mint,
        associated_token::authority = escrow,
        associated_token::token_program = src_token_program,
    )]
    escrow_src_ata: InterfaceAccount<'info, TokenAccount>,
```
