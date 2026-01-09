# Audit Report

## Title
Zero-Balance Escrow Account Cancellation Wastes Transaction Fees Due to Missing Balance Validation

## Summary
The cancel script does not validate the token balance of escrow accounts before executing cancellation transactions. When combined with a bug in the `fill()` function that fails to close zero-balance escrow accounts, users can waste transaction fees attempting to cancel already-filled orders by transferring zero tokens.

## Finding Description
This vulnerability involves two interconnected issues that violate the **Token Safety** and **Compute Limits** invariants:

**Root Cause - Incorrect Close Condition in fill():**
The `fill()` function contains a logic error in determining when to close escrow accounts. [1](#0-0) 

The condition checks `if ctx.accounts.escrow_src_ata.amount == amount` where `ctx.accounts.escrow_src_ata.amount` is the REMAINING balance after the token transfer, and `amount` is the quantity just transferred. For a complete order fill:
- Initial escrow balance: 100 tokens
- Transfer amount: 100 tokens  
- After transfer, remaining balance: 0 tokens
- Condition evaluates: `if 0 == 100` → FALSE
- Account is NOT closed despite zero balance

**Missing Balance Validation in Cancel Script:**
The cancel client script only verifies escrow account existence without checking the token balance. [2](#0-1) 

When the cancel instruction executes on a zero-balance escrow, it attempts to transfer zero tokens back to the maker for non-native assets. [3](#0-2) 

The transfer uses `ctx.accounts.escrow_src_ata.amount` which is zero. SPL Token's `transfer_checked` allows zero-amount transfers and succeeds as a no-op operation, but the user still pays full transaction fees for this meaningless operation.

## Impact Explanation
**Severity: Low**

This issue results in wasted transaction fees without direct fund loss:
- Users attempting to cancel already-filled orders pay ~5,000 lamports (~$0.001 at current SOL prices) per failed cancellation attempt
- No tokens are lost or stolen
- The escrow account is eventually closed, recovering rent lamports
- Impact is limited to poor user experience and minor economic inefficiency

The issue does not enable:
- Token theft or unauthorized transfers
- Protocol compromise or denial of service
- Access control bypasses
- Fund loss beyond transaction fees

## Likelihood Explanation
**Likelihood: Medium-High**

This scenario can occur in normal protocol operation:
1. A resolver completely fills an order
2. Due to the buggy condition, the escrow account remains open with zero balance
3. The order maker, unaware the order is filled, attempts cancellation
4. The cancel script succeeds in checking account existence and submits the transaction
5. Transaction executes with zero-token transfer, wasting fees

This does not require:
- Malicious actor coordination
- Privileged access or insider knowledge
- Complex exploit chains
- Precise timing attacks

The likelihood is increased by:
- Race conditions between fill and cancel operations
- Lack of off-chain order status monitoring
- Users attempting cancellation of stale orders

## Recommendation

**Fix 1: Correct the escrow close condition in fill()**
```rust
// Close escrow if all tokens are filled
if ctx.accounts.escrow_src_ata.amount == 0 {
    close_account(CpiContext::new_with_signer(
        // ... rest of close_account call
    ))?;
}
```

This ensures escrow accounts are properly closed when fully drained.

**Fix 2: Add balance validation in cancel script**
```typescript
const accountInfo = await splToken.getAccount(connection, escrowSrcAtaAddr);
if (accountInfo.amount === 0n) {
  console.error(`Order already filled - escrow has zero balance`);
  return;
}
console.log(`Order exists with balance: ${accountInfo.amount}`);
```

This prevents users from wasting fees on zero-balance cancellations.

## Proof of Concept

**Reproduction Steps:**

1. Create an order with 100 tokens
2. Have a resolver fill the entire order (100 tokens)
3. Observe that the escrow account remains open with zero balance due to incorrect close condition
4. Run the cancel script which will:
   - Pass the `getAccount` check (account exists)
   - Submit a cancel transaction
   - Execute `transfer_checked` with amount=0
   - Complete successfully but waste transaction fees
   - Finally close the account

**Expected vs Actual Behavior:**
- Expected: Escrow closed after full fill, cancel script fails with "account not found"
- Actual: Escrow remains open with zero balance, cancel script executes wasteful zero-transfer

**Test Scenario:**
```typescript
// After filling an order completely
const escrowInfo = await splToken.getAccount(connection, escrowAddress);
console.log(`Escrow balance after fill: ${escrowInfo.amount}`); // Should be 0

// Attempting cancellation
await cancel(connection, program, maker, srcMint, false, orderHash);
// Transaction succeeds but only transfers 0 tokens, wasting fees
```

## Notes
This finding addresses the exact scenario described in the security question. While classified as Low severity due to minimal financial impact (only wasted transaction fees), it represents a legitimate protocol inefficiency stemming from incorrect account lifecycle management. The root cause is the buggy close condition at line 266 of the fill() function, which should check for zero balance rather than comparing remaining balance with transferred amount.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L265-281)
```rust
        // Close escrow if all tokens are filled
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
        }
```

**File:** programs/fusion-swap/src/lib.rs (L301-327)
```rust
        // Return remaining src tokens back to maker
        if !order_src_asset_is_native {
            transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.src_token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.escrow_src_ata.to_account_info(),
                        mint: ctx.accounts.src_mint.to_account_info(),
                        to: ctx
                            .accounts
                            .maker_src_ata
                            .as_ref()
                            .ok_or(FusionError::MissingMakerSrcAta)?
                            .to_account_info(),
                        authority: ctx.accounts.escrow.to_account_info(),
                    },
                    &[&[
                        "escrow".as_bytes(),
                        ctx.accounts.maker.key().as_ref(),
                        &order_hash,
                        &[ctx.bumps.escrow],
                    ]],
                ),
                ctx.accounts.escrow_src_ata.amount,
                ctx.accounts.src_mint.decimals,
            )?;
        }
```

**File:** scripts/fusion-swap/cancel.ts (L78-98)
```typescript
  try {
    const escrowAddr = findEscrowAddress(
      fusionSwap.programId,
      makerKeypair.publicKey,
      orderHash
    );

    const escrowSrcAtaAddr = await splToken.getAssociatedTokenAddress(
      srcMint,
      escrowAddr,
      true
    );

    await splToken.getAccount(connection, escrowSrcAtaAddr);
    console.log(`Order exists`);
  } catch (e) {
    console.error(
      `Escrow with order hash = ${orderHash} and maker = ${makerKeypair.publicKey.toString()} does not exist`
    );
    return;
  }
```
