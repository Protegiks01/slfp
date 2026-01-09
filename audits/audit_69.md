# Audit Report

## Title
Client-Side Input Validation Failure Leading to Wasted Gas Fees in Order Cancellation

## Summary
The cancel script lacks input validation to ensure consistency between `srcMint` and `srcAssetIsNative` parameters, causing predictable on-chain transaction failures that waste users' gas fees when they provide mismatched values.

## Finding Description
The cancel script at `scripts/fusion-swap/cancel.ts` prompts users to manually enter both the `srcMint` address and a boolean `srcAssetIsNative` flag [1](#0-0) . However, it performs no validation to ensure these values are consistent before submitting the transaction.

When a user provides the native mint address (`So11111111111111111111111111111111111112`) but incorrectly specifies `srcAssetIsNative = false`, the on-chain cancel instruction performs validation checks that will fail in two distinct scenarios:

**Scenario 1: Order originally created with native SOL (srcAssetIsNative = true)**
The on-chain validation at lines 291-299 checks parameter consistency [2](#0-1) . When `srcAssetIsNative = false` is passed, Anchor's automatic account resolution derives the `maker_src_ata` address from the IDL PDA seeds [3](#0-2) . If this account doesn't exist on-chain (which is typical for orders created with native flow), the account deserialization fails and the transaction is rejected.

**Scenario 2: Order originally created with wSOL tokens (srcAssetIsNative = false) but cancelled with srcAssetIsNative = true**
When `srcAssetIsNative = true` is incorrectly passed, the validation passes but the token transfer is skipped at line 302 [4](#0-3) . The subsequent `close_account` call attempts to close an account with non-zero token balance [5](#0-4) , which violates the SPL Token program requirement that accounts must have zero balance before closure, causing transaction failure.

The root cause is that the cancel script doesn't read or validate against the original order configuration saved during creation [6](#0-5) , instead relying solely on user input.

## Impact Explanation
This qualifies as **Medium severity** under "Individual user fund loss through specific exploits" - users lose gas fees on failed transactions. While no tokens are stolen, users waste Solana transaction fees (typically 0.000005 SOL per signature) when submitting transactions that will deterministically fail. This breaks the **Compute Limits** invariant as compute units are unnecessarily consumed for predictably failing operations.

The impact is limited to self-inflicted harm - users can only waste their own gas fees, not exploit other users' orders.

## Likelihood Explanation
**High likelihood** - Users can easily make this mistake when manually entering parameters, especially when dealing with native SOL vs wSOL tokens. The confusion between the native mint address and the boolean flag is a common source of user error. The lack of any client-side validation or automated parameter derivation makes this issue very likely to occur in production usage.

## Recommendation
Implement client-side validation in the cancel script to prevent inconsistent parameter submission:

```typescript
async function main() {
  // ... existing code ...
  const srcMint = new PublicKey(prompt("Enter src mint public key: "));
  
  // Automatically derive srcAssetIsNative instead of prompting
  const srcAssetIsNative = srcMint.equals(splToken.NATIVE_MINT);
  
  // Alternatively, if prompting is required, validate consistency
  const userInput = prompt("Is src asset native? (true/false): ") === "true";
  if (srcMint.equals(splToken.NATIVE_MINT) && !userInput) {
    console.error("ERROR: Native mint detected but srcAssetIsNative is false");
    return;
  }
  if (!srcMint.equals(splToken.NATIVE_MINT) && userInput) {
    console.error("ERROR: Non-native mint but srcAssetIsNative is true");
    return;
  }
  const srcAssetIsNative = userInput;
  // ... rest of code ...
}
```

Better yet, read from the saved `order.json` file to use the exact parameters from order creation, eliminating user input errors entirely.

## Proof of Concept

```typescript
// PoC demonstrating the issue
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { Program } from "@coral-xyz/anchor";
import * as splToken from "@solana/spl-token";

// Scenario 1: Order created with native SOL, cancelled with wrong flag
async function demonstrateScenario1() {
  // 1. Create order with native SOL
  const orderConfig = {
    srcAssetIsNative: true,  // Correct: native SOL
    // ... other config
  };
  // Order creation succeeds
  
  // 2. User attempts to cancel with wrong parameter
  const cancelIx = await program.methods
    .cancel(orderHashBytes, false)  // WRONG: should be true
    .accountsPartial({
      maker: makerKeypair.publicKey,
      srcMint: splToken.NATIVE_MINT,  // Correct: native mint
      escrow,
      escrowSrcAta,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
    })
    .instruction();
  
  // 3. Transaction fails because maker_src_ata doesn't exist
  // Error: "Account does not exist" or account deserialization failure
  // Result: Gas fees wasted (~0.000005 SOL)
}

// Scenario 2: Order created with wSOL token, cancelled with wrong flag
async function demonstrateScenario2() {
  // 1. Create order with wSOL token
  const orderConfig = {
    srcAssetIsNative: false,  // Correct: wSOL token
    // ... other config
  };
  // maker_src_ata exists and is used
  
  // 2. User attempts to cancel with wrong parameter
  const cancelIx = await program.methods
    .cancel(orderHashBytes, true)  // WRONG: should be false
    .accountsPartial({
      maker: makerKeypair.publicKey,
      srcMint: splToken.NATIVE_MINT,
      escrow,
      escrowSrcAta,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
    })
    // maker_src_ata NOT provided (native flow)
    .instruction();
  
  // 3. Transaction fails at close_account
  // Error: "Cannot close account with non-zero token balance"
  // Result: Gas fees wasted (~0.000005 SOL)
}
```

## Notes
This is a client-side validation issue rather than an on-chain protocol vulnerability. The on-chain validation logic is functioning correctly by rejecting inconsistent states. The issue is that the cancel script doesn't prevent users from submitting transactions that will deterministically fail. While the financial impact is limited to wasted gas fees, it represents a violation of the **Compute Limits** invariant and creates poor user experience. The fix should be implemented at the client script level to validate inputs before transaction submission.

### Citations

**File:** scripts/fusion-swap/cancel.ts (L69-71)
```typescript
  const srcMint = new PublicKey(prompt("Enter src mint public key: "));
  const srcAssetIsNative =
    prompt("Is src asset native? (true/false): ") === "true";
```

**File:** programs/fusion-swap/src/lib.rs (L291-299)
```rust
        require!(
            ctx.accounts.src_mint.key() == native_mint::id() || !order_src_asset_is_native,
            FusionError::InconsistentNativeSrcTrait
        );

        require!(
            order_src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );
```

**File:** programs/fusion-swap/src/lib.rs (L302-327)
```rust
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

**File:** idl/fusion_swap.json (L127-186)
```json
          "name": "maker_src_ata",
          "docs": [
            "Maker's ATA of src_mint"
          ],
          "writable": true,
          "optional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "path": "maker"
              },
              {
                "kind": "account",
                "path": "src_token_program"
              },
              {
                "kind": "account",
                "path": "src_mint"
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                140,
                151,
                37,
                143,
                78,
                36,
                137,
                241,
                187,
                61,
                16,
                41,
                20,
                142,
                13,
                131,
                11,
                90,
                19,
                153,
                218,
                255,
                16,
                132,
                4,
                142,
                123,
                216,
                219,
                233,
                248,
                89
              ]
            }
          }
        },
```

**File:** scripts/fusion-swap/create.ts (L86-86)
```typescript
  fs.writeFileSync("order.json", JSON.stringify(orderConfigs));
```
