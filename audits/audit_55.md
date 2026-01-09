# Audit Report

## Title
Permanent DoS on Order Cancellation When Maker's Source ATA is Closed After Order Creation

## Summary
A maker who creates an order with non-native tokens and subsequently closes their source Associated Token Account (ATA) cannot cancel their order through the `cancel` instruction, resulting in a denial of service where their escrowed tokens remain locked until they recreate the ATA. This breaks the protocol's guarantee that users can always cancel their own orders.

## Finding Description
The `cancel` instruction in the fusion-swap program contains a logical inconsistency in how it handles the optional `maker_src_ata` account for non-native token orders. The vulnerability arises from the interaction between Anchor's optional account handling and the program's consistency checks. [1](#0-0) 

The IDL defines `maker_src_ata` as optional with PDA constraints. However, the Rust implementation enforces a strict consistency check: [2](#0-1) 

This check requires that for non-native tokens (`order_src_asset_is_native = false`), the `maker_src_ata` must be provided (`is_none() = false`). The program then attempts to transfer tokens back to this account: [3](#0-2) 

The account constraint structure lacks the `init_if_needed` attribute: [4](#0-3) 

**Attack Scenario:**
1. User creates an order with non-native tokens (e.g., USDC)
2. User's `maker_src_ata` exists at order creation time
3. User closes their `maker_src_ata` (e.g., to reclaim ~0.00203 SOL rent)
4. User attempts to cancel the order

**The Catch-22:**
- **Scenario A**: Pass the ATA address → Anchor fails to deserialize the non-existent account (account not found error)
- **Scenario B**: Pass program ID (None) → Fails the consistency check with `InconsistentNativeSrcTrait` error [5](#0-4) 

The test suite confirms this behavior but doesn't cover the scenario where the ATA exists at creation but is closed later: [6](#0-5) 

This violates the **Escrow Integrity** invariant: "Escrowed tokens must be securely locked and only released under valid conditions" - users cannot retrieve their legitimately escrowed tokens through the intended cancellation mechanism.

## Impact Explanation
**Medium Severity** - This creates a denial of service for individual users:
- Users cannot cancel orders containing their own escrowed tokens
- Tokens remain locked in escrow until workaround is applied
- Users must recreate their ATA (additional transaction fees) to unlock funds
- Alternatively, users must wait for order expiration and rely on resolver cancellation (losing the cancellation premium)

The impact is limited to Medium (not High) because:
- Funds are not permanently lost (workaround exists)
- Only affects individual orders, not protocol-wide
- No token theft or unauthorized access occurs
- Workaround requires only ATA recreation

## Likelihood Explanation
**Medium to High Likelihood** - This scenario is realistic and likely to occur:

1. **Common User Behavior**: Users frequently close ATAs to reclaim rent (~0.00203 SOL per ATA). This is especially common when:
   - Users finish trading a particular token
   - Users want to consolidate/cleanup accounts
   - Users transfer all tokens out and Solana wallets auto-close accounts

2. **No Warning**: The protocol doesn't warn users or prevent ATA closure for active orders

3. **Natural Workflow**: Users may create an order, later decide to close their position in that token entirely (closing the ATA), then remember they have an open order to cancel

4. **Solana Ecosystem**: The Solana ecosystem encourages closing unused accounts to reclaim rent, making this a natural user action

## Recommendation
Add the `init_if_needed` constraint to `maker_src_ata` in the `Cancel` struct, similar to how `maker_dst_ata` is handled in the `Fill` struct:

```rust
/// Maker's ATA of src_mint
#[account(
    init_if_needed,
    payer = maker,
    mut,
    associated_token::mint = src_mint,
    associated_token::authority = maker,
    associated_token::token_program = src_token_program,
)]
maker_src_ata: Option<InterfaceAccount<'info, TokenAccount>>,
```

This allows the instruction to automatically create the ATA if it doesn't exist, with the maker paying for the creation. This ensures users can always cancel their orders regardless of ATA state.

**Alternative Solution**: Modify the logic to handle native token unwrapping when `maker_src_ata` doesn't exist for non-native orders, similar to how native tokens are already handled.

## Proof of Concept

**Steps to Reproduce:**

1. Create an order with non-native tokens (USDC):
```typescript
const orderConfig = {
  srcMint: USDC_MINT,
  srcAssetIsNative: false,
  srcAmount: new BN(100_000_000),
  // ... other config
};
await program.methods.create(orderConfig)
  .accounts({ /* accounts */ })
  .rpc();
```

2. Close the maker's source ATA:
```typescript
await splToken.closeAccount(
  connection,
  maker,
  makerSrcAta,
  maker.publicKey,
  maker
);
```

3. Attempt to cancel the order:
```typescript
// Scenario A: Pass ATA address (doesn't exist)
await program.methods.cancel(orderHash, false)
  .accountsPartial({
    maker: maker.publicKey,
    srcMint: USDC_MINT,
    escrow,
    escrowSrcAta,
    srcTokenProgram: TOKEN_PROGRAM_ID,
    // makerSrcAta will be auto-resolved to the ATA address
  })
  .signers([maker])
  .rpc();
// Result: Error - Account not found or cannot deserialize

// Scenario B: Pass null to indicate None
await program.methods.cancel(orderHash, false)
  .accountsPartial({
    maker: maker.publicKey,
    srcMint: USDC_MINT,
    escrow,
    escrowSrcAta,
    srcTokenProgram: TOKEN_PROGRAM_ID,
    makerSrcAta: null,
  })
  .signers([maker])
  .rpc();
// Result: Error Code: InconsistentNativeSrcTrait
```

4. **Workaround** (non-obvious to users): Recreate the ATA first:
```typescript
await splToken.createAssociatedTokenAccount(
  connection,
  maker,
  USDC_MINT,
  maker.publicKey
);
// Now cancellation works
```

This PoC demonstrates that normal cancellation is impossible once the ATA is closed, requiring users to discover and apply a non-obvious workaround.

## Notes
This vulnerability specifically affects non-native token orders where the maker closes their source ATA after order creation. Native SOL orders are unaffected as they use a different code path. The issue could impact user experience significantly as closing ATAs to reclaim rent is a common practice in the Solana ecosystem.

### Citations

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

**File:** programs/fusion-swap/src/lib.rs (L296-299)
```rust
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

**File:** programs/fusion-swap/src/lib.rs (L628-635)
```rust
    /// Maker's ATA of src_mint
    #[account(
        mut,
        associated_token::mint = src_mint,
        associated_token::authority = maker,
        associated_token::token_program = src_token_program,
    )]
    maker_src_ata: Option<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/fusion-swap/src/error.rs (L5-6)
```rust
    #[msg("Inconsistent native src trait")]
    InconsistentNativeSrcTrait,
```

**File:** tests/suits/fusion-swap.ts (L1777-1793)
```typescript
    it("Cancellation with spl tokens fails if maker-src-ata is absent", async () => {
      const orderHash = calculateOrderHash(state.escrows[0].orderConfig);

      await expect(
        program.methods
          .cancel(Array.from(orderHash), false)
          .accountsPartial({
            maker: state.alice.keypair.publicKey,
            srcMint: state.tokens[0],
            escrow: state.escrows[0].escrow,
            srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
            makerSrcAta: null,
          })
          .signers([state.alice.keypair])
          .rpc()
      ).to.be.rejectedWith("Error Code: InconsistentNativeSrcTrait");
    });
```
