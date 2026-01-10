# Audit Report

## Title
Permanent DoS on Order Cancellation When Maker's Source ATA is Closed After Order Creation

## Summary
A maker who creates an order with non-native tokens and subsequently closes their source Associated Token Account (ATA) cannot cancel their order through the `cancel` instruction, resulting in a denial of service where their escrowed tokens remain locked until they recreate the ATA. This breaks the protocol's guarantee that users can always cancel their own orders.

## Finding Description
The `cancel` instruction in the fusion-swap program contains a logical inconsistency in how it handles the optional `maker_src_ata` account for non-native token orders. The vulnerability arises from the interaction between Anchor's optional account handling and the program's consistency checks.

The `cancel` function enforces a strict consistency check that requires for non-native tokens, the `maker_src_ata` must be provided (not None): [1](#0-0) 

The program then attempts to transfer tokens back to this account: [2](#0-1) 

However, the account constraint structure for the `Cancel` instruction lacks the `init_if_needed` attribute: [3](#0-2) 

The IDL confirms `maker_src_ata` is optional but has PDA constraints: [4](#0-3) 

**Attack Scenario:**
1. User creates an order with non-native tokens (e.g., USDC)
2. User's `maker_src_ata` exists at order creation time
3. User closes their `maker_src_ata` to reclaim ~0.00203 SOL rent (standard Solana practice)
4. User attempts to cancel the order

**The Catch-22:**
- **Scenario A**: Pass the ATA address → Anchor fails to deserialize the non-existent account (account not found error during account validation)
- **Scenario B**: Pass None (program ID) → Fails the consistency check with `InconsistentNativeSrcTrait` error

The test suite confirms Scenario B behavior but doesn't cover the scenario where the ATA exists at creation but is closed later: [5](#0-4) 

This violates the **Escrow Integrity** invariant: "Escrowed tokens must be securely locked and only released under valid conditions" - users cannot retrieve their legitimately escrowed tokens through the intended cancellation mechanism.

**Additional Impact:** The `cancel_by_resolver` function has the identical issue, meaning even after order expiration, resolvers also cannot cancel the order if the maker's ATA is closed: [6](#0-5) [7](#0-6) 

## Impact Explanation
**Medium Severity** - This creates a denial of service for individual users:

- Users cannot cancel orders containing their own escrowed tokens
- Tokens remain locked in escrow until workaround is applied
- Users must recreate their ATA (additional transaction fees and complexity) to unlock funds
- Even after order expiration, resolvers face the same issue and cannot cancel the order
- Users lose the ability to receive the cancellation premium that would otherwise be preserved

The impact is limited to Medium (not High) because:
- Funds are not permanently lost (workaround exists: recreate ATA then cancel)
- Only affects individual orders, not protocol-wide
- No token theft or unauthorized access occurs
- Workaround requires only ATA recreation (deterministic address)

## Likelihood Explanation
**Medium to High Likelihood** - This scenario is realistic and likely to occur:

1. **Common User Behavior**: Users frequently close ATAs to reclaim rent (~0.00203 SOL per ATA). This is especially common when:
   - Users finish trading a particular token
   - Users want to consolidate/cleanup accounts
   - Users transfer all tokens out and Solana wallets auto-close accounts
   - Users manage multiple token positions and close unused accounts

2. **No Warning**: The protocol doesn't warn users or prevent ATA closure for active orders

3. **Natural Workflow**: Users may create an order, later decide to close their position in that token entirely (closing the ATA), then remember they have an open order to cancel

4. **Solana Ecosystem**: The Solana ecosystem encourages closing unused accounts to reclaim rent, making this a natural and incentivized user action

## Recommendation
Add the `init_if_needed` attribute to the `maker_src_ata` account constraint in the `Cancel` struct:

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

This allows the ATA to be automatically recreated if it doesn't exist when the user attempts to cancel. The same fix should be applied to the `CancelByResolver` struct.

Alternatively, if automatic initialization is not desired, document this behavior clearly and provide client-side tooling to check and recreate ATAs before cancellation attempts.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import * as splToken from "@solana/spl-token";
import { expect } from "chai";

it("DoS: Cannot cancel order after closing maker's source ATA", async () => {
  // 1. Create order with non-native tokens
  const escrow = await state.createEscrow({
    escrowProgram: program,
    payer,
    provider,
  });
  
  const orderHash = calculateOrderHash(escrow.orderConfig);
  const makerSrcAta = state.alice.atas[state.tokens[0].toString()].address;
  
  // 2. Verify order was created successfully
  const escrowAccount = await splToken.getAccount(
    provider.connection, 
    escrow.ata
  );
  expect(escrowAccount.amount).to.equal(state.defaultSrcAmount.toNumber());
  
  // 3. Close the maker's source ATA (to reclaim rent)
  const makerSrcAtaInfo = await splToken.getAccount(
    provider.connection,
    makerSrcAta
  );
  
  // Burn all tokens first
  await splToken.burn(
    provider.connection,
    state.alice.keypair,
    makerSrcAta,
    state.tokens[0],
    state.alice.keypair,
    makerSrcAtaInfo.amount
  );
  
  // Close the account
  await splToken.closeAccount(
    provider.connection,
    state.alice.keypair,
    makerSrcAta,
    state.alice.keypair.publicKey,
    state.alice.keypair
  );
  
  // 4. Verify ATA is closed
  await expect(
    splToken.getAccount(provider.connection, makerSrcAta)
  ).to.be.rejectedWith(splToken.TokenAccountNotFoundError);
  
  // 5. Attempt to cancel - this will fail with DoS
  // Scenario A: Passing the ATA address fails with account deserialization error
  await expect(
    program.methods
      .cancel(Array.from(orderHash), false)
      .accountsPartial({
        maker: state.alice.keypair.publicKey,
        srcMint: state.tokens[0],
        escrow: escrow.escrow,
        srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
        makerSrcAta: makerSrcAta, // ATA doesn't exist
      })
      .signers([state.alice.keypair])
      .rpc()
  ).to.be.rejected; // Account not found error
  
  // Scenario B: Passing null fails with consistency check
  await expect(
    program.methods
      .cancel(Array.from(orderHash), false)
      .accountsPartial({
        maker: state.alice.keypair.publicKey,
        srcMint: state.tokens[0],
        escrow: escrow.escrow,
        srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
        makerSrcAta: null, // Passing None
      })
      .signers([state.alice.keypair])
      .rpc()
  ).to.be.rejectedWith("Error Code: InconsistentNativeSrcTrait");
  
  // Tokens remain locked in escrow
  const escrowAfter = await splToken.getAccount(
    provider.connection,
    escrow.ata
  );
  expect(escrowAfter.amount).to.equal(state.defaultSrcAmount.toNumber());
});
```

## Notes
This vulnerability affects both maker-initiated cancellation (`cancel`) and resolver-initiated cancellation (`cancel_by_resolver`), as both functions have identical consistency checks and account constraints. The only workaround is for the maker to recreate their ATA before attempting cancellation, which adds friction and transaction costs to the user experience. The protocol should either support automatic ATA initialization or clearly document this limitation to prevent user confusion and fund lockup scenarios.

### Citations

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

**File:** programs/fusion-swap/src/lib.rs (L360-362)
```rust
            order.src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );
```

**File:** programs/fusion-swap/src/lib.rs (L377-402)
```rust
        if !order.src_asset_is_native {
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
        };
```

**File:** programs/fusion-swap/src/lib.rs (L629-635)
```rust
    #[account(
        mut,
        associated_token::mint = src_mint,
        associated_token::authority = maker,
        associated_token::token_program = src_token_program,
    )]
    maker_src_ata: Option<InterfaceAccount<'info, TokenAccount>>,
```

**File:** idl/fusion_swap.json (L126-186)
```json
        {
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
