# Audit Report

## Title
Temporary DoS on Order Cancellation When Maker's Source ATA is Closed After Order Creation

## Summary
Users who create orders with non-native tokens and subsequently close their source Associated Token Account (ATA) cannot cancel their orders through the `cancel` instruction, resulting in a temporary denial of service where escrowed tokens remain locked until they recreate the ATA. This breaks the protocol's guarantee that users can always cancel their own orders.

## Finding Description
The `cancel` instruction in the fusion-swap program contains a design flaw in how it handles the optional `maker_src_ata` account for non-native token orders. The vulnerability arises from the interaction between Anchor's optional account handling and the program's consistency checks.

The `cancel` function enforces a strict consistency check that requires for non-native tokens, the `maker_src_ata` must be provided (not None): [1](#0-0) 

The program then attempts to transfer tokens back to this account: [2](#0-1) 

However, the account constraint structure for the `Cancel` instruction lacks the `init_if_needed` attribute: [3](#0-2) 

The IDL confirms `maker_src_ata` is optional but has PDA constraints without initialization support: [4](#0-3) 

**The Catch-22 Scenario:**
1. User creates an order with non-native tokens (e.g., USDC) - maker_src_ata exists
2. User closes their maker_src_ata to reclaim ~0.00203 SOL rent (standard Solana practice)
3. User attempts to cancel the order:
   - **Scenario A**: Pass the ATA address → Anchor fails to deserialize the non-existent account (account validation fails)
   - **Scenario B**: Pass None (program ID) → Fails the consistency check with `InconsistentNativeSrcTrait` error

The test suite confirms Scenario B behavior but doesn't cover the scenario where the ATA exists at creation but is closed later: [5](#0-4) 

This violates the protocol invariant that users can always cancel their own orders.

**Additional Impact:** The `cancel_by_resolver` function has the identical issue: [6](#0-5) [7](#0-6) 

Even after order expiration, resolvers cannot cancel orders if the maker's ATA is closed, preventing recovery of the cancellation premium.

## Impact Explanation
**Medium Severity** - This creates a temporary denial of service for individual users:

- Users cannot cancel orders containing their own escrowed tokens through the intended mechanism
- Tokens remain locked in escrow until the workaround is applied (recreate ATA, then cancel)
- Users must pay additional transaction fees (~0.000005 SOL) and re-deposit rent (~0.00203 SOL, though reclaimable) to unlock funds
- Even after order expiration, resolvers face the same issue and cannot claim the cancellation premium
- Violates the protocol guarantee that users can always cancel their own orders

The impact is limited to Medium (not High) because:
- Funds are not permanently lost - a workaround exists (recreate ATA then cancel)
- Only affects individual orders, not protocol-wide operations
- No token theft or unauthorized access occurs
- The ATA address is deterministic and can always be recreated
- Workaround requires only a single additional transaction

## Likelihood Explanation
**Medium to High Likelihood** - This scenario is realistic and likely to occur:

1. **Common User Behavior**: Users frequently close ATAs to reclaim rent (~0.00203 SOL per ATA). This is especially common when:
   - Users finish trading a particular token
   - Users consolidate or cleanup their accounts
   - Wallets auto-close accounts when all tokens are transferred out
   - Users manage multiple token positions and close unused accounts

2. **No Warning or Prevention**: The protocol doesn't warn users or prevent ATA closure for active orders

3. **Natural Workflow**: Users may create an order, later decide to close their position in that token entirely (closing the ATA), then remember they have an open order to cancel

4. **Solana Ecosystem Pattern**: The Solana ecosystem encourages closing unused accounts to reclaim rent, making this a natural and economically incentivized action

## Recommendation
Add `init_if_needed` constraint to `maker_src_ata` in both `Cancel` and `CancelByResolver` structs:

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

For `CancelByResolver`, the `payer` should be the `resolver` account since the maker is not a signer.

Alternatively, modify the logic to allow cancellation without the maker_src_ata by transferring tokens to a different designated account or holding them for later claim.

## Proof of Concept
Add this test to `tests/suits/fusion-swap.ts` after the existing cancel tests:

```typescript
it("Cancel fails when maker closes their source ATA after order creation", async () => {
  // Create an order with SPL tokens
  const orderConfig = state.orderConfig({
    srcMint: state.tokens[0],
    srcAssetIsNative: false,
    srcAmount: new anchor.BN(10000),
    expirationTime: 0xffffffff,
  });

  const [escrow] = anchor.web3.PublicKey.findProgramAddressSync(
    [
      anchor.utils.bytes.utf8.encode("escrow"),
      state.alice.keypair.publicKey.toBuffer(),
      calculateOrderHash(orderConfig),
    ],
    program.programId
  );

  // Create the order
  await program.methods
    .create(orderConfig as ReducedOrderConfig)
    .accountsPartial({
      maker: state.alice.keypair.publicKey,
      makerReceiver: orderConfig.receiver,
      srcMint: state.tokens[0],
      dstMint: state.tokens[1],
      protocolDstAcc: null,
      integratorDstAcc: null,
      escrow,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
      makerSrcAta: state.alice.atas[state.tokens[0].toString()].address,
    })
    .signers([state.alice.keypair])
    .rpc();

  // Close the maker's source ATA to reclaim rent
  const makerSrcAtaInfo = await splToken.getAccount(
    provider.connection,
    state.alice.atas[state.tokens[0].toString()].address
  );
  
  await splToken.burn(
    provider.connection,
    state.alice.keypair,
    state.alice.atas[state.tokens[0].toString()].address,
    state.tokens[0],
    state.alice.keypair,
    makerSrcAtaInfo.amount,
    []
  );
  
  await splToken.closeAccount(
    provider.connection,
    state.alice.keypair,
    state.alice.atas[state.tokens[0].toString()].address,
    state.alice.keypair.publicKey,
    state.alice.keypair,
    []
  );

  const orderHash = calculateOrderHash(orderConfig);

  // Scenario A: Passing the ATA address fails with account not found
  await expect(
    program.methods
      .cancel(Array.from(orderHash), false)
      .accountsPartial({
        maker: state.alice.keypair.publicKey,
        srcMint: state.tokens[0],
        escrow: escrow,
        srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
        makerSrcAta: state.alice.atas[state.tokens[0].toString()].address,
      })
      .signers([state.alice.keypair])
      .rpc()
  ).to.be.rejected; // Anchor account validation fails

  // Scenario B: Passing null fails with InconsistentNativeSrcTrait
  await expect(
    program.methods
      .cancel(Array.from(orderHash), false)
      .accountsPartial({
        maker: state.alice.keypair.publicKey,
        srcMint: state.tokens[0],
        escrow: escrow,
        srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
        makerSrcAta: null,
      })
      .signers([state.alice.keypair])
      .rpc()
  ).to.be.rejectedWith("Error Code: InconsistentNativeSrcTrait");
});
```

## Notes
This vulnerability affects all orders created with non-native tokens where users close their source ATA after creation. While the workaround (recreating the ATA) is straightforward, it imposes unexpected costs and friction on users who are following standard Solana practices of closing unused accounts. The protocol should handle this scenario gracefully, either by initializing the ATA if needed during cancellation or by providing an alternative cancellation mechanism that doesn't require the maker's source ATA to exist.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L296-299)
```rust
        require!(
            order_src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );
```

**File:** programs/fusion-swap/src/lib.rs (L302-326)
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
```

**File:** programs/fusion-swap/src/lib.rs (L359-362)
```rust
        require!(
            order.src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );
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

**File:** programs/fusion-swap/src/lib.rs (L696-703)
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
