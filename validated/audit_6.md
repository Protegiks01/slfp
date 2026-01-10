# Audit Report

## Title
Partially Filled Native SOL Orders Cannot Be Cancelled With Original Parameters, Causing Fund Recovery Issues

## Summary
When a native SOL order is partially filled, the remaining wrapped SOL tokens in escrow cannot be cancelled using the original `src_asset_is_native=true` parameter. The cancel operation fails because it attempts to close a token account with a non-zero balance, violating SPL Token program constraints. Users must use unexpected parameters to recover funds.

## Finding Description

This vulnerability stems from a logic mismatch between order creation and cancellation flows for native SOL orders.

**Order Creation with Native SOL:**
When creating an order with `src_asset_is_native=true`, the protocol enforces that `maker_src_ata` must be `None` [1](#0-0) , and native SOL is wrapped to wSOL through a native transfer followed by `sync_native` [2](#0-1) .

**Partial Fill Behavior:**
During partial fills, tokens are transferred from escrow to the taker [3](#0-2) . The escrow account remains open if not fully filled, as shown by the conditional closure that only triggers when all tokens are transferred [4](#0-3) .

**Critical Bug in Cancel Flow:**
The `cancel()` function conditionally transfers tokens back to the maker **only when `order_src_asset_is_native` is `false`** [5](#0-4) . When this parameter is `true`, the token transfer is completely skipped, and `close_account` is called directly [6](#0-5) .

The SPL Token program has a fundamental constraint: accounts with non-zero token balances **cannot** be closed. This causes the transaction to fail when attempting to cancel a partially-filled native SOL order with the original `src_asset_is_native=true` parameter.

**Identical Issue in cancel_by_resolver:**
The same logic flaw exists in `cancel_by_resolver()` where the token transfer is skipped when `order.src_asset_is_native` is true [7](#0-6) , followed by a direct `close_account` call [8](#0-7) .

**Exploitation Path:**
1. User creates order with 100 native SOL (`src_asset_is_native=true`, `maker_src_ata=null`)
2. Order is partially filled (e.g., 50 SOL transferred to taker)  
3. 50 wrapped SOL tokens remain in `escrow_src_ata` with non-zero token balance
4. User calls `cancel()` with `order_src_asset_is_native=true` → **FAILS** (SPL Token constraint violation)
5. After expiry, `cancel_by_resolver()` also fails for the same reason
6. Workaround: User must call `cancel()` with `order_src_asset_is_native=false`, provide a wrapped SOL ATA to receive wrapped SOL, then manually unwrap

This breaks the **Escrow Integrity** invariant (escrowed tokens must be releasable under valid conditions) and **User Experience** invariant (users should be able to cancel orders using the same parameters they used for creation).

The test suite contains tests for native SOL cancellation [9](#0-8)  and partial fill cancellation with regular tokens [10](#0-9) , but notably lacks a test for the combination: **partial fill + cancel with native SOL**.

## Impact Explanation

**Medium Severity** - While funds are not permanently lost, the impact is significant:

1. **User Confusion**: Users cannot cancel orders using the same parameters they used for creation, violating the principle of least surprise
2. **Technical Barrier**: Non-technical users may not understand they need to call cancel with `src_asset_is_native=false`, provide a wrapped SOL associated token account, and manually unwrap the SOL afterward
3. **Additional Costs**: Users must pay ~0.002 SOL rent for wrapped SOL ATA creation if they don't already have one
4. **Soft Fund Lock**: Users unfamiliar with Solana token mechanics may believe their funds are permanently locked when the cancel transaction fails with a cryptic SPL Token error
5. **Resolver Impact**: Even authorized resolvers cannot cancel expired partially-filled native SOL orders through the standard `cancel_by_resolver()` path

The vulnerability affects **all native SOL orders that are partially filled**, which is a common scenario in limit order systems where large orders are filled incrementally.

This does not rise to High severity because:
- Funds are recoverable with the workaround (albeit unintuitive)
- No permanent loss of funds occurs
- No token theft is possible

## Likelihood Explanation

**High Likelihood** - This issue will occur frequently:

1. **Common Scenario**: Partial fills are a normal part of limit order execution, especially for large orders that exceed immediately available liquidity
2. **Natural User Behavior**: Users will naturally attempt to cancel using the same `src_asset_is_native` value they used during creation
3. **No Warning**: No error message or documentation warns users about this limitation before the transaction fails
4. **Affects All Native SOL Orders**: Every native SOL order that receives a partial fill is vulnerable
5. **No Privilege Required**: Any user creating native SOL orders will encounter this behavior

## Recommendation

Modify the `cancel()` and `cancel_by_resolver()` functions to handle native SOL partial fills correctly. When `order_src_asset_is_native=true` and the escrow has a non-zero balance, the functions should:

1. Transfer the wrapped SOL tokens to a temporary wrapped SOL ATA for the maker (or create one if needed)
2. Close the temporary wrapped SOL ATA to unwrap and return native SOL to the maker
3. Then close the escrow account

Alternatively, always transfer tokens back before closing, regardless of the `src_asset_is_native` flag:

```rust
// In cancel() function, replace lines 302-327 with:
// Always transfer remaining tokens back to maker
if order_src_asset_is_native {
    // For native SOL, close the wrapped SOL account to return native SOL
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
    ))?;
} else {
    // For regular tokens, transfer back to maker's ATA first
    transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.src_token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.escrow_src_ata.to_account_info(),
                mint: ctx.accounts.src_mint.to_account_info(),
                to: ctx.accounts.maker_src_ata.as_ref()
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
    
    // Then close the now-empty account
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
    ))?;
}
```

Note: For native SOL, closing a wrapped SOL token account automatically unwraps the remaining wSOL balance and transfers the lamports to the destination account. This is the standard behavior of the SPL Token program for native mint accounts.

## Proof of Concept

```typescript
// Add this test to tests/suits/fusion-swap.ts after line 1987

it("Cannot cancel partially-filled native SOL order with original parameters", async () => {
  const srcAmount = new anchor.BN(100_000_000); // 0.1 SOL
  
  // Create native SOL order
  const escrow = await state.createEscrow({
    escrowProgram: program,
    payer,
    provider,
    orderConfig: {
      srcMint: splToken.NATIVE_MINT,
      srcAssetIsNative: true,
      srcAmount,
      expirationTime: 0xffffffff,
    },
  });

  // Partially fill the order (50%)
  await program.methods
    .fill(escrow.reducedOrderConfig, srcAmount.divn(2))
    .accountsPartial(
      state.buildAccountsDataForFill({
        escrow: escrow.escrow,
        escrowSrcAta: escrow.ata,
        srcMint: splToken.NATIVE_MINT,
        makerDstAta: null,
      })
    )
    .signers([state.bob.keypair])
    .rpc();

  // Verify escrow has remaining balance
  const escrowAccount = await splToken.getAccount(
    provider.connection,
    escrow.ata
  );
  expect(escrowAccount.amount).to.equal(BigInt(srcAmount.divn(2).toNumber()));

  const orderHash = calculateOrderHash(escrow.orderConfig);

  // Attempt to cancel with original parameters (src_asset_is_native=true)
  // This should FAIL because close_account is called on non-zero balance
  await expect(
    program.methods
      .cancel(Array.from(orderHash), true) // order_src_asset_is_native=true
      .accountsPartial({
        maker: state.alice.keypair.publicKey,
        srcMint: splToken.NATIVE_MINT,
        escrow: escrow.escrow,
        srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
        makerSrcAta: null, // No ATA for native SOL
      })
      .signers([state.alice.keypair])
      .rpc()
  ).to.be.rejected; // Fails with SPL Token error: cannot close account with non-zero balance

  // Workaround: Create wrapped SOL ATA for maker if needed
  const makerWsolAta = await splToken.getAssociatedTokenAddress(
    splToken.NATIVE_MINT,
    state.alice.keypair.publicKey,
    false,
    splToken.TOKEN_PROGRAM_ID
  );

  // Check if ATA exists, if not create it
  try {
    await splToken.getAccount(provider.connection, makerWsolAta);
  } catch {
    // Create the ATA
    const tx = new anchor.web3.Transaction().add(
      splToken.createAssociatedTokenAccountInstruction(
        payer.publicKey,
        makerWsolAta,
        state.alice.keypair.publicKey,
        splToken.NATIVE_MINT,
        splToken.TOKEN_PROGRAM_ID
      )
    );
    await provider.sendAndConfirm(tx, [payer]);
  }

  // Cancel with src_asset_is_native=false to receive wrapped SOL
  await program.methods
    .cancel(Array.from(orderHash), false) // Must use false!
    .accountsPartial({
      maker: state.alice.keypair.publicKey,
      srcMint: splToken.NATIVE_MINT,
      escrow: escrow.escrow,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
      makerSrcAta: makerWsolAta, // Must provide wrapped SOL ATA
    })
    .signers([state.alice.keypair])
    .rpc();

  // Verify maker received wrapped SOL (not native SOL as expected)
  const makerWsolAccount = await splToken.getAccount(
    provider.connection,
    makerWsolAta
  );
  expect(makerWsolAccount.amount).to.equal(BigInt(srcAmount.divn(2).toNumber()));

  // User must now manually unwrap by closing the wrapped SOL account
  await splToken.closeAccount(
    provider.connection,
    payer,
    makerWsolAta,
    state.alice.keypair.publicKey,
    state.alice.keypair
  );
});
```

This test demonstrates:
1. Creating a native SOL order with `srcAssetIsNative=true`
2. Partially filling it (leaving 50% in escrow)
3. Attempting to cancel with the original `order_src_asset_is_native=true` parameter **fails**
4. Workaround requires using `order_src_asset_is_native=false`, providing a wrapped SOL ATA, and manually unwrapping afterward

## Notes

This vulnerability affects normal protocol operation and requires no special privileges or malicious intent. It will naturally occur whenever:
- Users create orders with native SOL
- Orders are partially filled (common in limit order systems)
- Users attempt to cancel using the same parameters they used for creation

The root cause is that the code assumes native SOL orders can always be cancelled by simply closing the wrapped SOL account and returning the rent lamports to the maker. This works for **full** cancellations (zero balance) but fails for **partial** cancellations (non-zero balance) because the SPL Token program prevents closing accounts with non-zero balances to prevent accidental token loss.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L96-98)
```rust
            order.src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );
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

**File:** programs/fusion-swap/src/lib.rs (L166-184)
```rust
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.src_token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.escrow_src_ata.to_account_info(),
                    mint: ctx.accounts.src_mint.to_account_info(),
                    to: ctx.accounts.taker_src_ata.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                &[&[
                    "escrow".as_bytes(),
                    ctx.accounts.maker.key().as_ref(),
                    order_hash,
                    &[ctx.bumps.escrow],
                ]],
            ),
            amount,
            ctx.accounts.src_mint.decimals,
        )?;
```

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

**File:** programs/fusion-swap/src/lib.rs (L329-343)
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
    }
```

**File:** programs/fusion-swap/src/lib.rs (L376-402)
```rust
        // Return remaining src tokens back to maker
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

**File:** programs/fusion-swap/src/lib.rs (L414-427)
```rust
        close_account(CpiContext::new_with_signer(
            ctx.accounts.src_token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.escrow_src_ata.to_account_info(),
                destination: ctx.accounts.resolver.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            &[&[
                "escrow".as_bytes(),
                ctx.accounts.maker.key().as_ref(),
                &order_hash,
                &[ctx.bumps.escrow],
            ]],
        ))?;
```

**File:** tests/suits/fusion-swap.ts (L1792-1843)
```typescript
      ).to.be.rejectedWith("Error Code: InconsistentNativeSrcTrait");
    });

    it("Cancel the trade with native tokens", async () => {
      const escrow = await state.createEscrow({
        escrowProgram: program,
        payer,
        provider,
        orderConfig: {
          srcMint: splToken.NATIVE_MINT,
        },
      });

      const orderHash = calculateOrderHash(escrow.orderConfig);

      const makerNativeBalanceBefore = (
        await provider.connection.getAccountInfo(state.alice.keypair.publicKey)
      ).lamports;

      await program.methods
        .cancel(Array.from(orderHash), true)
        .accountsPartial({
          maker: state.alice.keypair.publicKey,
          srcMint: splToken.NATIVE_MINT,
          escrow: escrow.escrow,
          srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
          makerSrcAta: null,
        })
        .signers([state.alice.keypair])
        .rpc();

      const tokenAccountRent =
        await provider.connection.getMinimumBalanceForRentExemption(
          splToken.AccountLayout.span
        );

      expect(
        (
          await provider.connection.getAccountInfo(
            state.alice.keypair.publicKey
          )
        ).lamports
      ).to.be.eq(
        makerNativeBalanceBefore +
          state.defaultSrcAmount.toNumber() +
          tokenAccountRent
      );

      await expect(
        splToken.getAccount(provider.connection, escrow.ata)
      ).to.be.rejectedWith(splToken.TokenAccountNotFoundError);
    });
```

**File:** tests/suits/fusion-swap.ts (L1925-1987)
```typescript
    it("Execute the partial fill and close escow after", async () => {
      const escrow = await state.createEscrow({
        escrowProgram: program,
        payer,
        provider,
      });

      // Fill the trade partially
      const transactionPromiseFill = () =>
        program.methods
          .fill(escrow.reducedOrderConfig, state.defaultSrcAmount.divn(2))
          .accountsPartial(
            state.buildAccountsDataForFill({
              escrow: escrow.escrow,
              escrowSrcAta: escrow.ata,
            })
          )
          .signers([state.bob.keypair])
          .rpc();

      const resultsFill = await trackReceivedTokenAndTx(
        provider.connection,
        [
          escrow.ata,
          state.alice.atas[state.tokens[1].toString()].address,
          state.bob.atas[state.tokens[0].toString()].address,
          state.bob.atas[state.tokens[1].toString()].address,
        ],
        transactionPromiseFill
      );

      expect(resultsFill).to.be.deep.eq([
        -BigInt(state.defaultSrcAmount.divn(2).toNumber()),
        BigInt(state.defaultDstAmount.divn(2).toNumber()),
        BigInt(state.defaultSrcAmount.divn(2).toNumber()),
        -BigInt(state.defaultDstAmount.divn(2).toNumber()),
      ]);

      const orderHash = calculateOrderHash(escrow.orderConfig);

      // Cancel the trade
      const transactionPromiseCancel = () =>
        program.methods
          .cancel(Array.from(orderHash), false)
          .accountsPartial({
            maker: state.alice.keypair.publicKey,
            srcMint: state.tokens[0],
            escrow: escrow.escrow,
            srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
          })
          .signers([state.alice.keypair])
          .rpc();

      const resultsCancel = await trackReceivedTokenAndTx(
        provider.connection,
        [state.alice.atas[state.tokens[0].toString()].address],
        transactionPromiseCancel
      );

      expect(resultsCancel).to.be.deep.eq([
        BigInt(state.defaultSrcAmount.divn(2).toNumber()),
      ]);
    });
```
