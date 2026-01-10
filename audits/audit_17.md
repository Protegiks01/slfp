# Audit Report

## Title
Partially Filled Native SOL Orders Cannot Be Cancelled With Original Parameters, Causing Fund Recovery Issues

## Summary
When a native SOL order is partially filled, the remaining wrapped SOL tokens in escrow cannot be cancelled using the original `src_asset_is_native=true` parameter. The cancel operation fails because it attempts to close a token account with a non-zero balance, violating SPL Token program constraints. Users must use unexpected parameters (`src_asset_is_native=false`) and provide a wrapped SOL ATA to recover funds.

## Finding Description

The vulnerability stems from inconsistent handling of native SOL between order creation and cancellation after partial fills.

**Order Creation Flow:**

During order creation with `src_asset_is_native=true`, the protocol enforces that no `maker_src_ata` is provided [1](#0-0) , then wraps native SOL to wSOL and stores it in `escrow_src_ata` [2](#0-1) .

**Partial Fill Flow:**

During partial fills, tokens are transferred from escrow to taker [3](#0-2) , but the escrow remains open if not fully filled [4](#0-3) . The `escrow_src_ata` retains a non-zero wSOL balance.

**Cancellation Failure:**

The `cancel()` function enforces the same parameter constraint [5](#0-4) . When `order_src_asset_is_native=true`, the token transfer is **skipped** [6](#0-5) , and `close_account` is called directly [7](#0-6) . However, SPL Token's `close_account` instruction **requires** a zero token balance, causing the transaction to fail.

The same issue exists in `cancel_by_resolver()` [8](#0-7)  where token transfer is skipped for native assets [9](#0-8) , followed by `close_account` [10](#0-9) .

**Exploitation Path:**
1. User creates order with 100 SOL (`src_asset_is_native=true`, no `maker_src_ata`)
2. Order is 50% filled (50 wSOL transferred to taker, 50 wSOL remains in escrow)
3. User attempts `cancel()` with `order_src_asset_is_native=true` → **Transaction FAILS** (SPL Token error: cannot close non-empty account)
4. After expiry, `cancel_by_resolver()` also fails for the same reason
5. User must call `cancel()` with `order_src_asset_is_native=false` and provide a wSOL ATA to recover funds

This breaks protocol invariants: users depositing native SOL expect to cancel with the same parameters used during creation and receive native SOL back, not wrapped SOL requiring manual unwrapping.

## Impact Explanation

**Medium Severity** - The impact is significant despite funds being ultimately recoverable:

1. **Functional Failure**: Core cancel operation fails for a common scenario
2. **User Confusion**: Cannot use original parameters for cancellation
3. **Technical Barrier**: Non-technical users must understand:
   - Call cancel with `src_asset_is_native=false`
   - Provide/create a wrapped SOL ATA (~0.002 SOL rent cost)
   - Manually unwrap wSOL afterward
4. **Soft Fund Lock**: Users unfamiliar with Solana token mechanics may believe funds are permanently inaccessible
5. **Resolver Impact**: Even authorized resolvers cannot cancel expired partially-filled native SOL orders using standard parameters

This affects **all native SOL orders that are partially filled**—a common scenario in limit order systems. The test suite lacks coverage for this scenario [11](#0-10) , where native SOL cancellation tests only cover fully unfilled orders.

## Likelihood Explanation

**High Likelihood** - This occurs frequently in normal protocol operation:

1. **Common Scenario**: Partial fills are standard in limit order execution
2. **Natural User Behavior**: Users logically attempt cancellation with creation parameters
3. **No Safeguards**: No warning messages or documentation about this limitation
4. **Universal Impact**: Every partially-filled native SOL order is affected
5. **No Privilege Required**: Any user creating native SOL orders will encounter this

The combination of high likelihood and medium impact creates a critical operational issue.

## Recommendation

Modify the `cancel()` and `cancel_by_resolver()` functions to handle partially-filled native SOL orders correctly:

**Option 1 (Recommended):** Always transfer remaining tokens when balance is non-zero, regardless of `src_asset_is_native` flag:

```rust
// In cancel() function, replace lines 302-327:
if ctx.accounts.escrow_src_ata.amount > 0 {
    if !order_src_asset_is_native {
        transfer_checked(
            // ... existing transfer logic
        )?;
    } else {
        // Transfer wSOL to maker's wSOL ATA or unwrap directly
        // Implementation depends on desired UX
    }
}
```

**Option 2:** Document the workaround and provide clear error messages when cancellation fails due to non-zero balance.

**Option 3:** Track partial fill status and automatically handle native/wrapped token distinction based on actual state rather than original parameter.

## Proof of Concept

Add this test to `tests/suits/fusion-swap.ts`:

```typescript
it("Cannot cancel partially filled native SOL order with original parameters", async () => {
    const srcAmount = new anchor.BN(100000);
    const partialFillAmount = srcAmount.divn(2); // 50% fill
    
    // Create order with native SOL
    const escrow = await state.createEscrow({
        escrowProgram: program,
        payer,
        provider,
        orderConfig: state.orderConfig({
            srcMint: splToken.NATIVE_MINT,
            srcAssetIsNative: true,
            srcAmount,
        }),
    });
    
    // Partially fill the order
    await program.methods
        .fill(escrow.reducedOrderConfig, partialFillAmount)
        .accountsPartial(
            state.buildAccountsDataForFill({
                escrow: escrow.escrow,
                escrowSrcAta: escrow.ata,
                srcMint: splToken.NATIVE_MINT,
                takerSrcAta: state.bob.atas[splToken.NATIVE_MINT.toString()].address,
            })
        )
        .signers([state.bob.keypair])
        .rpc();
    
    const orderHash = calculateOrderHash(escrow.orderConfig);
    
    // Attempt to cancel with original parameters - THIS SHOULD FAIL
    await expect(
        program.methods
            .cancel(Array.from(orderHash), true) // src_asset_is_native=true
            .accountsPartial({
                maker: state.alice.keypair.publicKey,
                srcMint: splToken.NATIVE_MINT,
                escrow: escrow.escrow,
                escrowSrcAta: escrow.ata,
                srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
                makerSrcAta: null,
            })
            .signers([state.alice.keypair])
            .rpc()
    ).to.be.rejected; // Fails with "cannot close account with non-zero balance"
    
    // Workaround: Cancel with src_asset_is_native=false and provide wSOL ATA
    const makerWsolAta = state.alice.atas[splToken.NATIVE_MINT.toString()].address;
    
    await program.methods
        .cancel(Array.from(orderHash), false) // src_asset_is_native=false
        .accountsPartial({
            maker: state.alice.keypair.publicKey,
            srcMint: splToken.NATIVE_MINT,
            escrow: escrow.escrow,
            escrowSrcAta: escrow.ata,
            srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
            makerSrcAta: makerWsolAta, // Provide wSOL ATA
        })
        .signers([state.alice.keypair])
        .rpc();
    
    // User must now manually unwrap the wSOL
});
```

## Notes

The vulnerability is confirmed through code analysis showing the execution path leads to certain failure. Test coverage analysis reveals no existing tests for partially-filled native SOL order cancellation [12](#0-11) , only tests for fully unfilled orders. The multiple trades test [13](#0-12)  demonstrates partial fills work correctly for regular SPL tokens but not native SOL cancellation.

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

**File:** programs/fusion-swap/src/lib.rs (L266-281)
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
        }
```

**File:** programs/fusion-swap/src/lib.rs (L297-299)
```rust
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

**File:** tests/suits/cancel-by-resolver.ts (L402-467)
```typescript
  it("Maker recives native tokens if order was created with native src assets", async () => {
    const amount = new anchor.BN(10000);
    const escrow = await state.createEscrow({
      escrowProgram: program,
      payer,
      provider: banksClient,
      orderConfig: state.orderConfig({
        srcMint: splToken.NATIVE_MINT,
        srcAssetIsNative: true,
        srcAmount: amount,
        fee: {
          maxCancellationPremium: defaultMaxCancellationPremium,
        },
        cancellationAuctionDuration: order.auctionDuration,
      }),
    });

    const makerNativeBalanceBefore = (
      await provider.connection.getAccountInfo(state.alice.keypair.publicKey)
    ).lamports;
    const resolverNativeBalanceBefore = (
      await provider.connection.getAccountInfo(state.bob.keypair.publicKey)
    ).lamports;

    // Rewind time to expire the order
    await setCurrentTime(context, state.defaultExpirationTime);

    const transactionPromise = () =>
      program.methods
        .cancelByResolver(escrow.reducedOrderConfig, new anchor.BN(0))
        .accountsPartial({
          resolver: state.bob.keypair.publicKey,
          maker: state.alice.keypair.publicKey,
          makerReceiver: escrow.orderConfig.receiver,
          srcMint: escrow.orderConfig.srcMint,
          dstMint: escrow.orderConfig.dstMint,
          escrow: escrow.escrow,
          escrowSrcAta: escrow.ata,
          protocolDstAcc: escrow.orderConfig.fee.protocolDstAcc,
          integratorDstAcc: escrow.orderConfig.fee.integratorDstAcc,
          srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
          makerSrcAta: null,
        })
        .signers([payer, state.bob.keypair])
        .rpc();

    const results = await trackReceivedTokenAndTx(
      provider.connection,
      [
        state.alice.atas[state.tokens[0].toString()].address,
        state.bob.atas[state.tokens[0].toString()].address,
      ],
      transactionPromise
    );

    expect(
      (await provider.connection.getAccountInfo(state.alice.keypair.publicKey))
        .lamports
    ).to.be.eq(makerNativeBalanceBefore + amount.toNumber() + tokenAccountRent);
    expect(
      (await provider.connection.getAccountInfo(state.bob.keypair.publicKey))
        .lamports
    ).to.be.eq(resolverNativeBalanceBefore);

    expect(results).to.be.deep.eq([BigInt(0), BigInt(0)]);
  });
```

**File:** tests/suits/fusion-swap.ts (L1535-1593)
```typescript
    it("Execute the multiple trades", async () => {
      let transactionPromise = () =>
        program.methods
          .fill(
            state.escrows[0].reducedOrderConfig,
            state.defaultSrcAmount.divn(2)
          )
          .accountsPartial(state.buildAccountsDataForFill({}))
          .signers([state.bob.keypair])
          .rpc();

      let results = await trackReceivedTokenAndTx(
        provider.connection,
        [
          state.escrows[0].ata,
          state.alice.atas[state.tokens[1].toString()].address,
          state.bob.atas[state.tokens[0].toString()].address,
          state.bob.atas[state.tokens[1].toString()].address,
        ],
        transactionPromise
      );

      expect(results).to.be.deep.eq([
        -BigInt(state.defaultSrcAmount.divn(2).toNumber()),
        BigInt(state.defaultDstAmount.divn(2).toNumber()),
        BigInt(state.defaultSrcAmount.divn(2).toNumber()),
        -BigInt(state.defaultDstAmount.divn(2).toNumber()),
      ]);

      // Second trade
      transactionPromise = () =>
        program.methods
          .fill(
            state.escrows[0].reducedOrderConfig,
            state.defaultSrcAmount.divn(2)
          )
          .accountsPartial(state.buildAccountsDataForFill({}))
          .signers([state.bob.keypair])
          .rpc();

      results = await trackReceivedTokenAndTx(
        provider.connection,
        [
          state.alice.atas[state.tokens[1].toString()].address,
          state.bob.atas[state.tokens[0].toString()].address,
          state.bob.atas[state.tokens[1].toString()].address,
        ],
        transactionPromise
      );
      await expect(
        splToken.getAccount(provider.connection, state.escrows[0].ata)
      ).to.be.rejectedWith(splToken.TokenAccountNotFoundError);

      expect(results).to.be.deep.eq([
        BigInt(state.defaultDstAmount.divn(2).toNumber()),
        BigInt(state.defaultSrcAmount.divn(2).toNumber()),
        -BigInt(state.defaultDstAmount.divn(2).toNumber()),
      ]);
    });
```

**File:** tests/suits/fusion-swap.ts (L1729-1775)
```typescript
    it("Cancellation works if src-token is native and maker-src-ata is not provided", async () => {
      const srcAmount = new anchor.BN(10000);
      // create new escrow
      const orderConfig = state.orderConfig({
        srcMint: splToken.NATIVE_MINT,
        srcAssetIsNative: true,
        srcAmount,
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

      await program.methods
        .create(orderConfig as ReducedOrderConfig)
        .accountsPartial({
          maker: state.alice.keypair.publicKey,
          makerReceiver: orderConfig.receiver,
          srcMint: splToken.NATIVE_MINT,
          dstMint: state.tokens[1],
          protocolDstAcc: null,
          integratorDstAcc: null,
          escrow,
          srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
          makerSrcAta: null,
        })
        .signers([state.alice.keypair])
        .rpc();

      await program.methods
        .cancel(Array.from(calculateOrderHash(orderConfig)), true)
        .accountsPartial({
          maker: state.alice.keypair.publicKey,
          srcMint: splToken.NATIVE_MINT,
          escrow: escrow,
          srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
          makerSrcAta: null,
        })
        .signers([state.alice.keypair])
        .rpc();
    });
```
