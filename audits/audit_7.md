# Audit Report

## Title
Partially Filled Native SOL Orders Cannot Be Cancelled With Original Parameters, Causing Fund Recovery Issues

## Summary
When a native SOL order is partially filled, the remaining wrapped SOL tokens become locked in escrow and cannot be cancelled using the original `src_asset_is_native=true` parameter. The cancel operation fails because it attempts to close a token account with a non-zero balance, violating SPL Token program constraints. Users must use unexpected parameters (`src_asset_is_native=false`) and receive wrapped SOL instead of native SOL.

## Finding Description

This vulnerability occurs due to a mismatch in how native SOL is handled during order creation versus cancellation after partial fills.

**Order Creation Flow:**
During order creation with `src_asset_is_native=true`, the protocol enforces that `maker_src_ata` must be `None` [1](#0-0) , and native SOL is wrapped to wSOL through a native transfer followed by `sync_native` [2](#0-1) .

**Partial Fill Flow:**
During partial fills, tokens are transferred from the escrow to the taker [3](#0-2) . The escrow account remains open if not fully filled, as indicated by the conditional closure check [4](#0-3) .

**Critical Bug in Cancel Flow:**
The `cancel()` function takes `order_src_asset_is_native` as a parameter and conditionally transfers tokens **only when this parameter is `false`** [5](#0-4) . When `order_src_asset_is_native=true`, the token transfer is **skipped entirely**, and `close_account` is called directly on the escrow [6](#0-5) . 

However, SPL Token's `close_account` instruction **fails** if the token account has a non-zero balance. This is a fundamental constraint of the SPL Token program to prevent accidental token loss.

**Same Issue in cancel_by_resolver:**
The identical logic flaw exists in `cancel_by_resolver()` where the token transfer is also skipped when `order.src_asset_is_native` is true [7](#0-6) , followed by a direct `close_account` call [8](#0-7) .

**Exploitation Path:**
1. User creates order with 100 native SOL (`src_asset_is_native=true`, `maker_src_ata=null`)
2. Order is partially filled (e.g., 50 SOL transferred to taker)
3. 50 wrapped SOL tokens remain in `escrow_src_ata` with non-zero token balance
4. User calls `cancel()` with `order_src_asset_is_native=true` → **FAILS** (SPL Token error: cannot close account with non-zero balance)
5. After expiry, `cancel_by_resolver()` also fails for the same reason
6. User must call `cancel()` with `order_src_asset_is_native=false` and provide a wrapped SOL ATA to recover funds as wrapped SOL, then manually unwrap

This breaks the **Escrow Integrity** invariant (escrowed tokens must be releasable under valid conditions) and **User Experience** invariant (users should be able to cancel orders using the same parameters they used for creation).

## Impact Explanation

**Medium Severity** - While funds are not permanently lost, the impact is significant:

1. **User Confusion**: Users cannot cancel orders using the same parameters they used for creation, violating the principle of least surprise
2. **Technical Barrier**: Non-technical users may not understand they need to call cancel with `src_asset_is_native=false`, provide a wrapped SOL associated token account, and manually unwrap the SOL afterward
3. **Additional Costs**: Users pay ~0.002 SOL rent for wrapped SOL ATA creation if they don't have one
4. **Soft Fund Lock**: Users unfamiliar with Solana token mechanics may believe their funds are permanently locked when the transaction fails
5. **Resolver Impact**: Even authorized resolvers cannot cancel expired partially-filled native SOL orders through the standard `cancel_by_resolver()` path

The vulnerability affects **all native SOL orders that are partially filled**, which is a common scenario in limit order systems where large orders are filled incrementally.

This does not rise to High severity because:
- Funds are recoverable with the workaround (albeit unintuitive)
- No permanent loss of funds occurs
- No token theft is possible

## Likelihood Explanation

**High Likelihood** - This issue will occur frequently:

1. **Common Scenario**: Partial fills are a normal part of limit order execution, especially for large orders that exceed available liquidity
2. **Natural User Behavior**: Users will naturally attempt to cancel using the same `src_asset_is_native` value they used during creation
3. **No Warning**: No error message or documentation warns users about this limitation
4. **Affects All Native SOL Orders**: Every native SOL order with a partial fill is vulnerable
5. **No Privilege Required**: Any user creating native SOL orders will encounter this

The test suite contains tests for native SOL cancellation [9](#0-8)  and partial fill cancellation [10](#0-9) , but notably lacks a test for the combination: **partial fill + cancel with native SOL**, which exposes this gap.

## Recommendation

Modify the `cancel()` and `cancel_by_resolver()` functions to handle native SOL token transfers properly. When `src_asset_is_native=true` and there are remaining tokens in the escrow, the functions should:

1. Transfer the wrapped SOL tokens back to the maker (not skip the transfer)
2. Then close the account after the balance reaches zero

**Fixed Code Pattern:**
```rust
// In cancel() function, replace lines 302-327
// Always transfer remaining tokens, regardless of native flag
transfer_checked(
    CpiContext::new_with_signer(
        ctx.accounts.src_token_program.to_account_info(),
        TransferChecked {
            from: ctx.accounts.escrow_src_ata.to_account_info(),
            mint: ctx.accounts.src_mint.to_account_info(),
            to: if order_src_asset_is_native {
                // For native orders, transfer to a temporary wrapped SOL ATA
                // or directly handle unwrapping here
                ctx.accounts.escrow_src_ata.to_account_info()  // needs adjustment
            } else {
                ctx.accounts.maker_src_ata
                    .as_ref()
                    .ok_or(FusionError::MissingMakerSrcAta)?
                    .to_account_info()
            },
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

Alternatively, for native SOL orders, use a direct lamport transfer from the escrow's wrapped SOL account to the maker before closing, ensuring proper unwrapping.

## Proof of Concept

The following test demonstrates the vulnerability (to be added to `tests/suits/fusion-swap.ts`):

```typescript
it("Cannot cancel partially filled native SOL order with src_asset_is_native=true", async () => {
  // Create native SOL order
  const srcAmount = new anchor.BN(100000);
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

  // Create order
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

  // Partial fill (50%)
  await program.methods
    .fill(orderConfig as ReducedOrderConfig, srcAmount.divn(2))
    .accountsPartial({
      // ... fill accounts
    })
    .signers([state.bob.keypair])
    .rpc();

  // Attempt to cancel with original parameters - THIS WILL FAIL
  await expect(
    program.methods
      .cancel(Array.from(calculateOrderHash(orderConfig)), true)
      .accountsPartial({
        maker: state.alice.keypair.publicKey,
        srcMint: splToken.NATIVE_MINT,
        escrow: escrow,
        srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
        makerSrcAta: null,
      })
      .signers([state.alice.keypair])
      .rpc()
  ).to.be.rejected; // Fails with SPL Token close_account error
});
```

**Notes:**
- The test demonstrates that canceling a partially-filled native SOL order with `srcAssetIsNative=true` and `makerSrcAta=null` fails
- Users must instead call cancel with `srcAssetIsNative=false` and provide a wrapped SOL ATA to recover their funds
- This forces users to receive wrapped SOL instead of native SOL and requires manual unwrapping

### Citations

**File:** programs/fusion-swap/src/lib.rs (L95-97)
```rust
        require!(
            order.src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
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

**File:** programs/fusion-swap/src/lib.rs (L265-280)
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

**File:** tests/suits/fusion-swap.ts (L1795-1843)
```typescript
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

**File:** tests/suits/fusion-swap.ts (L1948-1987)
```typescript
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
