# Audit Report

## Title
Partially Filled Native SOL Orders Cannot Be Cancelled With Original Parameters, Causing Fund Recovery Issues

## Summary
When a native SOL order is partially filled, the remaining wrapped SOL tokens become locked in escrow and cannot be cancelled using the original `src_asset_is_native=true` parameter. The cancel operation fails because it attempts to close a token account with a non-zero balance, violating SPL Token program constraints. Users must use unexpected parameters and receive wrapped SOL instead of native SOL.

## Finding Description

The vulnerability occurs due to a mismatch in how native SOL is handled during order creation versus cancellation after partial fills.

During order creation with `src_asset_is_native=true`, the code enforces that no `maker_src_ata` is provided [1](#0-0) , and native SOL is wrapped to wSOL through a native transfer followed by `sync_native` [2](#0-1) .

During partial fills, tokens are transferred from the escrow to the taker [3](#0-2) , but the escrow account remains open if not fully filled [4](#0-3) .

The critical issue occurs during cancellation. The `cancel()` function takes `order_src_asset_is_native` as a parameter and conditionally transfers tokens only when this parameter is `false` [5](#0-4) . When `order_src_asset_is_native=true`, the token transfer is **skipped**, and `close_account` is called directly on the escrow [6](#0-5) . However, SPL Token's `close_account` instruction **fails** if the token account has a non-zero balance, causing the entire transaction to fail.

The same issue exists in `cancel_by_resolver()` where the token transfer is also skipped when `order.src_asset_is_native` is true [7](#0-6) , followed by a direct `close_account` call [8](#0-7) .

**Exploitation Path:**
1. User creates order with 100 SOL (`src_asset_is_native=true`, no `maker_src_ata`)
2. 50 SOL worth is filled (50 wrapped SOL transferred to taker)
3. 50 wrapped SOL remains in `escrow_src_ata` with non-zero token balance
4. User calls `cancel()` with `order_src_asset_is_native=true` → **FAILS** (SPL Token error: cannot close non-empty account)
5. After expiry, `cancel_by_resolver()` also fails for the same reason
6. User must call `cancel()` with `order_src_asset_is_native=false` and provide a wrapped SOL ATA to recover funds

This breaks the **Escrow Integrity** invariant (escrowed tokens must be securely locked and only released under valid conditions) and **Token Safety** invariant (token transfers must be properly authorized and accounted for). Users depositing native SOL expect to receive native SOL back, not wrapped SOL requiring manual unwrapping.

## Impact Explanation

**Medium Severity** - While funds are not permanently lost, the impact is significant:

1. **User Confusion**: Users cannot cancel orders using the same parameters they used for creation
2. **Technical Barrier**: Non-technical users may not understand they need to call cancel with `src_asset_is_native=false`, provide a wrapped SOL associated token account, and manually unwrap the SOL afterward
3. **Additional Costs**: Users pay ~0.002 SOL rent for wrapped SOL ATA creation if they don't have one
4. **Soft Fund Lock**: Users unfamiliar with Solana token mechanics may believe their funds are permanently locked
5. **Resolver Impact**: Even authorized resolvers cannot cancel expired partially-filled native SOL orders using standard parameters

The vulnerability affects **all native SOL orders that are partially filled**, which is a common scenario in limit order systems. Every such order becomes uncancellable with the expected parameters.

This does not rise to High severity because funds are recoverable with correct (albeit unexpected) parameters and no permanent loss of funds occurs.

## Likelihood Explanation

**High Likelihood** - This issue will occur frequently:

1. **Common Scenario**: Partial fills are a normal part of limit order execution, especially for large orders
2. **Natural User Behavior**: Users will attempt to cancel using the same `src_asset_is_native` value they used during creation
3. **No Warning**: No error message or documentation warns users about this limitation
4. **Affects All Native SOL Orders**: Every native SOL order with a partial fill is vulnerable
5. **No Privilege Required**: Any user creating native SOL orders will encounter this

The combination of high likelihood and medium impact makes this a critical user experience issue that needs immediate fixing.

## Recommendation

The fix should transfer remaining wrapped SOL tokens back to the maker even when `order_src_asset_is_native=true`. The recommended approach is:

**For `cancel()` function:**
```rust
// Return remaining src tokens back to maker
if order_src_asset_is_native {
    // Transfer wrapped SOL and unwrap it by closing to maker
    if ctx.accounts.escrow_src_ata.amount > 0 {
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.src_token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.escrow_src_ata.to_account_info(),
                    mint: ctx.accounts.src_mint.to_account_info(),
                    to: ctx.accounts.maker.to_account_info(), // Create a temporary wSOL ATA for maker
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
} else {
    // Existing logic for non-native tokens
    transfer_checked(...)?;
}

close_account(...)?;
```

Alternatively, simplify by always requiring a `maker_src_ata` even for native SOL orders, or automatically create and close a temporary wSOL ATA during cancellation.

## Proof of Concept

A complete PoC would require setting up the test environment with:
1. Create a native SOL order with `src_asset_is_native=true`
2. Perform a partial fill of the order
3. Attempt to cancel with `order_src_asset_is_native=true` → observe transaction failure
4. Retry cancellation with `order_src_asset_is_native=false` and provided `maker_src_ata` → observe success

The vulnerability is evident from the code structure where the conditional token transfer [5](#0-4)  is skipped for native orders, leading to SPL Token program's rejection of closing non-empty accounts.

## Notes

This is a critical usability and security issue that violates user expectations. While technically funds are recoverable, the non-obvious workaround creates a significant barrier for users and could be perceived as a fund lock. The issue affects both user-initiated cancellations and resolver-initiated cancellations after expiry. Immediate remediation is recommended to maintain protocol integrity and user trust.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L95-98)
```rust
        require!(
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
