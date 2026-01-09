# Audit Report

## Title
Partially Filled Native SOL Orders Cannot Be Cancelled With Original Parameters, Causing Fund Recovery Issues

## Summary
When a native SOL order is partially filled, the remaining wrapped SOL tokens become locked in escrow and cannot be cancelled using the original `src_asset_is_native=true` parameter. The cancel operation fails because it attempts to close a token account with a non-zero balance, violating SPL Token program constraints. Users must use unexpected parameters and receive wrapped SOL instead of native SOL.

## Finding Description

The vulnerability occurs due to a mismatch in how native SOL is handled during order creation versus cancellation after partial fills.

During order creation with `src_asset_is_native=true`, native SOL is wrapped to wSOL and stored in `escrow_src_ata`: [1](#0-0) [2](#0-1) 

The check ensures no `maker_src_ata` is provided for native orders, and the SOL is wrapped to wSOL via `sync_native`.

During partial fills, tokens are transferred from escrow to taker, but the escrow remains open if not fully filled: [3](#0-2) [4](#0-3) 

The critical issue occurs during cancellation. The `cancel()` function takes `order_src_asset_is_native` as a parameter and conditionally transfers tokens: [5](#0-4) [6](#0-5) 

When `order_src_asset_is_native=true`, the token transfer is **skipped** (lines 302-327), and `close_account` is called directly. However, SPL Token's `close_account` instruction **fails** if the token account has a non-zero balance. This causes the entire transaction to fail.

The same issue exists in `cancel_by_resolver()`: [7](#0-6) [8](#0-7) 

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
2. **Technical Barrier**: Non-technical users may not understand they need to:
   - Call cancel with `src_asset_is_native=false`
   - Provide a wrapped SOL associated token account
   - Manually unwrap the SOL afterward
3. **Additional Costs**: Users pay ~0.002 SOL rent for wrapped SOL ATA creation if they don't have one
4. **Soft Fund Lock**: Users unfamiliar with Solana token mechanics may believe their funds are permanently locked
5. **Resolver Impact**: Even authorized resolvers cannot cancel expired partially-filled native SOL orders

The vulnerability affects **all native SOL orders that are partially filled**, which is a common scenario in limit order systems. Every such order becomes uncancellable with the expected parameters.

This does not rise to High severity because:
- Funds are recoverable with correct (albeit unexpected) parameters
- No permanent loss of funds occurs
- Only affects users who understand the workaround

## Likelihood Explanation

**High Likelihood** - This issue will occur frequently:

1. **Common Scenario**: Partial fills are a normal part of limit order execution, especially for large orders
2. **Natural User Behavior**: Users will attempt to cancel using the same `src_asset_is_native` value they used during creation
3. **No Warning**: No error message or documentation warns users about this limitation
4. **Affects All Native SOL Orders**: Every native SOL order with a partial fill is vulnerable
5. **No Privilege Required**: Any user creating native SOL orders will encounter this

The combination of high likelihood and medium impact makes this a critical user experience issue that needs immediate fixing.

## Recommendation

Modify the `cancel()` and `cancel_by_resolver()` functions to **always** transfer remaining tokens back to the maker when the escrow has a non-zero balance, regardless of the `src_asset_is_native` flag. The flag should only control whether to unwrap SOL after the transfer.

**For `cancel()` function:**

```rust
pub fn cancel(
    ctx: Context<Cancel>,
    order_hash: [u8; 32],
    order_src_asset_is_native: bool,
) -> Result<()> {
    require!(
        ctx.accounts.src_mint.key() == native_mint::id() || !order_src_asset_is_native,
        FusionError::InconsistentNativeSrcTrait
    );

    // Always check if maker_src_ata is needed based on remaining balance
    let has_tokens = ctx.accounts.escrow_src_ata.amount > 0;
    
    require!(
        !has_tokens || ctx.accounts.maker_src_ata.is_some(),
        FusionError::MissingMakerSrcAta
    );

    // Return remaining src tokens back to maker if any exist
    if has_tokens {
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
                        .unwrap()
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

Apply the same fix to `cancel_by_resolver()`. Additionally, update the `Cancel` struct to make `maker_src_ata` mandatory (non-optional) to ensure users always provide it.

Alternatively, if you want to preserve the option to receive native SOL directly, add unwrapping logic after the transfer when the token is wrapped SOL.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;
    use anchor_spl::token::{self, Token, TokenAccount, Mint};

    #[test]
    fn test_partial_fill_native_sol_cancel_fails() {
        // Setup: Create test accounts and context
        let maker = Keypair::new();
        let taker = Keypair::new();
        
        // Step 1: Create order with native SOL (src_asset_is_native=true)
        let order_config = OrderConfig {
            id: 1,
            src_amount: 100_000_000_000, // 100 SOL
            min_dst_amount: 1000_000_000, // 1000 tokens
            estimated_dst_amount: 1100_000_000,
            expiration_time: (Clock::get().unwrap().unix_timestamp + 3600) as u32,
            src_asset_is_native: true,  // Native SOL
            dst_asset_is_native: false,
            fee: FeeConfig {
                protocol_fee: 0,
                integrator_fee: 0,
                surplus_percentage: 0,
                max_cancellation_premium: 1_000_000,
            },
            dutch_auction_data: AuctionData::default(),
            cancellation_auction_duration: 0,
        };

        // Create order - SOL gets wrapped to wSOL in escrow_src_ata
        create(create_ctx, order_config.clone()).unwrap();
        
        // Verify escrow has 100 wrapped SOL tokens
        assert_eq!(escrow_src_ata.amount, 100_000_000_000);

        // Step 2: Partial fill - 50 SOL worth
        fill(fill_ctx, order_config.clone(), 50_000_000_000).unwrap();
        
        // Verify escrow now has 50 wrapped SOL tokens remaining
        assert_eq!(escrow_src_ata.amount, 50_000_000_000);

        // Step 3: Try to cancel with original parameters (src_asset_is_native=true, no maker_src_ata)
        let order_hash = compute_order_hash(&order_config);
        let cancel_result = cancel(
            cancel_ctx_without_maker_src_ata,
            order_hash,
            true  // order_src_asset_is_native=true (same as creation)
        );

        // This FAILS because close_account is called on non-empty token account
        assert!(cancel_result.is_err());
        // Expected error from SPL Token: "CloseAccount: Account not empty"
        
        // Step 4: User must use workaround - call with src_asset_is_native=false
        let cancel_workaround = cancel(
            cancel_ctx_with_maker_src_ata,
            order_hash,
            false  // Must lie about being native to trigger token transfer
        );
        
        // This succeeds, but user receives wrapped SOL instead of native SOL
        assert!(cancel_workaround.is_ok());
        assert_eq!(maker_wrapped_sol_ata.amount, 50_000_000_000);
        
        // User must now manually unwrap the SOL (additional step + transaction cost)
    }
}
```

**Notes:**

This vulnerability affects the core user experience of the protocol. The mismatch between creation and cancellation logic for native SOL orders creates a confusing and error-prone situation. Users who create native SOL orders with partial fills will encounter unexpected failures when trying to cancel, potentially leading to support burden and loss of user trust. The fix requires ensuring that token transfers always occur before account closure when the balance is non-zero, regardless of the asset type flag.

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
