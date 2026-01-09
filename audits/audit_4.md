# Audit Report

## Title
Maker Can Frontrun Resolver to Avoid Cancellation Premium Payment

## Summary
The `cancel()` function allows makers to cancel their orders at any time without paying the cancellation premium, even after expiration when `cancel_by_resolver()` would charge a premium. This enables makers to frontrun resolvers and avoid their agreed-upon obligation to pay cancellation premiums.

## Finding Description

The protocol implements two separate cancellation mechanisms:

1. **`cancel()` function** [1](#0-0)  - Callable by the maker with no time restrictions, returns all tokens and SOL to the maker without any premium deduction.

2. **`cancel_by_resolver()` function** [2](#0-1)  - Callable only by authorized resolvers after order expiration [3](#0-2) , calculates and deducts a cancellation premium from the maker's funds [4](#0-3) .

The vulnerability arises because:

- When creating an order, makers explicitly set `max_cancellation_premium` [5](#0-4) , agreeing to pay a premium if a resolver cancels after expiration
- The `cancel_by_resolver()` function requires this premium to be non-zero [6](#0-5) 
- However, the `cancel()` function has **no expiration check** and **no premium deduction**
- After expiration, makers can call `cancel()` to retrieve all funds without paying the premium they agreed to

**Exploitation Path:**
1. Maker creates order with `max_cancellation_premium = 1 SOL` (agreeing to pay premium)
2. Order expires at timestamp T
3. At T+1, resolver monitors for expired orders and attempts to call `cancel_by_resolver()` to claim the 1 SOL premium
4. Maker frontrunns by submitting `cancel()` transaction with higher priority fee
5. Due to Solana's account locking, only one transaction succeeds
6. Maker's `cancel()` executes first, closing the escrow and retrieving all funds
7. Resolver's `cancel_by_resolver()` fails because escrow is already closed
8. Maker avoids paying the 1 SOL premium they agreed to

This breaks the **Fee Correctness** invariant - the cancellation premium is a fee that should be properly calculated and distributed to resolvers, but makers can bypass it entirely.

## Impact Explanation

**Medium Severity** - This vulnerability causes:

- **Economic loss for resolvers**: Resolvers who monitor and attempt to cancel expired orders lose the premium income they should receive
- **Fee circumvention**: Makers avoid paying fees they explicitly agreed to when creating orders
- **Protocol economic model undermined**: The cancellation premium mechanism is designed to incentivize resolvers to handle expired orders, but becomes ineffective when makers can avoid payment
- **Not systemic theft**: No direct token theft from protocol escrow occurs, and impact is limited to individual order premiums rather than total protocol funds

The impact meets Medium severity criteria as it represents "fee calculation errors causing partial losses" and affects the economic incentive structure of the protocol.

## Likelihood Explanation

**High Likelihood** - This vulnerability is highly likely to be exploited because:

- **Easy to execute**: Makers simply call `cancel()` instead of letting resolvers handle cancellation
- **Clear economic incentive**: Makers save the full cancellation premium amount (can be significant)
- **No special requirements**: Any maker can exploit this with basic transaction submission
- **Frontrunning is straightforward**: Makers can monitor their own order expiration times and submit transactions with higher priority fees
- **Automation friendly**: This can be easily automated by order creation frontends

Rational economic actors (makers) will naturally prefer to cancel themselves after expiration rather than pay premiums to resolvers.

## Recommendation

Add an expiration check to the `cancel()` function to prevent makers from canceling after expiration when a cancellation premium is configured. Makers should only be allowed to cancel for free before expiration.

**Code Fix:**

Add the following check at the beginning of the `cancel()` function:

```rust
pub fn cancel(
    ctx: Context<Cancel>,
    order_hash: [u8; 32],
    order_src_asset_is_native: bool,
    order_expiration_time: u32,  // Add parameter
    order_max_cancellation_premium: u64,  // Add parameter
) -> Result<()> {
    // NEW: Prevent maker from canceling after expiration if premium is configured
    if order_max_cancellation_premium > 0 {
        let current_timestamp = Clock::get()?.unix_timestamp;
        require!(
            current_timestamp < order_expiration_time as i64,
            FusionError::OrderExpiredWithPremium
        );
    }
    
    // ... existing code ...
}
```

This ensures that once an order with a configured cancellation premium expires, only resolvers can cancel it (and claim the premium). Makers can still freely cancel before expiration.

## Proof of Concept

**Reproduction Steps:**

1. **Setup**: Maker creates an order with:
   - `src_amount`: 100 USDC
   - `expiration_time`: current_time + 3600 (1 hour)
   - `max_cancellation_premium`: 1 SOL
   - This means maker agrees to pay 1 SOL if a resolver cancels after expiration

2. **Wait**: Order expires (1 hour passes, order not filled)

3. **Resolver Action**: Authorized resolver sees expired order and calls `cancel_by_resolver()`:
   ```
   Transaction A (Resolver):
   - Function: cancel_by_resolver()
   - Expected: Maker gets 100 USDC + (escrow_lamports - 1 SOL)
   - Expected: Resolver gets 1 SOL premium
   ```

4. **Maker Frontrun**: Maker simultaneously calls `cancel()`:
   ```
   Transaction B (Maker):
   - Function: cancel()  
   - Priority fee: Higher than resolver's
   - Expected: Maker gets 100 USDC + all escrow_lamports
   ```

5. **Result**: 
   - Transaction B processes first (higher priority)
   - Maker gets: 100 USDC + all escrow SOL lamports (no premium paid)
   - Transaction A fails (escrow account already closed)
   - Resolver gets: Nothing (loses gas fees)

**Test Scenario:**
```rust
#[tokio::test]
async fn test_maker_frontrun_cancellation_premium() {
    // 1. Create order with 1 SOL cancellation premium
    // 2. Advance time past expiration
    // 3. Maker calls cancel() before resolver
    // 4. Verify maker gets all funds back (no premium deducted)
    // 5. Verify resolver's cancel_by_resolver() fails
    // 6. Confirm maker avoided 1 SOL premium payment
}
```

The vulnerability is confirmed by the absence of any expiration or premium checks in the `cancel()` function [1](#0-0) , combined with the expiration requirement in `cancel_by_resolver()` [3](#0-2) .

## Notes

The vulnerability exists because there are two separate cancellation paths with inconsistent access control:
- The `cancel()` path has no time restrictions
- The `cancel_by_resolver()` path is time-gated to post-expiration only

This asymmetry allows makers to avoid the premium by choosing which path to take. The fix should align the access control rules so that premium-bearing orders can only be cancelled by resolvers after expiration.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L286-343)
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

        require!(
            order_src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );

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

**File:** programs/fusion-swap/src/lib.rs (L345-436)
```rust
    pub fn cancel_by_resolver(
        ctx: Context<CancelByResolver>,
        order: OrderConfig,
        reward_limit: u64,
    ) -> Result<()> {
        require!(
            order.fee.max_cancellation_premium > 0,
            FusionError::CancelOrderByResolverIsForbidden
        );
        let current_timestamp = Clock::get()?.unix_timestamp;
        require!(
            current_timestamp >= order.expiration_time as i64,
            FusionError::OrderNotExpired
        );
        require!(
            order.src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );

        let order_hash = order_hash(
            &order,
            ctx.accounts.protocol_dst_acc.as_ref().map(|acc| acc.key()),
            ctx.accounts
                .integrator_dst_acc
                .as_ref()
                .map(|acc| acc.key()),
            ctx.accounts.src_mint.key(),
            ctx.accounts.dst_mint.key(),
            ctx.accounts.maker_receiver.key(),
        )?;

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

        let cancellation_premium = calculate_premium(
            current_timestamp as u32,
            order.expiration_time,
            order.cancellation_auction_duration,
            order.fee.max_cancellation_premium,
        );
        let maker_amount = ctx.accounts.escrow_src_ata.to_account_info().lamports()
            - std::cmp::min(cancellation_premium, reward_limit);

        // Transfer all the remaining lamports to the resolver first
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

        // Transfer all lamports from the closed account, minus the cancellation premium, to the maker
        uni_transfer(&UniTransferParams::NativeTransfer {
            from: ctx.accounts.resolver.to_account_info(),
            to: ctx.accounts.maker.to_account_info(),
            amount: maker_amount,
            program: ctx.accounts.system_program.clone(),
        })
    }
```

**File:** programs/fusion-swap/src/lib.rs (L713-729)
```rust
/// Configuration for fees applied to the escrow
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct FeeConfig {
    /// Protocol fee in basis points where `BASE_1E5` = 100%
    protocol_fee: u16,

    /// Integrator fee in basis points where `BASE_1E5` = 100%
    integrator_fee: u16,

    /// Percentage of positive slippage taken by the protocol as an additional fee.
    /// Value in basis points where `BASE_1E2` = 100%
    surplus_percentage: u8,

    /// Maximum cancellation premium
    /// Value in absolute lamports amount
    max_cancellation_premium: u64,
}
```
