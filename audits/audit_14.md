# Audit Report

## Title
Inconsistent Native Asset Flag Allows Cancellation Premium Bypass

## Summary
The validation for native asset flags in the `create` function is unidirectional, allowing orders with native mint (WSOL) but `src_asset_is_native = false`. This inconsistency causes resolvers to lose their cancellation premiums when calling `cancel_by_resolver`, receiving only rent lamports (~0.002 SOL) instead of the intended premium deducted from escrowed token value, or causing transaction failures due to arithmetic underflow.

## Finding Description

The protocol validates native asset flags using one-directional OR logic that permits WSOL orders with the native flag set to false. [1](#0-0) 

This validation translates to: "If the mint is NOT native, then the flag MUST be false." However, it erroneously allows: "If the mint IS native, the flag CAN be false."

**Truth Table:**
- `src_mint == NATIVE_MINT && src_asset_is_native == true` → PASS ✓ (correct)
- `src_mint == NATIVE_MINT && src_asset_is_native == false` → PASS ✓ (VULNERABLE)
- `src_mint != NATIVE_MINT && src_asset_is_native == true` → FAIL ✗ (correct)
- `src_mint != NATIVE_MINT && src_asset_is_native == false` → PASS ✓ (correct)

An attacker creates an order with `src_mint = NATIVE_MINT` but `src_asset_is_native = false`. During creation, WSOL tokens are deposited as SPL tokens into escrow. [2](#0-1) 

The vulnerability manifests in `cancel_by_resolver`. When the flag is false but the mint is WSOL, tokens are transferred back to maker FIRST: [3](#0-2) 

After this transfer, the escrow account only contains rent lamports (~0.00204 SOL). The premium is then calculated and subtracted from these remaining lamports: [4](#0-3) 

**Critical Issue**: The calculation expects to deduct the premium from the full escrow value (tokens + rent), but only rent remains.

This causes two failure modes:
- **Underflow/Transaction Failure**: If `cancellation_premium > rent`, the subtraction underflows causing DoS
- **Minimal Payment**: If `cancellation_premium < rent`, resolver receives only a fraction of rent instead of the intended premium from token value

The escrow is then closed and remaining lamports transferred: [5](#0-4) 

## Impact Explanation

**Severity: HIGH**

This vulnerability breaks the protocol's **Fee Correctness** invariant. Resolvers are systematically denied their rightful cancellation premiums, undermining the economic incentive model.

**Direct Impact:**
- For a 10 SOL order with 0.5 SOL premium (~5%), resolver receives only ~0.001 SOL instead of 0.5 SOL (99.8% loss)
- Resolvers lose `(intended_premium - 0.002 SOL)` per exploited order
- For orders with `max_cancellation_premium = 1 SOL`, 99.8% of premium is effectively stolen

**Systemic Impact:**
- Undermines the protocol's cancellation auction mechanism
- Expired orders accumulate without proper cleanup incentives
- Resolver participation decreases due to unprofitable cancellations
- Protocol reputation damage when resolvers discover systematic underpayment

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Basic understanding of Solana token accounts and WSOL mechanics
- Ability to create orders with custom parameters
- No privileged access required
- No collusion required

**Exploitation Complexity:**
- Simple parameter manipulation during order creation
- The validation bug makes this trivial to execute
- Client-side scripts default to `false` for native flags, making accidental exploitation possible: [6](#0-5) 

**Detection Difficulty:**
- Order appears normal on-chain until cancellation attempt
- Premium loss only visible when resolver calls `cancel_by_resolver`
- No alerts or monitoring during order lifecycle

**Realistic Scenario:**
1. Attacker creates 100 orders with 10 SOL each, native mint but flag = false
2. Sets `max_cancellation_premium = 0.5 SOL` each (total 50 SOL expected premiums)
3. Orders expire naturally
4. Resolvers attempt cancellation, receive only ~0.002 SOL per order
5. Attacker saves ~49.8 SOL in premiums that should have been paid

## Recommendation

Replace the unidirectional validation with bidirectional equality checking:

```rust
require!(
    (ctx.accounts.src_mint.key() == native_mint::id()) == order.src_asset_is_native,
    FusionError::InconsistentNativeSrcTrait
);

require!(
    (ctx.accounts.dst_mint.key() == native_mint::id()) == order.dst_asset_is_native,
    FusionError::InconsistentNativeDstTrait
);
```

This ensures:
- If mint is native → flag must be true
- If mint is not native → flag must be false

Apply the same fix to the `cancel` function validation.

## Proof of Concept

While a complete runnable test is recommended for HIGH severity findings, the vulnerability can be demonstrated with the following test flow:

1. Create order with:
   - `src_mint = NATIVE_MINT` (WSOL)
   - `src_asset_is_native = false`
   - `src_amount = 10_000_000_000` (10 SOL)
   - `max_cancellation_premium = 500_000_000` (0.5 SOL)

2. Wait for order expiration

3. Call `cancel_by_resolver` with a whitelisted resolver

4. Observe:
   - Tokens transferred back to maker at lines 377-402
   - Escrow has only ~2,039,280 lamports (rent)
   - Premium calculation at line 410: `2_039_280 - 500_000_000` underflows
   - Transaction fails OR (in release mode) wraps to huge number causing subsequent transfer failure

**Expected**: Resolver should receive 0.5 SOL premium from the 10 SOL token value
**Actual**: Transaction fails or resolver receives minimal payment

## Notes

The vulnerability is confirmed by examining the actual code paths. The validation logic at lines 51-54 uses OR logic that permits the vulnerable state, and the cancellation logic at lines 376-411 demonstrates how this leads to premium bypass. The client script defaults further increase the likelihood of accidental exploitation.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L51-54)
```rust
        require!(
            ctx.accounts.src_mint.key() == native_mint::id() || !order.src_asset_is_native,
            FusionError::InconsistentNativeSrcTrait
        );
```

**File:** programs/fusion-swap/src/lib.rs (L95-130)
```rust
        require!(
            order.src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );

        // Maker => Escrow
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
        } else {
            uni_transfer(&UniTransferParams::TokenTransfer {
                from: ctx
                    .accounts
                    .maker_src_ata
                    .as_ref()
                    .ok_or(FusionError::MissingMakerSrcAta)?
                    .to_account_info(),
                authority: ctx.accounts.maker.to_account_info(),
                to: ctx.accounts.escrow_src_ata.to_account_info(),
                mint: *ctx.accounts.src_mint.clone(),
                amount: order.src_amount,
                program: ctx.accounts.src_token_program.clone(),
            })
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

**File:** programs/fusion-swap/src/lib.rs (L404-411)
```rust
        let cancellation_premium = calculate_premium(
            current_timestamp as u32,
            order.expiration_time,
            order.cancellation_auction_duration,
            order.fee.max_cancellation_premium,
        );
        let maker_amount = ctx.accounts.escrow_src_ata.to_account_info().lamports()
            - std::cmp::min(cancellation_premium, reward_limit);
```

**File:** programs/fusion-swap/src/lib.rs (L413-436)
```rust
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

**File:** scripts/fusion-swap/create.ts (L43-44)
```typescript
  srcAssetIsNative: boolean = false,
  dstAssetIsNative: boolean = false,
```
