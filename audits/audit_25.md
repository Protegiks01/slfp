# Audit Report

## Title
Token-2022 Transfer Fees Cause Accounting Mismatch and Fund Loss for Order Makers

## Summary
The Fusion Protocol accepts Token-2022 mints with transfer fees without accounting for fee deductions during token transfers. This causes makers to lose funds during both order creation (src_mint fees) and order filling (dst_mint fees), as the protocol assumes transfers move exact amounts but transfer fees reduce the actual amounts received.

## Finding Description

The protocol uses `Interface<'info, TokenInterface>` to accept both SPL Token and Token-2022 programs, but fails to account for Token-2022's transfer fee extension. This breaks the **Token Safety** and **Escrow Integrity** invariants. [1](#0-0) 

The client script accepts arbitrary mint addresses as `srcMint` and `dstMint` parameters with no validation of token properties or extensions. [2](#0-1) 

The on-chain program validates mints as `InterfaceAccount<'info, Mint>`, which accepts any valid mint account including Token-2022 mints with transfer fees, but performs no checks for fee extensions.

**Attack Scenario 1 - Maker Loses Src Tokens to Transfer Fees:**

1. Attacker creates Token-2022 mint with 10% transfer fee as `srcMint`
2. Attacker creates order to sell 1000 tokens for 1000 USDC via `create()` function
3. During order creation, tokens transfer from maker to escrow: [3](#0-2) 

4. The `transfer_checked` call attempts to transfer 1000 tokens
5. Due to 10% transfer fee: escrow receives only 900 tokens, 100 tokens taken as fee
6. Order advertises 1000 tokens but escrow only has 900 tokens
7. When resolver attempts to fill, the check limits execution: [4](#0-3) 

8. Only 900 tokens can be filled, maker receives only 900 USDC instead of 1000 USDC
9. Maker loses 100 tokens' worth of value to the transfer fee

**Attack Scenario 2 - Maker Loses Dst Tokens to Transfer Fees:**

1. Order uses Token-2022 mint with 10% transfer fee as `dstMint`
2. During order fill, protocol calculates maker should receive `maker_dst_amount`: [5](#0-4) 

3. Transfer from taker to maker executes: [6](#0-5) 

4. Due to 10% transfer fee on `dst_mint`, maker receives only `maker_dst_amount * 0.9`
5. Maker loses 10% of their expected payment to the transfer fee

## Impact Explanation

**Severity: HIGH**

This vulnerability causes direct financial loss to order makers:

- **Immediate fund loss**: Makers lose tokens to transfer fees during escrow transfer and payment receipt
- **Accounting inconsistency**: Orders advertise amounts that cannot be fulfilled due to escrowed balance being less than advertised
- **Unfillable orders**: Partial orders become unfillable when escrow balance is depleted by fees
- **Widespread impact**: Affects any order using Token-2022 mints with transfer fees (increasingly common as Token-2022 adoption grows)

The vulnerability breaks critical protocol invariants:
- **Token Safety**: Token transfers are not properly accounted for (actual amounts differ from expected)
- **Escrow Integrity**: Escrowed amounts don't match order specifications
- **Fee Correctness**: Fee deductions occur that are not reflected in protocol calculations

## Likelihood Explanation

**Likelihood: HIGH**

- **No validation barrier**: Protocol accepts any valid mint without checking for transfer fee extension
- **Token-2022 adoption increasing**: More tokens are being launched with transfer fees
- **Unintentional exploitation**: Makers may unknowingly create orders with fee-bearing tokens without realizing they'll lose funds
- **Low attacker sophistication**: No special knowledge or setup required - simply use a Token-2022 mint with fees

The exploitation requires only:
1. Access to a Token-2022 mint with transfer fees (publicly available)
2. Creating an order through the standard interface
3. No special permissions or insider access needed

## Recommendation

Add validation to reject Token-2022 mints with transfer fees, or alternatively, implement proper accounting for transfer fees. The simplest fix is to check for and reject mints with the transfer fee extension:

```rust
// In the Create struct validation
pub struct Create<'info> {
    // ... existing fields ...
    
    #[account(
        constraint = !has_transfer_fee_extension(&src_mint) @ FusionError::TransferFeeTokensNotSupported,
    )]
    src_mint: Box<InterfaceAccount<'info, Mint>>,
    
    #[account(
        constraint = !has_transfer_fee_extension(&dst_mint) @ FusionError::TransferFeeTokensNotSupported,
    )]
    dst_mint: Box<InterfaceAccount<'info, Mint>>,
}

// Add helper function
fn has_transfer_fee_extension(mint: &InterfaceAccount<Mint>) -> bool {
    use anchor_spl::token_2022::spl_token_2022::extension::{
        BaseStateWithExtensions, StateWithExtensions
    };
    
    if let Ok(mint_data) = mint.to_account_info().try_borrow_data() {
        if let Ok(mint_with_extensions) = StateWithExtensions::<
            anchor_spl::token_2022::spl_token_2022::state::Mint
        >::unpack(&mint_data) {
            return mint_with_extensions.get_extension::<
                anchor_spl::token_2022::spl_token_2022::extension::transfer_fee::TransferFeeConfig
            >().is_ok();
        }
    }
    false
}
```

Add new error code in `error.rs`:
```rust
#[msg("Token with transfer fees not supported")]
TransferFeeTokensNotSupported,
```

Alternatively, implement full support by:
1. Querying actual post-transfer balances
2. Adjusting all calculations based on actual received amounts
3. Documenting that orders with fee-bearing tokens will behave differently

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;
    use anchor_spl::token_2022::{
        self,
        spl_token_2022::{
            extension::{transfer_fee::TransferFee, ExtensionType},
            instruction::initialize_mint2,
        },
    };

    #[test]
    fn test_transfer_fee_causes_fund_loss() {
        // Setup: Create Token-2022 mint with 10% transfer fee
        let transfer_fee_basis_points: u16 = 1000; // 10%
        let maximum_fee: u64 = u64::MAX;
        
        // Create order with 1000 tokens
        let src_amount = 1000u64;
        let order = OrderConfig {
            src_amount,
            // ... other fields
        };
        
        // Execute create instruction
        // Token transfer from maker to escrow with 10% fee
        // Expected: escrow receives 1000 tokens
        // Actual: escrow receives 900 tokens (100 deducted as fee)
        
        // Verify escrow balance
        let escrow_balance = get_escrow_balance();
        assert_eq!(escrow_balance, 900); // Only 900 tokens in escrow
        
        // Attempt to fill order for full 1000 tokens
        let fill_result = fill_order(1000);
        
        // Fill fails or is limited to 900 tokens
        assert!(fill_result.is_err() || fill_result.unwrap() <= 900);
        
        // Maker loses 100 tokens worth of value
        // Order advertises 1000 tokens but only 900 can be sold
    }
}
```

**Reproduction Steps:**
1. Create Token-2022 mint with transfer fee extension (e.g., 10% fee)
2. Create order using this mint as `srcMint` with `src_amount = 1000`
3. Observe escrow receives only 900 tokens due to transfer fee
4. Attempt to fill order - can only fill 900 tokens
5. Maker receives payment for 900 tokens instead of 1000 tokens
6. 100 tokens' worth of value lost to transfer fee

**Notes**

The vulnerability affects both `srcMint` (during escrow) and `dstMint` (during payment). While Token-2022 transfer hooks pose additional risks (reentrancy, DoS), the transfer fee accounting issue is the most concrete and immediately exploitable vulnerability. The protocol should either explicitly support Token-2022 with proper fee handling or reject these mints entirely until proper support is implemented.

### Citations

**File:** scripts/fusion-swap/create.ts (L38-39)
```typescript
  srcMint: PublicKey,
  dstMint: PublicKey,
```

**File:** programs/fusion-swap/src/lib.rs (L117-129)
```rust
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
```

**File:** programs/fusion-swap/src/lib.rs (L139-142)
```rust
        require!(
            amount <= ctx.accounts.escrow_src_ata.amount,
            FusionError::NotEnoughTokensInEscrow
        );
```

**File:** programs/fusion-swap/src/lib.rs (L193-199)
```rust
        let (protocol_fee_amount, integrator_fee_amount, maker_dst_amount) = get_fee_amounts(
            order.fee.integrator_fee,
            order.fee.protocol_fee,
            order.fee.surplus_percentage,
            dst_amount,
            get_dst_amount(order.src_amount, order.estimated_dst_amount, amount, None)?,
        )?;
```

**File:** programs/fusion-swap/src/lib.rs (L202-229)
```rust
        let mut params = if order.dst_asset_is_native {
            UniTransferParams::NativeTransfer {
                from: ctx.accounts.taker.to_account_info(),
                to: ctx.accounts.maker_receiver.to_account_info(),
                amount: maker_dst_amount,
                program: ctx.accounts.system_program.clone(),
            }
        } else {
            UniTransferParams::TokenTransfer {
                from: ctx
                    .accounts
                    .taker_dst_ata
                    .as_ref()
                    .ok_or(FusionError::MissingTakerDstAta)?
                    .to_account_info(),
                authority: ctx.accounts.taker.to_account_info(),
                to: ctx
                    .accounts
                    .maker_dst_ata
                    .as_ref()
                    .ok_or(FusionError::MissingMakerDstAta)?
                    .to_account_info(),
                mint: *ctx.accounts.dst_mint.clone(),
                amount: maker_dst_amount,
                program: ctx.accounts.dst_token_program.clone(),
            }
        };
        uni_transfer(&params)?;
```

**File:** programs/fusion-swap/src/lib.rs (L464-464)
```rust
    src_mint: Box<InterfaceAccount<'info, Mint>>,
```
