# Audit Report

## Title
Rent Extraction Attack via Repeated maker_dst_ata Initialization in fill()

## Summary
A malicious maker can repeatedly drain a taker's lamports by exploiting the `init_if_needed` constraint on `maker_dst_ata`. The taker pays rent (~0.002 SOL per initialization) to create the maker's destination token account, which the maker can then close to reclaim the rent. By closing and forcing re-initialization across multiple fills, the maker extracts lamports from the taker. [1](#0-0) 

## Finding Description
The vulnerability exists in the `Fill` account structure where `maker_dst_ata` is configured with `init_if_needed` and `payer = taker`. This breaks two critical security guarantees:

1. **Token Safety Invariant**: While the primary concern is token transfers, SOL (lamports) are being drained from the taker in an unintended economic attack.
2. **Fee Correctness Invariant**: The rent cost (~2,039,280 lamports or 0.00203928 SOL per initialization) acts as a hidden fee that the taker pays but the maker can reclaim, creating an unfair economic imbalance.

**Attack Propagation:**

When a taker calls `fill()` for an order where `dst_asset_is_native = false` (SPL token destination), the following occurs: [2](#0-1) 

The token transfer path uses `maker_dst_ata` which may not exist. Anchor's `init_if_needed` automatically creates it, charging the taker.

**Post-Fill Exploitation:**

After receiving tokens in `maker_dst_ata`, the maker controls this Associated Token Account (derived from their `maker_receiver` address). The maker can:
1. Transfer all tokens out of `maker_dst_ata` to another wallet
2. Close the `maker_dst_ata` using SPL Token program's `close_account` instruction
3. Receive the full rent refund (~0.002 SOL) to their wallet

**Repeated Attack:**

When the taker fills another order (partial fill of a large order, or a new order from the same maker), the closed `maker_dst_ata` no longer exists. The `init_if_needed` constraint triggers again, charging the taker another ~0.002 SOL to re-initialize the same account address.

## Impact Explanation
**Severity: MEDIUM** - Individual user fund loss through specific exploits.

**Quantified Impact:**
- Per attack cycle: Taker loses 0.00203928 SOL (~$0.20 at $100/SOL)
- Maker gains: 0.00203928 SOL (net, after minimal gas costs)
- For 100 orders filled: Taker loses ~0.2 SOL (~$20)
- For 1000 orders filled: Taker loses ~2 SOL (~$200)

**Affected Users:**
- All takers/resolvers who fill orders for SPL tokens (non-native destinations)
- Particularly impacts high-volume resolvers filling many orders
- Any taker interacting with malicious makers who exploit this

**Economic Harm:**
The attack creates a direct wealth transfer from takers to makers through rent extraction. This undermines the economic fairness of the protocol, as takers are unknowingly subsidizing account creation costs that makers can fully reclaim.

## Likelihood Explanation
**Likelihood: MEDIUM**

**Attacker Requirements:**
- Malicious maker must create orders (minimal cost: escrow rent + gas)
- Must wait for takers to fill orders
- Must perform close_account operations between fills
- Economically viable: pure profit from rent refunds

**Complexity: LOW**
- Attack is straightforward: create order → wait for fill → close ATA → repeat
- No sophisticated timing or complex transaction ordering required
- Uses standard SPL Token program operations
- Automatable with simple scripts

**Detection Difficulty: HIGH**
- Takers may not notice small rent charges (0.002 SOL) among transaction costs
- Appears as legitimate account initialization in transaction logs
- No obvious on-chain indicator distinguishing malicious from legitimate behavior

**Economic Viability:**
- Profitable for makers at any scale
- No upfront cost (rent is recoverable)
- Scales linearly with number of fills
- High-volume resolvers are attractive targets (more fills = more profit)

## Recommendation

**Solution: Remove `init_if_needed` and require pre-existing maker_dst_ata**

Modify the `maker_dst_ata` account constraint to remove `init_if_needed`:

```rust
/// Maker's ATA of dst_mint
#[account(
    mut,
    associated_token::mint = dst_mint,
    associated_token::authority = maker_receiver,
    associated_token::token_program = dst_token_program,
)]
maker_dst_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
```

**Implementation Changes:**

1. **Update Fill struct**: Remove `init_if_needed` and `payer = taker` constraints
2. **Update Create function**: Add requirement or documentation that makers must initialize their destination ATAs before creating orders
3. **Client-side validation**: Add checks in scripts to verify `maker_dst_ata` exists before order creation

**Benefits:**
- Eliminates rent extraction attack vector completely
- Shifts account creation responsibility to the appropriate party (maker)
- Reduces transaction costs for takers
- Aligns with SPL Token best practices (account owners should create their own accounts)

**Trade-offs:**
- Makers must perform one-time ATA initialization per token they wish to receive
- Slightly less convenient for first-time makers
- Requires order creation to fail if maker_dst_ata doesn't exist (clear error messaging needed)

## Proof of Concept

**Reproduction Steps:**

1. **Setup:**
   - Maker creates wallet with BONK ATA for receiving tokens
   - Maker creates Order #1: Selling 100 USDC for 1M BONK
   - Maker's BONK ATA exists and is funded with rent

2. **First Fill:**
   ```
   Taker calls fill(Order #1, amount: 50 USDC)
   → maker_dst_ata exists, no initialization cost
   → Transfer: 50 USDC (escrow → taker), 500K BONK (taker → maker ATA)
   → Success
   ```

3. **Maker Closes ATA:**
   ```
   Maker calls SPL Token: transfer(all BONK from maker_dst_ata to cold wallet)
   Maker calls SPL Token: close_account(maker_dst_ata, refund_to: maker_wallet)
   → Maker receives 2,039,280 lamports refund
   → maker_dst_ata no longer exists
   ```

4. **Second Fill (Attack Triggers):**
   ```
   Taker calls fill(Order #1, amount: 50 USDC)
   → maker_dst_ata doesn't exist
   → Anchor init_if_needed triggers
   → Taker pays 2,039,280 lamports to initialize maker_dst_ata
   → Transfer: 50 USDC (escrow → taker), 500K BONK (taker → maker ATA)
   → Success, but taker paid unnecessary rent
   ```

5. **Repeat:** Maker closes ATA again, cycle continues

**Expected vs Actual Behavior:**

| Scenario | Expected Cost to Taker | Actual Cost to Taker |
|----------|------------------------|---------------------|
| First fill (new ATA) | 0.002 SOL rent | 0.002 SOL rent ✓ |
| Second fill (existing ATA) | 0 SOL | 0 SOL ✓ |
| Second fill (closed ATA) | 0 SOL | **0.002 SOL rent** ✗ |

**Rust Test Pseudocode:**
```rust
#[tokio::test]
async fn test_rent_extraction_attack() {
    // Setup: Create maker, taker, token mints
    let maker = create_funded_keypair();
    let taker = create_funded_keypair();
    let usdc_mint = create_token_mint();
    let bonk_mint = create_token_mint();
    
    // Create order
    create_order(&maker, usdc_amount: 100, bonk_amount: 1_000_000);
    
    // First fill - measure taker balance
    let taker_balance_before = get_balance(&taker);
    fill_order(&taker, amount: 50);
    let taker_balance_after_1 = get_balance(&taker);
    let cost_1 = taker_balance_before - taker_balance_after_1;
    
    // Maker closes ATA
    let maker_dst_ata = get_associated_token_address(&maker, &bonk_mint);
    transfer_all_tokens(&maker_dst_ata, &maker_cold_wallet);
    close_account(&maker_dst_ata, &maker);
    
    // Second fill - measure cost again
    let taker_balance_before_2 = get_balance(&taker);
    fill_order(&taker, amount: 50);
    let taker_balance_after_2 = get_balance(&taker);
    let cost_2 = taker_balance_before_2 - taker_balance_after_2;
    
    // Verify rent extraction
    assert!(cost_2 > cost_1, "Taker paid rent again!");
    assert_eq!(cost_2 - cost_1, 2_039_280, "Rent extraction confirmed");
}
```

## Notes

This vulnerability specifically affects orders where `dst_asset_is_native = false` (SPL token destinations). Native SOL transfers bypass the `maker_dst_ata` entirely and transfer directly to `maker_receiver`, making them immune to this attack. [3](#0-2) 

The attack is economically rational for makers because:
- Gas costs for closing accounts are negligible (~5,000 lamports)
- Rent refund is substantial (2,039,280 lamports)
- Net profit per cycle: ~2,034,280 lamports (~$0.20)
- Scales with number of takers and orders filled

High-volume resolvers are particularly vulnerable as they may fill hundreds of orders per day, potentially losing significant amounts to this rent extraction attack if interacting with malicious makers.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L202-228)
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
```

**File:** programs/fusion-swap/src/lib.rs (L571-579)
```rust
    /// Maker's ATA of dst_mint
    #[account(
        init_if_needed,
        payer = taker,
        associated_token::mint = dst_mint,
        associated_token::authority = maker_receiver,
        associated_token::token_program = dst_token_program,
    )]
    maker_dst_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
```
