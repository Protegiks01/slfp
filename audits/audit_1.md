# Audit Report

## Title
Asymmetric Fee Comparison Allows Order Creators to Avoid Surplus Fees, Causing Protocol Revenue Loss

## Summary
The `get_fee_amounts()` function contains an asymmetric comparison that allows malicious order creators to craft orders where surplus fees are never charged, even when the actual destination amount significantly exceeds the estimated amount. This results in direct protocol revenue loss. [1](#0-0) 

## Finding Description
The vulnerability exists in the surplus fee calculation logic within the `get_fee_amounts()` function. The function compares `actual_dst_amount` (which equals `dst_amount` minus base protocol and integrator fees) against `estimated_dst_amount` (which has no fees subtracted) to determine if surplus fees should be charged. [2](#0-1) 

This asymmetric comparison creates a gap equal to the base fee amounts. When an order is filled:

1. `dst_amount` is calculated from `min_dst_amount` with the Dutch auction rate bump applied
2. Base protocol and integrator fees are deducted from `dst_amount` to get `actual_dst_amount`
3. `actual_dst_amount` is compared to `estimated_dst_amount` (which has NO fees deducted)
4. Surplus fees only apply if `actual_dst_amount > estimated_dst_amount`

**The bug**: Even when `dst_amount > estimated_dst_amount` (which should trigger surplus fees), if `dst_amount - base_fees < estimated_dst_amount`, no surplus fee is charged.

A malicious order creator can exploit this by:
1. Setting `estimated_dst_amount` slightly above `min_dst_amount` (e.g., 5% higher)
2. Setting high base fee percentages (protocol_fee + integrator_fee ≥ 3%)
3. This ensures that across most auction rates, `(dst_amount - base_fees) < estimated_dst_amount`, preventing surplus fees

**Concrete Example:**
- Order parameters:
  - `min_dst_amount = 1000`
  - `estimated_dst_amount = 1050` (5% above min)
  - `protocol_fee = 1.5%` (1500 basis points)
  - `integrator_fee = 1.5%` (1500 basis points)
  - `surplus_percentage = 50%`

- Resolver fills when auction rate_bump = 8%:
  - `dst_amount = 1000 × 1.08 = 1080`
  - `protocol_fee_amount = 1080 × 0.015 = 16.2`
  - `integrator_fee_amount = 1080 × 0.015 = 16.2`
  - `actual_dst_amount = 1080 - 16.2 - 16.2 = 1047.6`
  - Comparison: Is `1047.6 > 1050`? **NO**
  - **Result: No surplus fee charged despite dst_amount being 30 tokens (2.9%) above estimated**

If the comparison were symmetric (comparing `dst_amount` vs `estimated_dst_amount` or properly accounting for fees on both sides):
- `1080 > 1050` → Surplus of 30 tokens
- Surplus fee = `30 × 0.5 = 15 tokens` should go to protocol
- Instead, protocol loses this 15 token surplus fee revenue

## Impact Explanation
**Severity: HIGH** - Significant protocol fee loss

This vulnerability causes direct financial harm to the protocol by allowing order creators to systematically avoid surplus fees. The impact includes:

1. **Direct Revenue Loss**: Protocol loses surplus fee revenue on every maliciously crafted order that gets filled above the estimated rate
2. **Systematic Exploitation**: Any order creator can exploit this by simply choosing appropriate fee parameters
3. **Cumulative Damage**: Over many orders, the lost revenue compounds significantly
4. **Economic Model Disruption**: The surplus fee mechanism is designed to capture value when orders execute better than expected; this vulnerability breaks that incentive model

The vulnerability breaks **Invariant #6: Fee Correctness** - "Fee calculations must be accurate and funds distributed correctly."

## Likelihood Explanation
**Likelihood: HIGH**

The exploitation requirements are minimal:
1. **No special privileges required**: Any user can create orders with arbitrary fee parameters
2. **Simple to exploit**: Attacker only needs to understand the comparison logic and set parameters accordingly
3. **No timing complexity**: Unlike other auction manipulation attacks, this works across a range of fill times
4. **Financially motivated**: Order creators are directly incentivized to maximize their returns by avoiding fees
5. **Easy to discover**: The asymmetric comparison is visible in the source code

The attack is profitable for order creators whenever:
- They expect their order to be filled above the estimated rate (common in volatile markets)
- They can set base fee percentages high enough to create the comparison gap
- The saved surplus fees exceed any downside from higher base fees (which they would pay anyway)

## Recommendation

**Fix the asymmetric comparison** by ensuring both sides of the comparison are on the same basis. The correct approach is to compare `dst_amount` directly to `estimated_dst_amount` BEFORE subtracting base fees:

```rust
fn get_fee_amounts(
    integrator_fee: u16,
    protocol_fee: u16,
    surplus_percentage: u8,
    dst_amount: u64,
    estimated_dst_amount: u64,
) -> Result<(u64, u64, u64)> {
    let integrator_fee_amount = dst_amount
        .mul_div_floor(integrator_fee as u64, BASE_1E5)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut protocol_fee_amount = dst_amount
        .mul_div_floor(protocol_fee as u64, BASE_1E5)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // FIX: Compare dst_amount to estimated_dst_amount directly
    // before subtracting any fees
    if dst_amount > estimated_dst_amount {
        protocol_fee_amount += (dst_amount - estimated_dst_amount)
            .mul_div_floor(surplus_percentage as u64, BASE_1E2)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    Ok((
        protocol_fee_amount,
        integrator_fee_amount,
        dst_amount - integrator_fee_amount - protocol_fee_amount,
    ))
}
```

This ensures surplus fees are charged whenever the actual destination amount exceeds the estimated amount, regardless of base fee magnitudes.

## Proof of Concept

**Demonstration of the vulnerability:**

```rust
// Scenario: Malicious order designed to avoid surplus fees
// Order parameters:
const MIN_DST: u64 = 1_000_000; // 1000 tokens (6 decimals)
const ESTIMATED_DST: u64 = 1_050_000; // 1050 tokens (5% above min)
const PROTOCOL_FEE: u16 = 1500; // 1.5% (out of 100,000)
const INTEGRATOR_FEE: u16 = 1500; // 1.5% (out of 100,000)
const SURPLUS_PERCENTAGE: u8 = 50; // 50% (out of 100)

// Resolver fills when auction rate_bump = 8000 (8%)
// Calculation from get_dst_amount():
// dst_amount = MIN_DST * (BASE_1E5 + 8000) / BASE_1E5
//            = 1_000_000 * 108_000 / 100_000
//            = 1_080_000

const DST_AMOUNT: u64 = 1_080_000;

// Call get_fee_amounts() as it currently exists:
// 1. protocol_fee_amount = 1_080_000 * 1500 / 100_000 = 16_200
// 2. integrator_fee_amount = 1_080_000 * 1500 / 100_000 = 16_200
// 3. actual_dst_amount = 1_080_000 - 16_200 - 16_200 = 1_047_600
// 4. Is actual_dst_amount > ESTIMATED_DST?
//    Is 1_047_600 > 1_050_000? NO
// 5. No surplus fee charged
// 6. Final protocol fee = 16_200 (only base fee)

// Expected behavior (if comparison were correct):
// 1. Is DST_AMOUNT > ESTIMATED_DST?
//    Is 1_080_000 > 1_050_000? YES
// 2. Surplus = (1_080_000 - 1_050_000) * 50 / 100 = 15_000
// 3. Total protocol fee should be = 16_200 + 15_000 = 31_200
// 4. Protocol loses 15_000 tokens in revenue

// Result: Despite dst_amount being 2.9% (30_000 tokens) above 
// estimated, NO surplus fee is charged due to the asymmetric comparison.
// The maker receives 1_047_600 tokens instead of 1_032_600 if surplus 
// were properly charged, and the protocol loses 15_000 tokens.
```

**Execution steps to reproduce:**
1. Deploy the fusion-swap program
2. Create an order with `min_dst_amount = 1000`, `estimated_dst_amount = 1050`, `protocol_fee = 1.5%`, `integrator_fee = 1.5%`, `surplus_percentage = 50%`
3. Set up a Dutch auction with `initial_rate_bump` allowing fills around 8% above minimum
4. Have a resolver fill the order when `rate_bump ≈ 8000`
5. Observe that `dst_amount = 1080` but no surplus fee is charged
6. Verify protocol receives only `32.4` tokens (3% base fees) instead of `47.4` (base + surplus)
7. Confirm maker receives `1047.6` instead of the correct `1032.6`, representing a 15 token protocol loss

**Notes**

The vulnerability stems from comparing post-fee actual amounts against pre-fee estimated amounts. This creates an exploitable gap proportional to the base fee rates. While the protocol still receives base fees, it systematically loses surplus fee revenue that should be collected when orders execute better than estimated. The fix requires ensuring both sides of the comparison operate on the same basis—either both before fees or both after fees, with the former being the correct approach since `estimated_dst_amount` represents the maker's expectation of the gross amount they'll receive.

### Citations

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

**File:** programs/fusion-swap/src/lib.rs (L799-807)
```rust
    let actual_dst_amount = (dst_amount - protocol_fee_amount)
        .checked_sub(integrator_fee_amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    if actual_dst_amount > estimated_dst_amount {
        protocol_fee_amount += (actual_dst_amount - estimated_dst_amount)
            .mul_div_floor(surplus_percentage as u64, BASE_1E2)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
```
