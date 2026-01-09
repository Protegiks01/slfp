# Audit Report

## Title
Dutch Auction Timing Manipulation Enables Systematic Surplus Fee Evasion

## Summary
Resolvers can strategically delay order fills until the Dutch auction price drops below the estimated destination amount, completely avoiding surplus fees and extracting value that should be captured by the protocol. This breaks the fee correctness invariant and enables systematic protocol revenue loss across all orders with surplus fee configurations.

## Finding Description

The surplus fee mechanism is designed to capture a percentage of "positive slippage" when resolvers execute orders at better-than-estimated prices. However, the Dutch auction decreases `dst_amount` over time while comparing against a fixed `estimated_dst_amount`, creating an exploitable timing window. [1](#0-0) 

The surplus fee is only charged when `actual_dst_amount > estimated_dst_amount`. However, the `dst_amount` calculation applies a time-decaying rate bump from the Dutch auction: [2](#0-1) 

The `rate_bump` decreases linearly from `initial_rate_bump` to 0 over the auction duration: [3](#0-2) 

This creates a fundamental mismatch: the actual amount (with auction) decreases over time, but the estimated amount (without auction) stays constant: [4](#0-3) 

**Attack Path:**
1. Resolver monitors an order with `surplus_percentage > 0`
2. Calculates when `dst_amount` (with auction decay) will drop below `estimated_dst_amount`
3. Waits until that timestamp to fill the order
4. Surplus fee condition fails: `actual_dst_amount <= estimated_dst_amount`
5. Protocol receives only base protocol_fee, not the surplus fee
6. Resolver keeps additional value that should have been captured by protocol

## Impact Explanation

**HIGH Severity** - This vulnerability causes:

- **Systematic Protocol Revenue Loss**: Every order with surplus_percentage > 0 is exploitable
- **Incentive Misalignment**: Resolvers are rewarded for delaying fills, harming maker experience
- **Economic Impact**: With surplus_percentage typically 50%, protocol loses ~50% of positive slippage value
- **Widespread Exploitation**: Any resolver can exploit this with simple timing calculations

Example with realistic parameters:
- Order: 1000 USDC → SOL
- `min_dst_amount` = 9 SOL
- `estimated_dst_amount` = 10 SOL
- `surplus_percentage` = 50%
- `protocol_fee` = 0.1%

**Early fill (t=0)**: dst_amount = 11 SOL
- Base protocol fee: 0.011 SOL
- actual_dst_amount: 10.989 SOL
- Surplus: 10.989 - 10 = 0.989 SOL
- Surplus fee: 0.989 × 0.5 = 0.495 SOL
- **Total protocol fee: 0.506 SOL**

**Late fill (t=near_end)**: dst_amount = 9.5 SOL
- Base protocol fee: 0.0095 SOL
- actual_dst_amount: 9.49 SOL
- actual_dst_amount < estimated_dst_amount → no surplus
- **Total protocol fee: 0.0095 SOL**

**Protocol loss per order: ~0.49 SOL** (98% reduction in fee capture)

## Likelihood Explanation

**VERY HIGH** - Exploitation is:

- **Trivial**: Requires only timestamp monitoring and calculation
- **Profitable**: Resolvers directly benefit from fee avoidance
- **Systematic**: Applies to every order with Dutch auction + surplus fee
- **No special access required**: Any resolver can exploit
- **Undetectable**: Appears as normal late-auction fills
- **Rational behavior**: Economically incentivized for all resolvers

The attack requires no privileged access, complex setup, or collusion. Every rational resolver would exploit this to maximize profits.

## Recommendation

The fundamental issue is comparing auction-adjusted amounts against fixed estimated amounts. Fix by applying auction adjustments consistently to both sides of the comparison:

```rust
fn get_fee_amounts(
    integrator_fee: u16,
    protocol_fee: u16,
    surplus_percentage: u8,
    dst_amount: u64,
    estimated_dst_amount: u64,
    opt_data: Option<&AuctionData>,  // ADD: auction data
) -> Result<(u64, u64, u64)> {
    let integrator_fee_amount = dst_amount
        .mul_div_floor(integrator_fee as u64, BASE_1E5)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut protocol_fee_amount = dst_amount
        .mul_div_floor(protocol_fee as u64, BASE_1E5)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let actual_dst_amount = (dst_amount - protocol_fee_amount)
        .checked_sub(integrator_fee_amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // FIX: Apply same auction adjustment to estimated amount
    let adjusted_estimated = if let Some(data) = opt_data {
        let rate_bump = calculate_rate_bump(Clock::get()?.unix_timestamp as u64, data);
        estimated_dst_amount
            .mul_div_ceil(BASE_1E5 + rate_bump, BASE_1E5)
            .ok_or(ProgramError::ArithmeticOverflow)?
    } else {
        estimated_dst_amount
    };

    if actual_dst_amount > adjusted_estimated {
        protocol_fee_amount += (actual_dst_amount - adjusted_estimated)
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

Update the call site to pass auction data: [5](#0-4) 

Change to:
```rust
let (protocol_fee_amount, integrator_fee_amount, maker_dst_amount) = get_fee_amounts(
    order.fee.integrator_fee,
    order.fee.protocol_fee,
    order.fee.surplus_percentage,
    dst_amount,
    order.estimated_dst_amount,  // Use base estimated amount
    Some(&order.dutch_auction_data),  // Pass auction data for consistent comparison
)?;
```

This ensures surplus fees are calculated based on the resolver's ability to beat the auction-adjusted expected price at the current timestamp, not just the initial estimate.

## Proof of Concept

**Reproduction Steps:**

1. Create order with:
   - src_amount: 1,000,000,000 (1000 USDC with 6 decimals)
   - min_dst_amount: 9,000,000,000 (9 SOL with 9 decimals)
   - estimated_dst_amount: 10,000,000,000 (10 SOL)
   - surplus_percentage: 50
   - protocol_fee: 100 (0.1%)
   - Dutch auction with initial_rate_bump: 20000 (20% above min)

2. At t=0 (auction start):
   - rate_bump = 20000
   - dst_amount = 9 SOL × 1.2 = 10.8 SOL
   - actual_dst_amount ≈ 10.79 SOL (after base fees)
   - actual > estimated → surplus fee = (10.79 - 10) × 0.5 = 0.395 SOL
   - Total protocol fee: ~0.405 SOL

3. Wait until rate_bump decays to ~5000 (auction 75% complete)
   - dst_amount = 9 SOL × 1.05 = 9.45 SOL
   - actual_dst_amount ≈ 9.44 SOL (after base fees)
   - actual < estimated → NO surplus fee
   - Total protocol fee: ~0.009 SOL

4. Resolver fills at step 3, avoiding 0.396 SOL in surplus fees

**Expected Behavior:** Protocol should collect surplus fees when resolvers achieve better execution than auction-adjusted expectations.

**Actual Behavior:** Protocol loses surplus fees when resolvers time fills to exploit auction decay.

---

**Notes:**

The vulnerability stems from an architectural mismatch between the dynamic Dutch auction pricing and the static surplus fee comparison. The issue is not with individual calculations but with the interaction between these mechanisms. The recommended fix aligns both sides of the comparison to use auction-adjusted values, preserving the intended economic incentives while preventing timing-based fee evasion.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L186-199)
```rust
        let dst_amount = get_dst_amount(
            order.src_amount,
            order.min_dst_amount,
            amount,
            Some(&order.dutch_auction_data),
        )?;

        let (protocol_fee_amount, integrator_fee_amount, maker_dst_amount) = get_fee_amounts(
            order.fee.integrator_fee,
            order.fee.protocol_fee,
            order.fee.surplus_percentage,
            dst_amount,
            get_dst_amount(order.src_amount, order.estimated_dst_amount, amount, None)?,
        )?;
```

**File:** programs/fusion-swap/src/lib.rs (L775-780)
```rust
    if let Some(data) = opt_data {
        let rate_bump = calculate_rate_bump(Clock::get()?.unix_timestamp as u64, data);
        result = result
            .mul_div_ceil(BASE_1E5 + rate_bump, BASE_1E5)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
```

**File:** programs/fusion-swap/src/lib.rs (L803-807)
```rust
    if actual_dst_amount > estimated_dst_amount {
        protocol_fee_amount += (actual_dst_amount - estimated_dst_amount)
            .mul_div_floor(surplus_percentage as u64, BASE_1E2)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
```

**File:** programs/fusion-swap/src/auction.rs (L17-54)
```rust
pub fn calculate_rate_bump(timestamp: u64, data: &AuctionData) -> u64 {
    if timestamp <= data.start_time as u64 {
        return data.initial_rate_bump as u64;
    }
    let auction_finish_time = data.start_time as u64 + data.duration as u64;
    if timestamp >= auction_finish_time {
        return 0;
    }

    let mut current_rate_bump = data.initial_rate_bump as u64;
    let mut current_point_time = data.start_time as u64;

    for point_and_time_delta in data.points_and_time_deltas.iter() {
        let next_rate_bump = point_and_time_delta.rate_bump as u64;
        let point_time_delta = point_and_time_delta.time_delta as u64;
        let next_point_time = current_point_time + point_time_delta;

        if timestamp <= next_point_time {
            // Overflow is not possible because:
            // 1. current_point_time < timestamp <= next_point_time
            // 2. timestamp * rate_bump < 2^64
            // 3. point_time_delta != 0 as this would contradict point 1
            return ((timestamp - current_point_time) * next_rate_bump
                + (next_point_time - timestamp) * current_rate_bump)
                / point_time_delta;
        }

        current_rate_bump = next_rate_bump;
        current_point_time = next_point_time;
    }

    // Overflow is not possible because:
    // 1. timestamp < auction_finish_time
    // 2. rate_bump * timestamp < 2^64
    // 3. current_point_time < auction_finish_time as we know that current_point_time < timestamp
    current_rate_bump * (auction_finish_time - timestamp)
        / (auction_finish_time - current_point_time)
}
```
