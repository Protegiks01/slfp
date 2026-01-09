# Audit Report

## Title
Linear Cancellation Premium Enables Resolver Griefing Through Intentional Non-Fill Strategy

## Summary
The linear premium calculation in `calculate_premium` creates a perverse economic incentive where resolvers can profit more by intentionally avoiding profitable order fills and instead waiting for expiration to claim cancellation premiums. This breaks the auction fairness invariant and enables systematic griefing of maker orders. [1](#0-0) 

## Finding Description
The protocol implements a cancellation premium mechanism to incentivize resolvers to clean up expired orders. However, the linear premium formula creates an exploitable misalignment between filling incentives and cancellation incentives.

**The Vulnerability Chain:**

1. **Premium Calculation**: The `calculate_premium` function uses a simple linear interpolation that grows from 0 to `max_cancellation_premium` over `cancellation_auction_duration` after order expiration. [2](#0-1) 

2. **Cancellation Reward**: In `cancel_by_resolver`, resolvers receive the calculated premium as a reward for canceling expired orders, with the premium deducted from the maker's escrowed lamports. [3](#0-2) 

3. **No Profitability Check**: The code never validates whether the order was unprofitable to fill or whether the resolver attempted to fill it. Any expired order can be canceled for the premium. [4](#0-3) 

4. **High Premium Values**: Test data shows premiums can be set as high as 50% of the source amount, which can easily exceed potential fill profits. [5](#0-4) 

**Attack Scenario:**
- Maker creates order: Sell 100 USDC for minimum 90 SOL
- Dutch auction increases price from 90 to 100 SOL over 24 hours
- `max_cancellation_premium` = 10 SOL (to incentivize cleanup)
- `cancellation_auction_duration` = 1 hour
- At hour 23, auction price reaches 98 SOL, current market = 96 SOL
- Resolver could fill and earn: 98 - 96 = 2 SOL profit
- **Instead, resolver calculates**: Wait 1 hour for expiration, then 30 minutes into cancellation auction
- Premium at T+30min = (1800/3600) × 10 = 5 SOL
- **Resolver earns 5 SOL instead of 2 SOL by NOT filling the order**

**Broken Invariants:**
- **Auction Fairness** (Invariant #4): Dutch auctions should result in fills at market-clearing prices, but resolvers can game the system to avoid filling
- **Escrow Integrity** (Invariant #3): Escrowed tokens should be released only under valid conditions, but the premium mechanism creates conditions where valid fills are avoided

## Impact Explanation
**Medium Severity** - This vulnerability affects individual orders and causes systematic harm:

1. **Direct Maker Losses**: Makers lose their `max_cancellation_premium` (potentially significant SOL amounts) even when orders were profitable to fill

2. **Order Griefing**: Profitable orders fail to execute because resolvers have perverse incentives to wait rather than fill

3. **Market Inefficiency**: The protocol fails its core purpose of facilitating token swaps through competitive auctions

4. **Systematic Exploitation**: All orders with `max_cancellation_premium > fill_profit` near expiration are vulnerable

5. **No Protocol-Wide Drain**: Impact is limited to individual orders, not the entire protocol, preventing Critical severity classification

## Likelihood Explanation
**High Likelihood** of occurrence:

1. **Rational Economic Behavior**: Any profit-maximizing resolver will exploit this when `premium > fill_profit`, requiring no collusion or special access

2. **Common Scenario**: Orders becoming profitable near expiration is a normal occurrence in Dutch auctions as prices increase over time

3. **Easy Detection**: Resolvers can trivially calculate and compare fill profit vs. potential cancellation premium

4. **Low Barriers**: Only requires resolver whitelist access (expected for normal operation) and basic economic calculation

5. **Observable**: The test suite demonstrates premiums of 50% of order value are considered acceptable, making exploitation highly profitable [6](#0-5) 

## Recommendation
Implement a multi-faceted fix to realign incentives:

**1. Exponential Premium Growth**: Replace linear premium with exponential/quadratic growth to make early cancellation less profitable:
```rust
pub fn calculate_premium(
    timestamp: u32,
    auction_start_time: u32,
    auction_duration: u32,
    max_cancellation_premium: u64,
) -> u64 {
    if timestamp <= auction_start_time {
        return 0;
    }
    
    let time_elapsed = timestamp - auction_start_time;
    if time_elapsed >= auction_duration {
        return max_cancellation_premium;
    }
    
    // Quadratic growth: premium grows slowly at first, rapidly near end
    let progress = (time_elapsed as u128 * time_elapsed as u128) 
        / (auction_duration as u128 * auction_duration as u128);
    ((progress * max_cancellation_premium as u128) / 1u128) as u64
}
```

**2. Cap Maximum Premium**: Enforce reasonable limits on `max_cancellation_premium` during order creation:
```rust
// In create function
require!(
    order.fee.max_cancellation_premium <= order.src_amount / 20, // Max 5%
    FusionError::ExcessiveCancellationPremium
);
```

**3. Add Fill Attempt Tracking**: Require proof that fill was attempted or unprofitable before allowing cancellation, though this adds complexity.

**4. Competitive Cancellation**: The existing `reward_limit` parameter enables competition, but should be combined with exponential growth to be effective.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_resolver_profits_more_from_cancellation_than_fill() {
        // Scenario: Order becomes profitable 1 hour before expiration
        // Fill profit: 2 SOL
        // Max cancellation premium: 10 SOL
        // Cancellation auction: 1 hour (3600 seconds)
        
        let max_cancellation_premium = 10_000_000_000u64; // 10 SOL in lamports
        let expiration_time = 1000u32;
        let cancellation_auction_duration = 3600u32;
        
        // After 30 minutes into cancellation auction
        let cancel_timestamp = expiration_time + 1800;
        
        let premium = calculate_premium(
            cancel_timestamp,
            expiration_time,
            cancellation_auction_duration,
            max_cancellation_premium,
        );
        
        // Premium after 30 min = (1800/3600) * 10 SOL = 5 SOL
        assert_eq!(premium, 5_000_000_000u64); // 5 SOL
        
        // If fill profit was only 2 SOL, resolver profits 2.5x more by canceling
        let fill_profit = 2_000_000_000u64; // 2 SOL
        assert!(premium > fill_profit, "Cancellation is more profitable than filling");
        
        println!("Fill profit: {} lamports", fill_profit);
        println!("Cancellation premium: {} lamports", premium);
        println!("Resolver earns {}% more by canceling", 
                 ((premium - fill_profit) * 100) / fill_profit);
    }
    
    #[test]
    fn test_linear_premium_insufficient_early_deterrent() {
        let max_cancellation_premium = 10_000_000_000u64;
        let expiration_time = 1000u32;
        let cancellation_auction_duration = 3600u32;
        
        // Just 1 minute after expiration
        let early_cancel = expiration_time + 60;
        
        let premium = calculate_premium(
            early_cancel,
            expiration_time,
            cancellation_auction_duration,
            max_cancellation_premium,
        );
        
        // Premium after 1 min = (60/3600) * 10 SOL ≈ 0.167 SOL
        // This is very low, giving resolvers strong incentive to wait
        assert_eq!(premium, 166_666_666u64); // ~0.167 SOL
        assert!(premium < max_cancellation_premium / 50, 
                "Early premium is too low to deter waiting");
    }
}
```

**Reproduction Steps:**
1. Create an order with `max_cancellation_premium = 10 SOL` and `cancellation_auction_duration = 3600s`
2. Simulate order becoming profitable (e.g., 2 SOL profit) near expiration
3. Calculate that waiting for expiration + 30 minutes yields 5 SOL premium
4. Observe resolver rationally chooses to not fill and instead wait to cancel
5. Order expires unfilled, resolver claims 5 SOL premium, maker loses 5 SOL

**Notes:**
- The vulnerability is exacerbated when multiple resolvers collude or independently reach the same conclusion
- Even with competitive cancellation via `reward_limit`, if only one resolver is active, they can claim full premium
- The test suite confirms premiums up to 50% of order value are considered acceptable, making exploitation highly profitable in practice

### Citations

**File:** programs/fusion-swap/src/auction.rs (L56-72)
```rust
pub fn calculate_premium(
    timestamp: u32,
    auction_start_time: u32,
    auction_duration: u32,
    max_cancellation_premium: u64,
) -> u64 {
    if timestamp <= auction_start_time {
        return 0;
    }

    let time_elapsed = timestamp - auction_start_time;
    if time_elapsed >= auction_duration {
        return max_cancellation_premium;
    }

    (time_elapsed as u64 * max_cancellation_premium) / auction_duration as u64
}
```

**File:** programs/fusion-swap/src/lib.rs (L345-358)
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

**File:** tests/suits/cancel-by-resolver.ts (L18-22)
```typescript
  const defaultSrcAmount = new anchor.BN(1000000);
  const defaultMaxCancellationPremium = defaultSrcAmount
    .muln(50 * 100)
    .divn(100 * 100); // 50% from the srcAmount
  const defaultRewardLimit = defaultMaxCancellationPremium;
```

**File:** tests/suits/cancel-by-resolver.ts (L168-207)
```typescript
  it("Resolver can cancel the order at different points in the order time frame", async () => {
    const cancellationPoints = [10, 25, 50, 100].map(
      (percentage) =>
        state.defaultExpirationTime +
        (order.auctionDuration * (percentage * 100)) / (100 * 100)
    );
    for (const cancellationPoint of cancellationPoints) {
      const maxCancellationPremiums = [1, 2.5, 7.5].map(
        (percentage) => (tokenAccountRent * (percentage * 100)) / (100 * 100)
      );
      for (const maxCancellationPremium of maxCancellationPremiums) {
        await setCurrentTime(context, order.createTime);
        const escrow = await state.createEscrow({
          escrowProgram: program,
          payer,
          provider: banksClient,
          orderConfig: state.orderConfig({
            srcAmount: defaultSrcAmount,
            fee: {
              maxCancellationPremium: new anchor.BN(maxCancellationPremium),
            },
            cancellationAuctionDuration: order.auctionDuration,
          }),
        });

        const makerNativeBalanceBefore = (
          await provider.connection.getAccountInfo(
            state.alice.keypair.publicKey
          )
        ).lamports;
        const resolverNativeBalanceBefore = (
          await provider.connection.getAccountInfo(state.bob.keypair.publicKey)
        ).lamports;

        await setCurrentTime(context, cancellationPoint);

        const timeElapsed = cancellationPoint - state.defaultExpirationTime;
        const resolverPremium = Math.floor(
          (maxCancellationPremium * timeElapsed) / order.auctionDuration
        );
```
