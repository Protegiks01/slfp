# Audit Report

## Title
Front-Running Vulnerability in Dutch Auction Fill Mechanism Enables MEV Extraction

## Summary
The fill transaction submission mechanism in `scripts/fusion-swap/fill.ts` lacks MEV protection, allowing malicious resolvers or validators to front-run profitable fill opportunities discovered by honest resolvers. The time-based Dutch auction pricing combined with unprotected transaction submission creates extractable MEV that undermines auction fairness.

## Finding Description
The Fusion Protocol implements Dutch auction-based order execution where prices improve for takers over time. [1](#0-0)  The auction pricing is calculated at transaction execution time using the blockchain timestamp, not at transaction submission time.

When a resolver identifies a profitable fill opportunity, they submit a transaction using standard `sendAndConfirmTransaction` with no MEV protection mechanisms. [2](#0-1)  The codebase contains no priority fee configuration, transaction ordering guarantees, or commit-reveal schemes to protect resolvers from front-running.

The fill instruction calculates the destination amount at execution time using the current timestamp: [3](#0-2)  This creates a race condition where multiple resolvers can compete for the same order, and the winner is determined by transaction ordering within the Solana validator's slot.

**Attack Flow:**
1. Honest Resolver A monitors orders and identifies Order X becomes profitable at timestamp T
2. Resolver A submits fill transaction to network (revealing the opportunity)
3. Malicious Resolver B or validator observes A's pending transaction
4. Resolver B submits competing fill transaction with higher priority fee
5. Validator processes B's transaction first (either due to higher fee or validator MEV extraction)
6. B successfully fills the order and captures the profit
7. A's transaction fails with `NotEnoughTokensInEscrow` error [4](#0-3) 
8. Resolver A wasted gas and computational resources discovering the opportunity

This breaks the **Auction Fairness** invariant which requires that "Dutch auction pricing must be deterministic and manipulation-resistant." While the pricing itself is deterministic, the lack of MEV protection makes the auction manipulable through transaction reordering.

## Impact Explanation
**Severity: Medium**

The vulnerability causes economic harm to honest resolvers without directly stealing protocol or maker funds:

- **Resolvers performing price discovery lose profits**: Resolvers who invest computational resources to identify profitable fills get front-run by free-riders with MEV infrastructure
- **Reduced resolver participation**: If honest resolvers consistently lose to front-runners, they may exit the system, reducing competition and potentially leading to worse execution prices for makers
- **Centralization risk**: Creates competitive advantage for resolvers with access to MEV infrastructure (Jito bundles, validator relationships), centralizing the resolver ecosystem
- **Wasted gas costs**: Honest resolvers pay transaction fees for failed fill attempts

The impact is **Medium** rather than High because:
- No direct theft from the protocol treasury or maker funds
- Makers still receive their intended amounts at the correct auction price
- The system continues to function, but with unfair competition dynamics

## Likelihood Explanation
**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low barrier to entry**: Any whitelisted resolver can monitor pending transactions and submit competing fills with higher priority fees
2. **Profitable incentive**: The attacker captures 100% of the profit margin that the original resolver discovered
3. **Existing MEV infrastructure**: Solana has established MEV infrastructure (Jito bundles) that makes exploitation straightforward
4. **No detection mechanism**: The protocol cannot distinguish between legitimate competition and malicious front-running
5. **Continuous opportunity**: Every profitable fill creates an MEV extraction opportunity

The combination of high profitability, low technical barrier, and existing infrastructure makes exploitation almost certain in production.

## Recommendation

Implement MEV protection mechanisms in the fill transaction submission:

**1. Add Priority Fee Support:**
```typescript
// In fill.ts, add compute unit price instruction
import { ComputeBudgetProgram } from "@solana/web3.js";

const priorityFeeIx = ComputeBudgetProgram.setComputeUnitPrice({
  microLamports: calculateDynamicPriorityFee(orderProfitability)
});

const tx = new Transaction()
  .add(priorityFeeIx)
  .add(fillIx);
```

**2. Implement Commit-Reveal Scheme:**
Add a two-phase fill process where resolvers commit to filling without revealing the order, then reveal after commitment period expires.

**3. Use Private Transaction Pools:**
Integrate with Jito Block Engine or similar services to submit transactions privately, preventing mempool observation.

**4. Add Resolver Reputation System:**
Penalize resolvers who frequently submit failing fill transactions (likely front-runners) and reward those with high success rates.

**5. Implement Fill Intent Mechanism:**
Allow resolvers to pre-register intent to fill with bonded stake, giving priority to first registrants within a time window.

## Proof of Concept

**Scenario**: Two resolvers compete to fill the same order

```typescript
// Setup: Order exists with Dutch auction improving over time
// Resolver A discovers profitability at time T
// Resolver B monitors and front-runs

// Resolver A's transaction
async function resolverA_fill() {
  const tx = new Transaction().add(fillIx);
  // Standard priority - will be delayed
  await sendAndConfirmTransaction(connection, tx, [resolverA]);
}

// Resolver B's front-running transaction
async function resolverB_frontrun() {
  // Observe Resolver A's pending transaction
  // Submit with higher priority fee
  const priorityFeeIx = ComputeBudgetProgram.setComputeUnitPrice({
    microLamports: 50000 // Higher than default
  });
  
  const tx = new Transaction()
    .add(priorityFeeIx)
    .add(fillIx);
    
  // This executes first due to higher priority
  await sendAndConfirmTransaction(connection, tx, [resolverB]);
}

// Result:
// - Resolver B's transaction executes first, fills order successfully
// - Resolver A's transaction fails with "Not enough tokens in escrow"
// - Resolver A wasted gas, Resolver B captured the profit
```

**Reproduction Steps:**
1. Create an order with Dutch auction starting in 1 hour
2. Wait until auction price makes filling profitable
3. Have Resolver A submit fill transaction with default priority
4. Have Resolver B monitor and submit competing fill with 2x priority fee
5. Observe Resolver B's transaction executes first
6. Resolver A receives transaction failure error

## Notes

While Solana's transaction model differs from Ethereum's mempool-based MEV, the fundamental front-running vulnerability remains. Validators can reorder transactions within their slots, and priority fees explicitly allow paying for transaction ordering preference. The lack of any MEV protection in the current implementation makes exploitation straightforward for sophisticated resolvers.

The vulnerability affects the resolver ecosystem's health rather than immediate protocol solvency, justifying the Medium severity rating. However, long-term centralization of resolvers toward MEV-capable actors could degrade the protocol's intended competitive auction dynamics and potentially harm maker execution quality.

### Citations

**File:** programs/fusion-swap/src/auction.rs (L17-24)
```rust
pub fn calculate_rate_bump(timestamp: u64, data: &AuctionData) -> u64 {
    if timestamp <= data.start_time as u64 {
        return data.initial_rate_bump as u64;
    }
    let auction_finish_time = data.start_time as u64 + data.duration as u64;
    if timestamp >= auction_finish_time {
        return 0;
    }
```

**File:** scripts/fusion-swap/fill.ts (L87-92)
```typescript
  const tx = new Transaction().add(fillIx);

  const signature = await sendAndConfirmTransaction(connection, tx, [
    takerKeypair,
  ]);
  console.log(`Transaction signature ${signature}`);
```

**File:** programs/fusion-swap/src/lib.rs (L186-191)
```rust
        let dst_amount = get_dst_amount(
            order.src_amount,
            order.min_dst_amount,
            amount,
            Some(&order.dutch_auction_data),
        )?;
```

**File:** programs/fusion-swap/src/error.rs (L13-14)
```rust
    #[msg("Not enough tokens in escrow")]
    NotEnoughTokensInEscrow,
```
