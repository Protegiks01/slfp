# Audit Report

## Title
Race Condition in Resolver Deregistration Allows Unauthorized Order Cancellation

## Summary
The `CancelByResolver` instruction validates resolver access by only checking that the `resolver_access` PDA exists, without verifying active authorization status. This creates a Time-of-Check-Time-of-Use (TOCTTOU) race condition between deregistration transaction submission and confirmation, allowing deregistered resolvers to extract cancellation premiums during the race window.

## Finding Description

The vulnerability stems from the access control model relying solely on account existence rather than an authorization status flag.

**CancelByResolver Validation:** The account validation only verifies PDA derivation and existence, with no check for active authorization status: [1](#0-0) 

**ResolverAccess Structure:** The account contains only a `bump` field with no status indicator to distinguish between active and deactivating resolvers: [2](#0-1) 

**Deregistration Mechanism:** The deregister function closes the account, but closure only takes effect when the transaction confirms: [3](#0-2) 

**Attack Scenario:**

1. Whitelist authority submits a `deregister` transaction to remove a misbehaving resolver
2. Transaction enters the mempool but hasn't confirmed yet
3. The resolver detects the pending deregistration via RPC monitoring
4. Resolver rapidly submits multiple `cancel_by_resolver` transactions with high priority fees targeting expired orders
5. If any resolver transactions confirm before the deregister transaction, they pass validation because the `resolver_access` account still exists
6. Resolver collects cancellation premiums calculated by the auction mechanism: [4](#0-3) 
7. Once deregister confirms and closes the account, subsequent attempts fail, but premiums have already been extracted

This breaks the access control invariant that only currently-authorized resolvers can perform privileged operations.

## Impact Explanation

**Severity: HIGH**

The vulnerability enables significant unauthorized access with concrete financial impact:

1. **Access Control Bypass:** Resolvers retain the ability to execute privileged operations (order cancellation) after authorization should have been revoked
2. **Financial Loss:** Malicious resolvers can extract cancellation premiums that should go to legitimate authorized resolvers or remain with makers
3. **Amplification Potential:** A single attacker can target multiple expired orders simultaneously during the race window
4. **Protocol Trust Degradation:** The whitelist mechanism designed to maintain resolver reputation becomes effectively bypassable

Severity is HIGH rather than CRITICAL because:
- Exploit window is time-limited (deregister submission to confirmation)
- Only affects already-expired orders eligible for resolver cancellation
- Premium amounts are bounded by the order's `max_cancellation_premium` configuration
- Requires initial legitimate registration (cannot be exploited by arbitrary actors)

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is highly likely to be exploited due to:

1. **Trivial Detection:** Pending deregister transactions are observable through:
   - Public RPC node subscriptions to account changes
   - Mempool monitoring via validator connections
   - On-chain program log monitoring

2. **Low Execution Complexity:** 
   - No cryptographic exploits required
   - Standard transaction submission with priority fees
   - Publicly available on-chain order data
   - Can be fully automated with simple monitoring bots

3. **Strong Economic Incentive:** 
   - Resolvers being deregistered are likely to maximize extraction before losing access
   - Premium values calculated proportionally to time since expiration can be substantial
   - Zero marginal cost to attempt (only transaction fees)

4. **Favorable Network Conditions:**
   - Network congestion extends the race window
   - Priority fee system allows attackers to increase confirmation probability
   - Multiple block slots between submission and confirmation provide exploitation time

5. **Repeated Opportunities:** Every resolver deregistration event creates a new exploitation window

## Recommendation

Implement a two-phase deactivation mechanism:

**Phase 1 - Deactivate:** Add an `is_active: bool` field to `ResolverAccess` and create a new instruction to set it to `false`. This change takes effect immediately upon confirmation.

**Phase 2 - Close:** After a safety period (e.g., 100 slots), call the existing deregister function to close the account and reclaim rent.

**Modified ResolverAccess:**
```rust
#[account]
#[derive(InitSpace)]
pub struct ResolverAccess {
    pub bump: u8,
    pub is_active: bool,  // Add this field
}
```

**Modified Validation in CancelByResolver and Fill:**
```rust
#[account(
    seeds = [whitelist::RESOLVER_ACCESS_SEED, resolver.key().as_ref()],
    bump = resolver_access.bump,
    seeds::program = whitelist::ID,
    constraint = resolver_access.is_active @ FusionError::ResolverNotActive  // Add this check
)]
resolver_access: Account<'info, whitelist::ResolverAccess>,
```

This ensures access revocation is atomic with transaction confirmation, eliminating the race window.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating an order with `max_cancellation_premium` set to a significant value
2. Waiting for order expiration
3. Having the whitelist authority submit a deregister transaction
4. Before deregister confirms, having the resolver submit `cancel_by_resolver` transactions
5. Observing that the resolver successfully collects the premium if their transaction confirms first

The test would need to simulate transaction ordering by controlling block confirmation sequencing, demonstrating that both the deregister and cancel_by_resolver transactions can independently succeed depending on confirmation order, with the resolver extracting value when winning the race.

**Notes**

The vulnerability exists because Solana's atomic execution guarantees apply within individual transactions, not across competing transactions from different actors. The protocol's access control model conflates account existence with authorization status, creating a TOCTTOU vulnerability during the account closure process. A resolver being deregistered should be treated as an untrusted actor attempting to extract maximum value before access termination, not as a "reputable resolver" (which is precisely why deregistration was initiated).

### Citations

**File:** programs/fusion-swap/src/lib.rs (L403-411)
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

**File:** programs/fusion-swap/src/lib.rs (L648-653)
```rust
    #[account(
        seeds = [whitelist::RESOLVER_ACCESS_SEED, resolver.key().as_ref()],
        bump = resolver_access.bump,
        seeds::program = whitelist::ID,
    )]
    resolver_access: Account<'info, whitelist::ResolverAccess>,
```

**File:** programs/whitelist/src/lib.rs (L100-106)
```rust
    #[account(
        mut,
        close = authority,
        seeds = [RESOLVER_ACCESS_SEED, user.key().as_ref()],
        bump,
    )]
    pub resolver_access: Account<'info, ResolverAccess>,
```

**File:** programs/whitelist/src/lib.rs (L133-134)
```rust
pub struct ResolverAccess {
    pub bump: u8,
```
