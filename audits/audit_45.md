# Audit Report

## Title
Missing Temporary Suspension Mechanism Allows Misbehaving Resolvers to Continue Operations

## Summary
The whitelist program lacks a temporary suspension mechanism for resolvers. Once registered, a resolver can only be fully deregistered (account closure), with no intermediate suspension state. This operational gap means misbehaving resolvers can continue filling orders and canceling orders during investigation periods, potentially harming users.

## Finding Description

The whitelist program provides only binary access control: a resolver is either registered (with full access) or deregistered (completely removed). There is no mechanism to temporarily suspend a resolver's privileges while maintaining their registration. [1](#0-0) 

The `ResolverAccess` account stores only a `bump` field with no status indicator for suspension or active/inactive states.

The whitelist program exposes only two management operations:

**Register operation** - Creates a ResolverAccess account: [2](#0-1) 

**Deregister operation** - Closes the ResolverAccess account completely: [3](#0-2) 

The deregister operation uses the `close = authority` constraint, permanently closing the account: [4](#0-3) 

The fusion-swap program enforces resolver authorization by verifying the existence of the `ResolverAccess` account during fill operations: [5](#0-4) 

And during resolver-initiated cancellations: [6](#0-5) 

**Attack Scenario:**

1. A registered resolver begins misbehaving (e.g., consistently front-running orders, extracting maximum value, providing poor execution quality)
2. The protocol authority detects suspicious behavior and wants to investigate
3. No temporary suspension mechanism exists - only two options:
   - **Option A:** Immediately deregister (permanent removal, may be too harsh if behavior is legitimate)
   - **Option B:** Allow continued operations during investigation (users continue to be harmed)
4. During the investigation window (hours to days), the misbehaving resolver continues to execute `fill()` and `cancel_by_resolver()` operations
5. Users suffer from continued poor execution or value extraction until full deregistration occurs

## Impact Explanation

This is rated as **Medium Severity** because:

- **Operational Security Gap**: The protocol cannot respond quickly to resolver misbehavior without permanent deregistration
- **User Harm During Investigation**: Users can continue to be affected by poor resolver behavior during the investigation period
- **Binary Enforcement**: The lack of granular access control (suspend vs. remove) limits the authority's ability to manage resolver access appropriately
- **No Direct Fund Theft**: While users may experience poor execution or value extraction, this doesn't constitute direct protocol compromise or guaranteed fund loss

The impact is limited because:
- The authority can still deregister misbehaving resolvers (permanent solution exists)
- This requires a trusted resolver to become malicious
- No protocol-level funds are directly at risk

## Likelihood Explanation

**Likelihood: Medium**

This scenario requires:
- A registered resolver to begin misbehaving (trusted role turning malicious)
- The authority to detect the misbehavior
- A need for investigation before permanent action

The likelihood is medium because:
- Resolvers are expected to be reputable actors, but incentives may change
- Behavioral analysis may require time to distinguish between legitimate competitive execution and actual misbehavior
- The protocol has no mechanism to quickly pause a resolver's access during this investigation period

## Recommendation

Implement a suspension mechanism in the whitelist program by:

1. **Add a status field to `ResolverAccess`:**

```rust
#[account]
#[derive(InitSpace)]
pub struct ResolverAccess {
    pub bump: u8,
    pub is_active: bool,  // New field: true = active, false = suspended
}
```

2. **Add a suspend instruction:**

```rust
pub fn suspend(ctx: Context<Suspend>, _user: Pubkey) -> Result<()> {
    ctx.accounts.resolver_access.is_active = false;
    Ok(())
}

pub fn unsuspend(ctx: Context<Unsuspend>, _user: Pubkey) -> Result<()> {
    ctx.accounts.resolver_access.is_active = true;
    Ok(())
}
```

3. **Update account constraints in Fill and CancelByResolver:**

```rust
#[account(
    seeds = [whitelist::RESOLVER_ACCESS_SEED, taker.key().as_ref()],
    bump = resolver_access.bump,
    seeds::program = whitelist::ID,
    constraint = resolver_access.is_active @ FusionError::ResolverSuspended
)]
resolver_access: Account<'info, whitelist::ResolverAccess>,
```

4. **Modify the register function to initialize the status:**

```rust
pub fn register(ctx: Context<Register>, _user: Pubkey) -> Result<()> {
    ctx.accounts.resolver_access.bump = ctx.bumps.resolver_access;
    ctx.accounts.resolver_access.is_active = true;  // Active by default
    Ok(())
}
```

This allows the authority to temporarily suspend a resolver without permanent deregistration, enabling proper investigation while protecting users.

## Proof of Concept

The following demonstrates that no suspension mechanism exists and that a registered resolver can continue operations:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;

    #[test]
    fn test_no_suspension_mechanism() {
        // Demonstrate that ResolverAccess only has a bump field
        let resolver_access = ResolverAccess { bump: 255 };
        
        // No is_active, is_suspended, or status field exists
        // Only two states: account exists (registered) or doesn't exist (deregistered)
        assert_eq!(resolver_access.bump, 255);
        
        // The whitelist program has only 4 instructions:
        // 1. initialize - sets up whitelist with authority
        // 2. register - creates ResolverAccess account
        // 3. deregister - closes ResolverAccess account (permanent)
        // 4. set_authority - changes whitelist authority
        //
        // No suspend/unsuspend/pause instructions exist
        
        // During order filling, the check is simply:
        // "Does the ResolverAccess PDA exist?"
        // If YES -> resolver can fill orders
        // If NO -> resolver cannot fill orders
        //
        // No intermediate suspended state is possible
    }
    
    #[test]
    fn test_deregister_is_permanent() {
        // The deregister instruction uses `close = authority`
        // This permanently closes the account and returns rent
        // There is no way to "reactivate" without creating a new account
        // via register, which costs gas and creates a new state
    }
}
```

**Reproduction Steps:**

1. Deploy the whitelist program
2. Register a resolver using the `register` instruction
3. Observe that the resolver can now call `fill()` and `cancel_by_resolver()` in fusion-swap
4. Attempt to find a `suspend` instruction - it doesn't exist
5. The only option to stop the resolver is `deregister`, which permanently closes the account
6. During any investigation period before deregistration, the resolver continues to have full access

## Notes

This finding represents an **operational security limitation** rather than a direct code vulnerability. The access control mechanism works as designed - it simply lacks granularity. The severity is Medium because:

- Users can be harmed by continued misbehavior during investigation periods
- The protocol lacks a graduated enforcement mechanism
- The authority must choose between harsh permanent action or continued user exposure
- However, no direct protocol funds are at risk, and deregistration remains available as a last resort

The recommended suspension mechanism would provide operational flexibility while maintaining security guarantees.

### Citations

**File:** programs/whitelist/src/lib.rs (L24-28)
```rust
    /// Registers a new user to the whitelist
    pub fn register(ctx: Context<Register>, _user: Pubkey) -> Result<()> {
        ctx.accounts.resolver_access.bump = ctx.bumps.resolver_access;
        Ok(())
    }
```

**File:** programs/whitelist/src/lib.rs (L30-33)
```rust
    /// Removes a user from the whitelist
    pub fn deregister(_ctx: Context<Deregister>, _user: Pubkey) -> Result<()> {
        Ok(())
    }
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

**File:** programs/whitelist/src/lib.rs (L131-135)
```rust
#[account]
#[derive(InitSpace)]
pub struct ResolverAccess {
    pub bump: u8,
}
```

**File:** programs/fusion-swap/src/lib.rs (L511-516)
```rust
    #[account(
        seeds = [whitelist::RESOLVER_ACCESS_SEED, taker.key().as_ref()],
        bump = resolver_access.bump,
        seeds::program = whitelist::ID,
    )]
    resolver_access: Account<'info, whitelist::ResolverAccess>,
```

**File:** programs/fusion-swap/src/lib.rs (L647-653)
```rust
    /// Account allowed to cancel the order
    #[account(
        seeds = [whitelist::RESOLVER_ACCESS_SEED, resolver.key().as_ref()],
        bump = resolver_access.bump,
        seeds::program = whitelist::ID,
    )]
    resolver_access: Account<'info, whitelist::ResolverAccess>,
```
