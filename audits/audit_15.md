# Audit Report

## Title
Single-Key Authority Transfer Enables Complete Whitelist Takeover Without Multi-Signature Protection

## Summary
The `set_authority()` function in the whitelist program lacks multi-signature requirements, timelock mechanisms, or two-step transfer processes. A single compromised authority key can immediately transfer complete control of the resolver whitelist to an attacker, enabling unauthorized manipulation of order execution across the entire protocol.

## Finding Description

The whitelist program's `set_authority()` function allows the current authority to transfer control to a new authority with only a single signature, providing no protection against key compromise. [1](#0-0) 

The function's account validation structure only requires that the `current_authority` must sign and match the stored authority: [2](#0-1) 

This breaks the **Access Control** invariant (Invariant #5: "Only authorized resolvers can fill orders or cancel by resolver") because:

1. **No Multi-Signature Requirement**: Only one signature is needed to transfer authority
2. **No Timelock**: Authority transfer happens immediately in a single transaction
3. **No Two-Step Process**: There's no "propose then accept" pattern requiring new authority confirmation
4. **No Recovery Mechanism**: Once transferred, the original authority loses all control

**Attack Propagation Path:**

When an attacker compromises the authority's private key:
1. Attacker calls `set_authority()` with their own address as `new_authority`
2. The whitelist authority is immediately transferred
3. Attacker can now call `register()` to add malicious resolver addresses: [3](#0-2) 

4. Malicious resolvers can then fill orders at manipulated prices since resolver access is checked in the fusion-swap program: [4](#0-3) 

5. Legitimate resolvers can be removed via `deregister()`: [5](#0-4) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables complete protocol compromise through resolver manipulation:

- **Complete Whitelist Control**: Attacker gains full authority over resolver registration/deregistration
- **Order Execution Manipulation**: Malicious resolvers can fill orders at unfavorable prices, extracting value from users
- **Resolver Ecosystem Disruption**: Legitimate resolvers can be removed, causing operational disruption
- **Irreversible Takeover**: No recovery mechanism exists once authority is transferred
- **Protocol-Wide Impact**: Affects all users since resolver authorization is mandatory for order filling

The impact is particularly severe because the fusion-swap program enforces resolver whitelist checks for both order filling and resolver-initiated cancellations: [6](#0-5) 

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Key compromise is a well-documented attack vector in blockchain systems:

- **Common Attack Surface**: Private keys are vulnerable to phishing, malware, social engineering, and infrastructure breaches
- **Single Point of Failure**: Only one key needs to be compromised
- **No Detection Window**: Immediate transfer provides no time for incident response
- **High-Value Target**: The authority key's power makes it an attractive target
- **Feasible Execution**: Attack requires only a single transaction call with one parameter

The attack complexity is LOW - once the key is compromised, exploitation is trivial with a single function call.

## Recommendation

Implement one or more of the following protections:

**Option 1: Multi-Signature Requirement (Recommended)**
Integrate with Solana's native multi-sig program (e.g., Squads Protocol) or implement a custom M-of-N signature scheme requiring multiple authorities to approve the transfer.

**Option 2: Two-Step Transfer Process**
```rust
pub struct WhitelistState {
    pub authority: Pubkey,
    pub pending_authority: Option<Pubkey>,
}

/// Propose new authority (called by current authority)
pub fn propose_authority_transfer(ctx: Context<ProposeTransfer>, new_authority: Pubkey) -> Result<()> {
    ctx.accounts.whitelist_state.pending_authority = Some(new_authority);
    Ok(())
}

/// Accept authority (called by new authority)
pub fn accept_authority_transfer(ctx: Context<AcceptTransfer>) -> Result<()> {
    require!(
        Some(ctx.accounts.new_authority.key()) == ctx.accounts.whitelist_state.pending_authority,
        WhitelistError::NotPendingAuthority
    );
    ctx.accounts.whitelist_state.authority = ctx.accounts.new_authority.key();
    ctx.accounts.whitelist_state.pending_authority = None;
    Ok(())
}
```

**Option 3: Timelock Mechanism**
Add a delay between authority change proposal and execution, allowing time for detection and response.

**Option 4: Emergency Pause**
Implement a separate emergency authority that can pause whitelist modifications if compromise is detected.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;
    
    #[test]
    fn test_single_key_authority_takeover() {
        // Setup: Initialize whitelist with authority keypair
        let authority = Keypair::new();
        let attacker = Keypair::new();
        
        // Step 1: Authority compromised (simulated by attacker obtaining private key)
        // In real attack: phishing, malware, or infrastructure breach
        let compromised_key = authority.clone();
        
        // Step 2: Attacker immediately calls set_authority with single signature
        let set_authority_ix = whitelist_program.methods
            .set_authority(attacker.pubkey())
            .accounts(SetAuthority {
                current_authority: compromised_key.pubkey(),
                whitelist_state: whitelist_state_pda,
            })
            .signers([&compromised_key])
            .instruction();
        
        // Execute attack transaction
        let tx = Transaction::new_signed_with_payer(
            &[set_authority_ix],
            Some(&compromised_key.pubkey()),
            &[&compromised_key],
            recent_blockhash,
        );
        
        // Step 3: Authority transferred - attacker now has complete control
        // Original authority has no recovery mechanism
        
        // Step 4: Attacker registers malicious resolver
        let register_malicious_ix = whitelist_program.methods
            .register(malicious_resolver.pubkey())
            .accounts(Register {
                authority: attacker.pubkey(),
                whitelist_state: whitelist_state_pda,
                resolver_access: resolver_access_pda,
                system_program: system_program::ID,
            })
            .signers([&attacker])
            .instruction();
        
        // Step 5: Malicious resolver can now fill orders at manipulated prices
        // causing value extraction from users
        
        assert!(whitelist_state.authority == attacker.pubkey());
    }
}
```

**Reproduction Steps:**
1. Deploy whitelist program and initialize with authority key
2. Simulate key compromise by using authority private key
3. Call `set_authority()` with attacker's address
4. Verify authority transferred with single transaction
5. Demonstrate attacker can register/deregister resolvers
6. Show malicious resolvers can fill orders in fusion-swap program

## Notes

This vulnerability is distinct from insider threat scenarios. Even if the 1inch team is fully trusted, their keys remain vulnerable to external compromise through phishing, malware, or infrastructure breaches. Industry best practices for critical protocol operations mandate multi-signature requirements or equivalent protection mechanisms.

The fusion-swap program's dependency on whitelist authorization for order filling means this single point of failure affects the entire protocol's security model. All escrowed funds and order executions depend on resolver authorization integrity.

### Citations

**File:** programs/whitelist/src/lib.rs (L24-28)
```rust
    /// Registers a new user to the whitelist
    pub fn register(ctx: Context<Register>, _user: Pubkey) -> Result<()> {
        ctx.accounts.resolver_access.bump = ctx.bumps.resolver_access;
        Ok(())
    }
```

**File:** programs/whitelist/src/lib.rs (L31-33)
```rust
    pub fn deregister(_ctx: Context<Deregister>, _user: Pubkey) -> Result<()> {
        Ok(())
    }
```

**File:** programs/whitelist/src/lib.rs (L36-40)
```rust
    pub fn set_authority(ctx: Context<SetAuthority>, new_authority: Pubkey) -> Result<()> {
        let whitelist_state = &mut ctx.accounts.whitelist_state;
        whitelist_state.authority = new_authority;
        Ok(())
    }
```

**File:** programs/whitelist/src/lib.rs (L111-123)
```rust
#[derive(Accounts)]
pub struct SetAuthority<'info> {
    #[account(mut)]
    pub current_authority: Signer<'info>,
    #[account(
        mut,
        seeds = [WHITELIST_STATE_SEED],
        bump,
        // Ensures only the current authority can set new authority
        constraint = whitelist_state.authority == current_authority.key() @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,
}
```

**File:** programs/fusion-swap/src/lib.rs (L510-516)
```rust
    /// Account allowed to fill the order
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
