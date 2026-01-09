# Audit Report

## Title
Whitelist Initialization Front-Running Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize` function lacks access control, allowing any attacker to front-run the legitimate protocol initialization and permanently seize control of the entire resolver access control system. This constitutes a critical PDA griefing attack where the attacker becomes the authority by winning the initialization race.

## Finding Description

The whitelist program contains a fundamental access control vulnerability in its initialization logic. The `initialize` function is designed to set up the whitelist state with an authority who controls resolver registrations. However, this function has no restrictions on who can call it. [1](#0-0) 

The whitelist state PDA is derived using completely predictable seeds - just a constant string `"whitelist_state"`: [2](#0-1) [3](#0-2) 

This creates a race condition where anyone can calculate the PDA address in advance and call `initialize` before the legitimate protocol team does. The Anchor `init` constraint ensures the account can only be initialized once, making this a permanent takeover: [4](#0-3) 

Once an attacker calls `initialize`, they become the authority and gain exclusive control over:
- Registering new resolvers via the `register` function (protected by authority check at line 70)
- Deregistering existing resolvers via the `deregister` function (protected by authority check at line 96)  
- Changing the authority via `set_authority` (protected by authority check at line 120)

The fusion-swap program depends on the whitelist for resolver authorization. Both `fill` and `cancel_by_resolver` operations require a valid `resolver_access` PDA: [5](#0-4) [6](#0-5) 

By controlling the whitelist authority, the attacker effectively controls who can execute the core protocol operations.

**Attack Steps:**
1. Monitor blockchain for whitelist program deployment
2. Calculate whitelist_state PDA: `findProgramAddress(["whitelist_state"], programId)`
3. Immediately call `initialize()` with attacker's keypair as signer
4. Transaction succeeds, attacker is set as authority
5. When protocol team attempts initialization, transaction fails (account already exists)
6. Attacker maintains permanent control unless they voluntarily transfer authority

This breaks multiple critical invariants:
- **Access Control (Invariant #5)**: The attacker now decides which resolvers are authorized
- **Account Validation (Invariant #7)**: No validation prevents unauthorized initialization
- **PDA Security (Invariant #9)**: Predictable PDA seeds enable the griefing attack

## Impact Explanation

**High Severity** - This vulnerability enables complete protocol access control takeover with the following impacts:

1. **Protocol DoS**: The legitimate protocol team loses ability to initialize the whitelist with the intended authority, effectively blocking proper protocol deployment.

2. **Resolver Authorization Control**: The attacker gains exclusive power to:
   - Register malicious resolvers who can fill orders
   - Deregister legitimate resolvers to disrupt operations
   - Prevent any competition by blocking new resolver registrations
   - Extract value by selling resolver access

3. **Protocol Integrity Compromise**: Since fusion-swap depends on whitelist for authorization, the attacker indirectly controls:
   - Which addresses can call `fill` to execute orders
   - Which addresses can call `cancel_by_resolver` to cancel orders
   - The entire security model of the protocol

4. **Permanent Damage**: Without the attacker's cooperation to transfer authority, the protocol team has no recovery mechanism. They would need to redeploy the entire program suite with a new program ID.

5. **Trust Destruction**: Even if detected early, this vulnerability demonstrates a fundamental security flaw that would severely damage user confidence.

The impact is **High** rather than Critical because it requires winning a deployment race and doesn't directly enable token theft, but it does enable complete disruption of protocol operations.

## Likelihood Explanation

**High Likelihood** - This attack is highly likely to succeed because:

1. **Trivial to Execute**: The attack requires no special skills beyond:
   - Monitoring program deployments (public information)
   - Calculating a PDA address (straightforward operation)
   - Submitting a transaction (basic blockchain interaction)

2. **Low Cost**: The attacker only needs:
   - Enough SOL for transaction fees and rent (~0.002 SOL)
   - No special privileges or insider access
   - No complex exploit chains

3. **Wide Attack Window**: The vulnerability exists from the moment the program is deployed until initialization completes. This could be minutes to hours depending on deployment procedures.

4. **High Attacker Motivation**: 
   - Complete control over a DEX protocol's access system is extremely valuable
   - Can be monetized through extortion or selling resolver slots
   - Minimal risk of detection before execution

5. **Deterministic Success**: If the attacker's transaction is confirmed before the legitimate one, the attack succeeds with 100% certainty due to the `init` constraint.

6. **No Detection**: The attacker's initialization transaction looks identical to a legitimate one, making it impossible to distinguish malicious intent until it's too late.

The only defense is ensuring the protocol team initializes immediately after deployment, but this creates operational risk and doesn't provide guaranteed protection against a determined attacker with transaction prioritization (e.g., higher fees, MEV bots).

## Recommendation

Implement access control on the `initialize` function to restrict it to a designated deployer address. There are several approaches:

**Option 1 - Hardcoded Authority (Recommended for Production)**:
Add a hardcoded authority check that must sign the initialization:

```rust
pub const EXPECTED_AUTHORITY: Pubkey = pubkey!("YOUR_PROTOCOL_AUTHORITY_PUBKEY");

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    require!(
        ctx.accounts.authority.key() == EXPECTED_AUTHORITY,
        WhitelistError::Unauthorized
    );
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2 - Upgrade Authority Check**:
Require that the program's upgrade authority signs the initialization:

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
    
    /// CHECK: Must be the program's upgrade authority
    pub program_data: Account<'info, ProgramData>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Verify authority is the upgrade authority
    require!(
        ctx.accounts.program_data.upgrade_authority_address == 
        Some(ctx.accounts.authority.key()),
        WhitelistError::Unauthorized
    );
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 3 - Two-Step Initialization**:
Use a program upgrade to switch from an initializable state to operational state after initialization is complete.

The recommended approach is **Option 1** for simplicity and security, ensuring only the known protocol authority can initialize the whitelist system.

## Proof of Concept

The following test demonstrates the vulnerability by showing an attacker can front-run initialization:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;
    use solana_program_test::*;
    use solana_sdk::{signature::Keypair, signer::Signer};

    #[tokio::test]
    async fn test_initialization_front_running() {
        let program_id = whitelist::ID;
        let mut program_test = ProgramTest::new(
            "whitelist",
            program_id,
            processor!(whitelist::entry),
        );

        let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

        // Legitimate protocol authority
        let legitimate_authority = Keypair::new();
        
        // Malicious attacker
        let attacker = Keypair::new();

        // Both can calculate the same PDA
        let (whitelist_state, _bump) = Pubkey::find_program_address(
            &[b"whitelist_state"],
            &program_id,
        );

        // Attacker initializes first (front-running)
        let attacker_init_ix = initialize(
            &program_id,
            &attacker.pubkey(),
            &whitelist_state,
        );

        let mut transaction = Transaction::new_with_payer(
            &[attacker_init_ix],
            Some(&payer.pubkey()),
        );
        transaction.sign(&[&payer, &attacker], recent_blockhash);
        
        // Attacker's initialization succeeds
        banks_client.process_transaction(transaction).await.unwrap();

        // Verify attacker is now the authority
        let whitelist_account = banks_client
            .get_account(whitelist_state)
            .await
            .unwrap()
            .unwrap();
        let whitelist_data: WhitelistState = 
            WhitelistState::try_deserialize(&mut whitelist_account.data.as_ref())
            .unwrap();
        assert_eq!(whitelist_data.authority, attacker.pubkey());

        // Legitimate protocol team tries to initialize
        let legitimate_init_ix = initialize(
            &program_id,
            &legitimate_authority.pubkey(),
            &whitelist_state,
        );

        let mut transaction = Transaction::new_with_payer(
            &[legitimate_init_ix],
            Some(&payer.pubkey()),
        );
        transaction.sign(&[&payer, &legitimate_authority], recent_blockhash);
        
        // Legitimate initialization FAILS - account already exists
        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_err()); // Fails due to account already initialized

        // Attacker maintains permanent control
        println!("Attack successful: Attacker controls whitelist authority");
    }
}
```

This PoC demonstrates:
1. Both attacker and legitimate authority can calculate the same PDA
2. Whoever calls `initialize` first becomes the authority
3. The second initialization attempt fails due to the `init` constraint
4. The attacker achieves permanent control with no recovery mechanism

## Notes

This vulnerability represents a fundamental flaw in the deployment security model. The PDA griefing occurs not through creating accounts at the PDA address (which isn't possible for non-program accounts), but through front-running the legitimate initialization call. The `init` constraint, while protecting against re-initialization, creates a first-come-first-served race condition that an attacker can exploit.

The impact extends beyond the whitelist program itself, as the fusion-swap program's resolver authorization system depends entirely on the whitelist program's integrity. Compromising the whitelist effectively compromises the entire protocol's access control system.

Immediate remediation is required before any production deployment to prevent an attacker from seizing control of the protocol's access control infrastructure.

### Citations

**File:** programs/whitelist/src/lib.rs (L9-9)
```rust
pub const WHITELIST_STATE_SEED: &[u8] = b"whitelist_state";
```

**File:** programs/whitelist/src/lib.rs (L18-22)
```rust
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let whitelist_state = &mut ctx.accounts.whitelist_state;
        whitelist_state.authority = ctx.accounts.authority.key();
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

**File:** programs/fusion-swap/src/lib.rs (L511-516)
```rust
    #[account(
        seeds = [whitelist::RESOLVER_ACCESS_SEED, taker.key().as_ref()],
        bump = resolver_access.bump,
        seeds::program = whitelist::ID,
    )]
    resolver_access: Account<'info, whitelist::ResolverAccess>,
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
