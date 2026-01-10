# Audit Report

## Title
Whitelist Initialization Front-Running Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize` function lacks access control, allowing any attacker to front-run the legitimate protocol initialization and permanently seize control of the entire resolver access control system through a PDA initialization race condition.

## Finding Description

The whitelist program contains a critical access control vulnerability in its initialization function. The `initialize` function sets up the whitelist state with an authority who controls all resolver registrations, but this function has zero restrictions on who can call it. [1](#0-0) 

The function accepts any `Signer` as the authority without validation: [2](#0-1) 

The whitelist state PDA is derived using only a predictable constant seed: [3](#0-2) [4](#0-3) 

This creates a race condition where anyone can calculate the PDA address in advance and call `initialize` before the protocol team. The Anchor `init` constraint ensures the account can only be initialized once, making any successful front-run permanent.

Once an attacker successfully initializes the whitelist, they become the authority and gain exclusive control over:

1. **Resolver Registration** - Protected by authority validation: [5](#0-4) 

2. **Resolver Deregistration** - Protected by authority validation: [6](#0-5) 

3. **Authority Transfer** - Protected by authority validation: [7](#0-6) 

The fusion-swap program critically depends on the whitelist for resolver authorization. The `fill` operation requires a valid `resolver_access` PDA: [8](#0-7) 

Similarly, the `cancel_by_resolver` operation also requires resolver access validation: [9](#0-8) 

By controlling the whitelist authority, an attacker effectively controls who can execute the core protocol operations (filling orders and canceling expired orders).

**Attack Execution:**
1. Monitor blockchain for whitelist program deployment (public information)
2. Calculate whitelist_state PDA: `findProgramAddress(["whitelist_state"], programId)`
3. Immediately submit `initialize()` transaction with attacker's keypair as signer
4. Transaction succeeds, attacker is permanently set as authority
5. Protocol team's initialization attempt fails (account already exists)
6. Attacker maintains permanent control unless they voluntarily transfer authority

## Impact Explanation

**High Severity** - This vulnerability enables complete protocol access control takeover with devastating consequences:

1. **Protocol Deployment DoS**: The legitimate protocol team permanently loses the ability to initialize the whitelist with the intended authority, completely blocking proper protocol deployment. Recovery requires redeploying all programs with new program IDs.

2. **Resolver Authorization Monopoly**: The attacker gains exclusive power to:
   - Register malicious resolvers who can manipulate order fills
   - Deregister legitimate resolvers to eliminate competition
   - Block new resolver registrations entirely
   - Monetize access by selling resolver slots
   - Extract value through extortion

3. **Protocol Security Model Compromise**: Since fusion-swap's core operations depend on whitelist validation, the attacker indirectly controls:
   - Which addresses can call `fill()` to execute orders
   - Which addresses can call `cancel_by_resolver()` to cancel expired orders
   - The entire trust model of the protocol

4. **Permanent Damage Without Recovery**: Without the attacker's cooperation to transfer authority, there is no recovery mechanism. The protocol team would need to:
   - Redeploy the entire program suite
   - Obtain new program IDs
   - Migrate all users and integrations
   - Rebuild trust in the system

5. **Ecosystem Trust Destruction**: Even if detected immediately, this vulnerability demonstrates a fundamental security flaw that would severely damage confidence in the protocol's security practices.

The severity is **High** (not Critical) because it doesn't directly enable token theft from existing escrows. However, it does enable complete disruption of protocol operations and forces expensive redeployment.

## Likelihood Explanation

**High Likelihood** - This attack is highly probable because:

1. **Trivial Technical Requirements**:
   - Monitor program deployments via public RPC endpoints
   - Calculate PDA using basic `findProgramAddress()` call
   - Submit standard transaction with sufficient priority fee
   - No special skills, insider access, or complex exploits needed

2. **Minimal Economic Cost**:
   - Transaction fees: ~0.002 SOL (~$0.40 at current prices)
   - Rent exemption: minimal lamports
   - No capital requirements or collateral needed

3. **Wide Attack Window**:
   - Vulnerability exists from program deployment until initialization
   - Typical deployment procedures may leave hours of exposure
   - Monitoring and reaction can be automated

4. **Strong Economic Incentives**:
   - Complete control over DEX protocol access control is extremely valuable
   - Can be monetized through extortion or selling access
   - Potential profit massively exceeds attack cost
   - Low risk of legal consequences in decentralized context

5. **Deterministic Success**:
   - If attacker's transaction confirms first, attack succeeds with 100% certainty
   - Priority fees and MEV infrastructure provide competitive advantages
   - No randomness or complex timing requirements

6. **Indistinguishable from Legitimate Use**:
   - Attacker's initialization transaction looks identical to legitimate one
   - No way to detect malicious intent before execution
   - By the time it's discovered, damage is permanent

The only defense is ensuring immediate initialization after deployment, but this creates operational risk and provides no guarantee against determined attackers using transaction prioritization mechanisms.

## Recommendation

Implement proper access control on the `initialize` function to prevent unauthorized initialization. The recommended approach is to verify that the signer is the program's upgrade authority:

```rust
use anchor_lang::prelude::*;

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Verify caller is the program upgrade authority
    let program_data = ctx.accounts.program_data.as_ref()
        .ok_or(WhitelistError::ProgramNotUpgradeable)?;
    
    require_keys_eq!(
        program_data.upgrade_authority_address
            .ok_or(WhitelistError::ProgramNotUpgradeable)?,
        ctx.accounts.authority.key(),
        WhitelistError::Unauthorized
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}

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

    /// The program account to verify upgrade authority
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key())
    )]
    pub program: Program<'info, System>,
    
    /// Program data account containing upgrade authority
    #[account()]
    pub program_data: Option<Account<'info, ProgramData>>,

    pub system_program: Program<'info, System>,
}
```

Alternative approaches:
1. **Multi-signature initialization**: Require multiple signers from known protocol team addresses
2. **Pre-initialized deployment**: Initialize the state in the same transaction as program deployment
3. **Time-locked initialization**: Only allow initialization within specific block range after deployment

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";
import { Keypair, PublicKey } from "@solana/web3.js";
import { expect } from "chai";

describe("Whitelist Front-Running Attack", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  
  const program = anchor.workspace.Whitelist as Program<Whitelist>;
  
  it("Attacker can front-run initialization and take control", async () => {
    // Attacker generates their own keypair
    const attackerKeypair = Keypair.generate();
    
    // Attacker calculates the predictable PDA
    const [whitelistState] = PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );
    
    // Fund attacker account
    const signature = await provider.connection.requestAirdrop(
      attackerKeypair.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(signature);
    
    // Attacker calls initialize with their own keypair
    await program.methods
      .initialize()
      .accounts({
        authority: attackerKeypair.publicKey,
        whitelistState: whitelistState,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([attackerKeypair])
      .rpc();
    
    // Verify attacker is now the authority
    const whitelistStateAccount = await program.account.whitelistState.fetch(
      whitelistState
    );
    expect(whitelistStateAccount.authority.toString()).to.equal(
      attackerKeypair.publicKey.toString()
    );
    
    // Protocol team tries to initialize (will fail)
    const protocolTeamKeypair = Keypair.generate();
    await provider.connection.requestAirdrop(
      protocolTeamKeypair.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    
    try {
      await program.methods
        .initialize()
        .accounts({
          authority: protocolTeamKeypair.publicKey,
          whitelistState: whitelistState,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([protocolTeamKeypair])
        .rpc();
      
      expect.fail("Protocol team initialization should have failed");
    } catch (error) {
      // Expected to fail - account already exists
      expect(error.toString()).to.include("already in use");
    }
    
    // Verify attacker still controls the whitelist
    const finalState = await program.account.whitelistState.fetch(whitelistState);
    expect(finalState.authority.toString()).to.equal(
      attackerKeypair.publicKey.toString()
    );
    
    console.log("✓ Attacker successfully front-ran initialization");
    console.log("✓ Attacker is now the permanent authority");
    console.log("✓ Protocol team cannot recover without redeployment");
  });
});
```

## Notes

This vulnerability represents a well-known class of Solana program vulnerabilities: **unprotected PDA initialization with predictable seeds**. Similar vulnerabilities have been found in other Solana protocols and are preventable with proper access control patterns.

The impact is particularly severe for the 1inch Fusion Protocol because:
1. The whitelist is the foundation of the protocol's security model
2. Resolvers must go through KYC/KYB (as documented in the whitepaper), but an attacker controlling the whitelist bypasses this entirely
3. The protocol cannot function without proper resolver authorization
4. Recovery requires complete redeployment with new program IDs

The attack is not theoretical - it can be executed trivially by any party monitoring Solana program deployments. The combination of high impact, high likelihood, and trivial execution complexity makes this a critical issue that must be addressed before mainnet deployment.

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

**File:** programs/whitelist/src/lib.rs (L44-46)
```rust
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
```

**File:** programs/whitelist/src/lib.rs (L48-54)
```rust
    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
        seeds = [WHITELIST_STATE_SEED],
        bump,
    )]
```

**File:** programs/whitelist/src/lib.rs (L66-71)
```rust
    #[account(
      seeds = [WHITELIST_STATE_SEED],
      bump,
      // Ensures only the whitelist authority can register new users
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
```

**File:** programs/whitelist/src/lib.rs (L92-97)
```rust
    #[account(
      seeds = [WHITELIST_STATE_SEED],
      bump,
      // Ensures only the whitelist authority can deregister users from the whitelist
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
```

**File:** programs/whitelist/src/lib.rs (L115-121)
```rust
    #[account(
        mut,
        seeds = [WHITELIST_STATE_SEED],
        bump,
        // Ensures only the current authority can set new authority
        constraint = whitelist_state.authority == current_authority.key() @ WhitelistError::Unauthorized
    )]
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
