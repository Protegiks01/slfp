# Audit Report

## Title
Permissionless Whitelist Initialization Allows Unauthorized Authority Takeover

## Summary
The whitelist program's `initialize()` function lacks authorization checks, allowing any actor to front-run the legitimate initialization and become the protocol authority. This grants complete control over resolver whitelisting, enabling monopolization of order filling, denial of service, or extortion attacks against the 1inch team.

## Finding Description

The whitelist program contains a critical access control vulnerability in its initialization mechanism. The `initialize()` function unconditionally sets the caller as the authority without any validation. [1](#0-0) 

The `Initialize` account struct accepts any `Signer<'info>` as the authority with no constraints on who can execute the initialization. [2](#0-1) 

The `whitelist_state` PDA is derived from a deterministic constant seed `[WHITELIST_STATE_SEED]`, making the address predictable to any potential attacker. [3](#0-2) 

The Anchor `init` constraint only prevents duplicate initialization - it does not restrict who can perform the initial call. This means whoever calls `initialize()` first becomes the permanent authority (unless transferred).

Once an attacker becomes the authority, they gain complete control over the `register()` function [4](#0-3) , the `deregister()` function [5](#0-4) , and the `set_authority()` function [6](#0-5) .

This authority control is critical because the fusion-swap program requires valid `resolver_access` accounts for order filling operations [7](#0-6)  and for resolver-initiated order cancellations [8](#0-7) .

**Attack Scenario:**
1. Attacker monitors for whitelist program deployment at address `5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S`
2. Attacker front-runs the legitimate initialization transaction with higher priority fees
3. Attacker becomes the authority and controls all resolver registration/deregistration
4. Attacker can: (a) whitelist only their own resolvers to monopolize order filling profits, (b) deny all resolver registrations to halt protocol operations, (c) demand ransom payment to transfer authority via `set_authority()`, or (d) charge fees for resolver whitelisting

## Impact Explanation

**Severity: HIGH**

This vulnerability breaks critical access control invariants by allowing unauthorized control over protocol resolver management. While the attacker cannot directly steal escrowed tokens, they gain complete control over who can participate in order filling and cancellation operations.

**Direct Impacts:**
- **Protocol Disruption**: Complete control over which resolvers can fill orders or cancel expired orders, effectively controlling protocol functionality
- **Economic Monopolization**: Attacker can whitelist only their own resolver addresses, capturing all order filling profits in a production environment
- **Extortion**: Attacker can demand payment to transfer authority to the legitimate 1inch team via the `set_authority()` function
- **Service Denial**: Can prevent protocol launch by refusing to whitelist any resolvers, making orders unfillable

The severity is HIGH (not CRITICAL) because:
- No direct theft of escrowed tokens is possible
- The 1inch team can mitigate by redeploying with a new program ID
- However, redeployment causes significant operational disruption, reputational damage, and delays

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is trivially exploitable with minimal barriers to execution:

- **Cost**: Approximately 0.001 SOL for rent-exempt account creation
- **Skill Required**: Basic knowledge of Solana transactions and mempool monitoring
- **Detection**: Program deployment events are publicly observable
- **Execution Complexity**: Single transaction with no special requirements

The attack requires only:
1. Monitoring for program deployment or initialization transactions
2. Submitting a competing transaction with higher priority fees to front-run
3. No special permissions, insider access, or complex coordination needed

Front-running initialization is a well-documented attack pattern across blockchain systems. The deterministic PDA derivation makes the target account address predictable before deployment.

**Important Note**: This is a **deployment-time vulnerability**. If the whitelist program has already been properly initialized by the 1inch team, the vulnerability window has closed (Anchor's `init` constraint prevents re-initialization). However, as a design vulnerability in the codebase, it represents a real security risk for initial deployment or any future redeployment scenarios.

## Recommendation

Implement one of the following mitigations:

**Option 1: Hardcode Authority (Recommended)**
```rust
pub const EXPECTED_AUTHORITY: Pubkey = pubkey!("AuthorityPublicKeyHere");

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

**Option 2: Use Upgrade Authority**
Validate that the initializer is the program upgrade authority by checking program data account.

**Option 3: Initialize in Deployment**
Include initialization as part of the deployment transaction in the same atomic bundle, ensuring proper authority is set before the program is publicly accessible.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";
import { Keypair, PublicKey } from "@solana/web3.js";
import { expect } from "chai";

describe("whitelist-initialization-vulnerability", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  
  const program = anchor.workspace.Whitelist as Program<Whitelist>;
  const attacker = Keypair.generate();

  it("Attacker can front-run initialization and become authority", async () => {
    // Airdrop SOL to attacker
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Find whitelist state PDA
    const [whitelistState] = PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    // Attacker calls initialize and becomes authority
    await program.methods
      .initialize()
      .accounts({
        authority: attacker.publicKey,
        whitelistState: whitelistState,
      })
      .signers([attacker])
      .rpc();

    // Verify attacker is now the authority
    const stateAccount = await program.account.whitelistState.fetch(whitelistState);
    expect(stateAccount.authority.toBase58()).to.equal(attacker.publicKey.toBase58());

    // Attacker now controls resolver registration
    const resolverToWhitelist = Keypair.generate().publicKey;
    const [resolverAccess] = PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), resolverToWhitelist.toBuffer()],
      program.programId
    );

    // Only attacker can register resolvers
    await program.methods
      .register(resolverToWhitelist)
      .accounts({
        authority: attacker.publicKey,
        whitelistState: whitelistState,
        resolverAccess: resolverAccess,
      })
      .signers([attacker])
      .rpc();

    console.log("✅ Attacker successfully took over whitelist authority");
    console.log("✅ Attacker can now control all resolver registrations");
  });
});
```

## Notes

This vulnerability is particularly critical because:

1. **Deterministic PDA**: The whitelist_state address is predictable from the constant seed, allowing attackers to prepare transactions in advance

2. **No Authority Validation**: Unlike the `register()`, `deregister()`, and `set_authority()` functions which all validate the authority, the `initialize()` function has zero authorization checks

3. **Protocol Dependency**: Both the `fill()` and `cancel_by_resolver()` instructions in fusion-swap require valid resolver_access accounts, making the whitelist program a critical dependency for protocol operations

4. **Time-Sensitive Window**: This vulnerability can only be exploited during the narrow window between program deployment and legitimate initialization, but the impact during that window is severe

5. **Mitigation Available**: The 1inch team can verify on-chain whether their whitelist program has been properly initialized before launching the protocol. If compromised, redeployment with a new program ID is possible but disruptive.

### Citations

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

**File:** programs/fusion-swap/src/lib.rs (L648-653)
```rust
    #[account(
        seeds = [whitelist::RESOLVER_ACCESS_SEED, resolver.key().as_ref()],
        bump = resolver_access.bump,
        seeds::program = whitelist::ID,
    )]
    resolver_access: Account<'info, whitelist::ResolverAccess>,
```
