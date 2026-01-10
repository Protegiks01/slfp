# Audit Report

## Title
Whitelist Initialization Front-Running Allows Complete Protocol Takeover

## Summary
The `initialize` instruction in the whitelist program lacks authorization checks, allowing any attacker to front-run the legitimate initialization transaction and permanently set themselves as the whitelist authority. This grants the attacker complete control over resolver registration, effectively allowing them to monopolize or completely disable the entire Fusion Swap protocol's order execution system.

## Finding Description

The whitelist program's `initialize` function is responsible for setting the authority that controls which resolvers can fill orders in the Fusion Swap protocol. However, this critical initialization function contains a severe vulnerability: **it has no validation whatsoever to restrict who can call it**. [1](#0-0) 

The function simply accepts any signer as the authority and stores their public key in the whitelist state. The `Initialize` account validation structure provides no constraints on who can be the authority: [2](#0-1) 

The authority account is merely marked as `Signer<'info>` with no additional constraints like `constraint = authority.key() == EXPECTED_AUTHORITY`. The PDA for the whitelist state is derived using only a constant seed: [3](#0-2) 

This makes the whitelist state address completely deterministic and publicly calculable. The `init` constraint on line 49 ensures the account can only be initialized once, meaning **the first caller permanently becomes the authority with no ability to override or reset**.

**Attack Flow:**

1. The 1inch team deploys the whitelist program to mainnet
2. An attacker monitors the blockchain for the program deployment
3. Before the legitimate team can initialize, the attacker submits their own `initialize` transaction with higher priority fees
4. The attacker's transaction executes first, setting `whitelist_state.authority = attacker.key()`
5. The legitimate initialization transaction from 1inch fails because the account already exists (Anchor's `init` constraint prevents re-initialization)
6. The attacker now permanently controls the whitelist authority

**Impact on Protocol Security:**

The whitelist authority has complete control over resolver registration through the `register` and `deregister` functions: [4](#0-3) [5](#0-4) 

Both functions enforce that only the current authority can register or deregister resolvers. This control is critical because the Fusion Swap protocol requires all order fillers to be whitelisted. The `fill` instruction validates this: [6](#0-5) 

Similarly, the `cancel_by_resolver` instruction also requires whitelist validation: [7](#0-6) 

Without a valid `resolver_access` PDA from the whitelist program, no one can fill orders or perform resolver-based cancellations. This means the attacker who controls the whitelist authority effectively controls the entire order execution system.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability results in complete protocol compromise with catastrophic consequences:

1. **Total Access Control Takeover**: The attacker becomes the permanent whitelist authority with absolutely no mechanism for the legitimate 1inch team to recover control. The `set_authority` function requires the current authority's signature, which the attacker now controls.

2. **Protocol Monopolization**: The attacker can whitelist only themselves (or their controlled addresses) as resolvers, monopolizing all order fills across the entire protocol. They can extract maximum value from every order by filling at the least favorable rates within the Dutch auction curve.

3. **Protocol Shutdown**: Alternatively, the attacker can deregister all legitimate resolvers and refuse to whitelist anyone, effectively shutting down the entire Fusion Swap protocol. All existing orders would become unfillable (except through maker cancellation), and no new orders could be executed.

4. **Permanent Damage**: Since there is no recovery mechanism and the whitelist state cannot be re-initialized due to Anchor's `init` constraint, the protocol would need to be completely redeployed with a new program ID. This would require:
   - Deploying new program versions
   - Migrating all users to the new program
   - Abandoning all infrastructure tied to the compromised program ID
   - Significant reputational damage and user trust loss

All users who create orders on the compromised deployment would be unable to have them filled by legitimate resolvers. The protocol becomes 100% non-functional, affecting every single user and rendering the entire deployed infrastructure worthless.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited for the following reasons:

1. **Public Knowledge**: Solana program deployments are entirely public and transparent. The program ID and all account addresses can be calculated by anyone monitoring the blockchain.

2. **Trivial Exploitation**: The attack requires only basic Solana development knowledge:
   - Calculate the deterministic whitelist state PDA
   - Construct a simple `initialize` transaction
   - Submit with adequate priority fees
   
   No sophisticated techniques, complex exploits, or deep protocol understanding is needed.

3. **No Technical Barriers**: The attacker needs only:
   - A Solana wallet with minimal SOL for transaction fees
   - Basic ability to construct and submit transactions
   - No special permissions, signatures, or access

4. **MEV Opportunity**: Even without explicitly malicious intent, MEV bots constantly scanning for front-running opportunities could inadvertently exploit this vulnerability, as initializing before the legitimate team provides economic control over protocol fees and operations.

5. **Critical Time Window**: There is an unavoidable window between program deployment and initialization during which the vulnerability is exploitable. On Solana, these are necessarily separate transactions, creating this exposure.

6. **High Economic Incentive**: The potential reward is enormous - complete control over a DeFi protocol that could handle significant trading volume. An attacker could either:
   - Extract maximum value by monopolizing order fills
   - Hold the protocol hostage for ransom
   - Cause maximum disruption to damage 1inch's reputation

The attack can be executed within minutes of observing the program deployment, making it a race condition that heavily favors attackers who are monitoring deployments.

## Recommendation

Implement proper authorization checks on the `initialize` function. There are several approaches:

**Option 1: Hardcode Expected Authority**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        mut,
        constraint = authority.key() == EXPECTED_AUTHORITY_PUBKEY @ WhitelistError::Unauthorized
    )]
    pub authority: Signer<'info>,
    // ... rest of accounts
}
```

**Option 2: Use Program Upgrade Authority**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key()),
        constraint = program_data.upgrade_authority_address == Some(authority.key()) @ WhitelistError::Unauthorized
    )]
    pub program: Program<'info, Whitelist>,
    
    /// CHECK: validated through constraint
    pub program_data: AccountInfo<'info>,
    
    // ... rest of accounts
}
```

**Option 3: Two-Step Initialization with Claim**
1. Deploy program with upgrade authority
2. Initialize with a temporary "unclaimed" state
3. Require the upgrade authority to "claim" ownership in a separate instruction
4. Only after claiming can the authority register resolvers

**Best Practice**: Use Option 2 (program upgrade authority) as it provides cryptographic proof that only the entity that deployed the program can initialize it, with no hardcoded addresses needed.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../../target/types/whitelist";
import { expect } from "chai";

describe("Whitelist Initialization Front-Running Attack", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Whitelist as Program<Whitelist>;
  
  it("Demonstrates front-running attack on initialize", async () => {
    // Attacker generates their own keypair
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund the attacker with some SOL
    const airdropSig = await provider.connection.requestAirdrop(
      attacker.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(airdropSig);

    // Calculate the deterministic whitelist state PDA (public knowledge)
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    // Attacker front-runs the legitimate initialization
    await program.methods
      .initialize()
      .accountsPartial({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([attacker])
      .rpc();

    // Verify the attacker is now the authority
    const whitelistState = await program.account.whitelistState.fetch(
      whitelistStatePDA
    );
    expect(whitelistState.authority.toString()).to.equal(
      attacker.publicKey.toString()
    );

    // Demonstrate the legitimate 1inch team can no longer initialize
    const legitimateAuthority = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      legitimateAuthority.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    
    try {
      await program.methods
        .initialize()
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
          whitelistState: whitelistStatePDA,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      // Should never reach here
      expect.fail("Legitimate initialization should have failed");
    } catch (error) {
      // Expected to fail because account already exists
      expect(error.toString()).to.include("already in use");
    }

    // Attacker can now control resolver registration
    const resolverToWhitelist = anchor.web3.Keypair.generate();
    
    // Attacker registers themselves as a resolver
    await program.methods
      .register(resolverToWhitelist.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();

    // Verify the resolver is registered
    const [resolverAccessPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), resolverToWhitelist.publicKey.toBuffer()],
      program.programId
    );
    
    const resolverAccess = await program.account.resolverAccess.fetch(
      resolverAccessPDA
    );
    expect(resolverAccess).to.not.be.null;

    // Legitimate authority cannot register resolvers
    const legitimateResolver = anchor.web3.Keypair.generate();
    
    try {
      await program.methods
        .register(legitimateResolver.publicKey)
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      expect.fail("Unauthorized registration should have failed");
    } catch (error) {
      expect(error.toString()).to.include("Unauthorized");
    }
  });
});
```

This proof of concept demonstrates:
1. An attacker can call `initialize` before the legitimate authority
2. The attacker becomes the permanent authority
3. Legitimate initialization attempts fail due to the account already existing
4. The attacker can register/deregister resolvers at will
5. The legitimate authority has no ability to register resolvers or recover control

## Notes

This vulnerability represents a fundamental flaw in the initialization pattern. Unlike some Solana programs that use upgrade authorities or multisigs for critical initialization, this implementation allows any arbitrary signer to become the permanent authority. The deterministic PDA derivation combined with the lack of authorization checks creates a race condition that strongly favors attackers, as they can monitor program deployments and submit initialization transactions immediately. The permanent nature of this compromise (due to Anchor's `init` constraint preventing re-initialization) means there is no recovery path other than complete protocol redeployment.

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
