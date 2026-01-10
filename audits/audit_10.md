# Audit Report

## Title
Unprotected Whitelist Initializer Enables Front-Running Attack and Permanent Authority Takeover

## Summary
The `initialize` function in the whitelist program lacks access control, allowing any attacker to front-run the legitimate initialization transaction during deployment and permanently seize control of the whitelist authority. This breaks the protocol's access control invariant and enables complete compromise of resolver permissions.

## Finding Description

The whitelist program's `initialize` function has no access control constraints, allowing any signer to call it and become the authority. [1](#0-0) 

The `Initialize` account validation struct only requires that the caller is a `Signer`, with no additional constraints on who can call this critical initialization function. [2](#0-1) 

The whitelist state PDA is deterministic, derived from a constant seed `WHITELIST_STATE_SEED` (defined as `b"whitelist_state"`) with no additional parameters. [3](#0-2) [4](#0-3) 

This creates a critical front-running vulnerability during deployment:

1. **Legitimate Deployment Attempt**: The 1inch team deploys the whitelist program and submits an `initialize` transaction to set up the whitelist with their authority
2. **Front-Running Attack**: A malicious actor monitoring the mempool detects the initialization transaction and submits their own `initialize` transaction with a higher priority fee
3. **Attacker Wins**: The attacker's transaction executes first, creating the whitelist_state PDA with the attacker set as authority [5](#0-4) 
4. **Legitimate Transaction Fails**: The legitimate initialization fails because Anchor's `init` constraint prevents reinitializing an already-initialized account [6](#0-5) 
5. **Permanent Takeover**: The attacker now controls all resolver registration/deregistration operations

The `register` and `deregister` functions both enforce that only the whitelist authority can execute them through constraint checks. [7](#0-6) [8](#0-7) 

The `set_authority` function requires the current authority to sign, providing no recovery mechanism once a malicious actor becomes the authority. [9](#0-8) [10](#0-9) 

This violates the protocol's critical access control invariant. According to the protocol whitepaper, "To participate in resolving Fusion swaps, a resolver's address must be authorized by going through KYC/KYB procedure." [11](#0-10)  An attacker controlling the whitelist authority can bypass this entirely, registering unauthorized resolvers or blocking legitimate ones.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables complete compromise of the protocol's resolver access control system:

- **Permanent Authority Hijacking**: The attacker gains permanent, irrevocable control of the whitelist authority through a one-time front-running attack during deployment
- **Resolver Access Manipulation**: The attacker can register malicious resolvers without KYC/KYB or deregister legitimate resolvers at will
- **Protocol Disruption**: All order filling operations depend on resolver whitelist status, so the attacker can selectively enable/disable order execution across the entire protocol
- **No Recovery Path**: Without redeploying the entire whitelist program and migrating all dependent contracts, there's no way to recover from this attack
- **Complete Access Control Bypass**: Breaks the fundamental security model where only authorized, KYC/KYB-verified resolvers can fill orders

The impact affects all users of the Fusion Protocol. A malicious authority could:
- Register themselves or colluding parties as resolvers to manipulate order execution and extract value
- Deregister all legitimate resolvers to halt protocol operations
- Hold the protocol hostage by demanding payment for control restoration
- Selectively approve resolvers to create unfair competitive advantages

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to succeed because:

1. **Easy to Execute**: Monitoring the mempool for initialization transactions is trivial using standard Solana RPC methods, and front-running with higher priority fees is a well-documented attack vector in Solana
2. **One-Time Critical Window**: The initialization only happens once during deployment, making it a critical vulnerability window that attackers will actively monitor for high-value protocols
3. **No Technical Barriers**: Any attacker with basic Solana knowledge can construct and submit an initialize transaction
4. **High Value Target**: Controlling the whitelist authority of a major DeFi protocol provides significant power and potential for profit extraction
5. **Public Deployment**: Program deployments are public and visible on-chain, making the initialization transaction easy to detect and front-run
6. **Deterministic PDA**: The whitelist state address is fully predictable [12](#0-11) , allowing attackers to prepare their front-running transaction in advance with the exact account addresses

The initialization script confirms this vulnerability is exploitable in practice, as it shows the standard deployment pattern without any front-running protections. [13](#0-12) 

## Recommendation

Implement access control on the `initialize` function to restrict who can call it. There are several secure approaches:

**Option 1: Require specific authority (recommended)**
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

**Option 2: Include authority in PDA seeds**
```rust
#[account(
    init,
    payer = authority,
    space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
    seeds = [WHITELIST_STATE_SEED, authority.key().as_ref()],
    bump,
)]
pub whitelist_state: Account<'info, WhitelistState>,
```

**Option 3: Two-step initialization**
Deploy the program with the upgrade authority, then have the upgrade authority call initialize before making the program immutable.

The recommended approach is Option 1, as it provides the clearest security guarantees and maintains the current PDA structure.

## Proof of Concept

```rust
// PoC demonstrating front-running vulnerability
// Add to tests/suits/whitelist.ts

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../../target/types/whitelist";
import { Keypair, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { findWhitelistStateAddress } from "../../scripts/utils";
import { expect } from "chai";

describe("Whitelist Front-Running PoC", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Whitelist as Program<Whitelist>;

  it("Attacker can front-run initialization", async () => {
    // Legitimate authority (1inch team)
    const legitimateAuthority = Keypair.generate();
    
    // Attacker
    const attacker = Keypair.generate();
    
    // Fund both accounts
    await provider.connection.requestAirdrop(
      legitimateAuthority.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    
    // Wait for airdrops
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const whitelistState = findWhitelistStateAddress(program.programId);
    
    // Attacker front-runs by calling initialize first
    await program.methods
      .initialize()
      .accounts({
        authority: attacker.publicKey,
        whitelistState,
      })
      .signers([attacker])
      .rpc();
    
    // Verify attacker is now the authority
    const whitelistStateAccount = await program.account.whitelistState.fetch(whitelistState);
    expect(whitelistStateAccount.authority.toBase58()).to.equal(attacker.publicKey.toBase58());
    
    // Legitimate initialization now fails
    try {
      await program.methods
        .initialize()
        .accounts({
          authority: legitimateAuthority.publicKey,
          whitelistState,
        })
        .signers([legitimateAuthority])
        .rpc();
      
      throw new Error("Should have failed - account already initialized");
    } catch (err) {
      // Expected to fail - account already initialized by attacker
      expect(err.toString()).to.include("already in use");
    }
    
    // Attacker now controls resolver registration
    const resolverToRegister = Keypair.generate().publicKey;
    const resolverAccessPda = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), resolverToRegister.toBuffer()],
      program.programId
    )[0];
    
    // Only attacker can register resolvers
    await program.methods
      .register(resolverToRegister)
      .accounts({
        authority: attacker.publicKey,
        whitelistState,
        resolverAccess: resolverAccessPda,
      })
      .signers([attacker])
      .rpc();
    
    console.log("✓ Attacker successfully took over whitelist authority");
    console.log("✓ Legitimate authority cannot initialize");
    console.log("✓ Attacker can now control all resolver registrations");
  });
});
```

## Notes

This vulnerability represents a critical deployment-time security issue that affects the entire protocol's security model. The lack of access control on the initializer is a well-known vulnerability pattern in blockchain smart contracts, and front-running during initialization is a documented attack vector in Solana and other blockchain ecosystems.

The vulnerability does NOT require the 1inch team or any trusted role to be compromised—rather, it exploits a race condition during the one-time deployment and initialization process. This clearly falls within the scope of untrusted actor attacks against the protocol.

The deterministic PDA derivation pattern used by the whitelist makes this attack particularly easy to execute, as attackers can prepare their transactions in advance with all necessary account addresses. The fix should be implemented before any mainnet deployment to prevent permanent loss of protocol control.

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

**File:** docs/whitepaper.md (L104-104)
```markdown
To participate in resolving Fusion swaps, a resolver’s address must be authorized by going through KYC/KYB procedure.
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
