# Audit Report

## Title
Unprotected Whitelist Initialization Enables Complete Access Control Takeover

## Summary
The whitelist program's `initialize` function lacks access control, allowing any attacker to front-run the legitimate initialization and become the whitelist authority. This grants complete control over resolver registration, breaking the protocol's fundamental access control mechanism.

## Finding Description

The whitelist program contains a critical initialization vulnerability where the `initialize()` function has no access control restrictions whatsoever. [1](#0-0) 

The `Initialize` account validation context only requires **any** signer but does not restrict who that signer can be. [2](#0-1)  The function simply takes whoever calls it as the authority and stores their public key.

The WhitelistState account stores the authority that controls all resolver registration operations. [3](#0-2) 

This authority is then properly enforced in critical operations like registering resolvers, [4](#0-3)  deregistering them, [5](#0-4)  and transferring authority. [6](#0-5) 

**Attack Scenario:**

1. Protocol team deploys the whitelist program to mainnet (program ID: `5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S`)
2. Attacker monitors the deployment and precomputes the deterministic WhitelistState PDA address using the seed `[WHITELIST_STATE_SEED]` [7](#0-6) 
3. Before the protocol can call `initialize()`, the attacker submits a transaction calling `initialize()` with their own keypair as the signer
4. The WhitelistState account is created at the canonical PDA with the attacker's public key as authority
5. When the protocol attempts to initialize, the transaction fails due to the Anchor `init` constraint - the account already exists
6. The attacker now controls the whitelist authority and can:
   - Register malicious resolvers who can fill orders at unfavorable prices
   - Deregister legitimate resolvers, preventing them from executing orders  
   - Transfer authority to confederates
   - Completely compromise the protocol's access control system

The fusion-swap program relies critically on whitelisted resolvers for order filling [8](#0-7)  and cancellation by resolver, [9](#0-8)  making this vulnerability critical to the entire protocol's security model.

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
6. **Known Attack Vector**: Front-running initialization is a well-documented vulnerability pattern in blockchain systems, particularly on networks without transaction ordering guarantees

The initialization script [10](#0-9)  implements no protection against this attack vector.

## Recommendation

Implement one of the following protection mechanisms:

**Option 1: Hardcode Expected Authority** (Recommended)
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Hardcode the expected authority address
    const EXPECTED_AUTHORITY: &str = "YOUR_AUTHORITY_PUBKEY_HERE";
    let expected_authority = Pubkey::from_str(EXPECTED_AUTHORITY)
        .map_err(|_| error!(WhitelistError::Unauthorized))?;
    
    require!(
        ctx.accounts.authority.key() == expected_authority,
        WhitelistError::Unauthorized
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: Add Authority Parameter with Signature Validation**
```rust
pub fn initialize(ctx: Context<Initialize>, expected_authority: Pubkey) -> Result<()> {
    require!(
        ctx.accounts.authority.key() == expected_authority,
        WhitelistError::Unauthorized
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = expected_authority;
    Ok(())
}
```

**Option 3: Atomic Deployment Pattern**
Deploy the program with the upgrade authority being the same as the intended whitelist authority, then immediately call initialize and revoke upgrade authority in a single atomic transaction bundle.

## Proof of Concept

**Note**: A compilable test demonstrating this vulnerability should be provided. The test should:
1. Deploy the whitelist program
2. Have an attacker account call `initialize()` before the legitimate authority
3. Verify the attacker controls the whitelist state
4. Show that the legitimate authority's initialization call fails
5. Demonstrate that the attacker can now register/deregister resolvers

The test can be added to the existing test suite by modifying the initialization sequence in `tests/suits/whitelist.ts` to demonstrate the front-running attack.

## Notes

This vulnerability represents a fundamental flaw in the program's initialization pattern. The deterministic nature of PDAs combined with the lack of access control on initialization creates a race condition that attackers can reliably exploit. The protocol's entire security model depends on proper whitelist authority control, making this a critical fix priority before mainnet deployment.

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

**File:** programs/fusion-swap/src/lib.rs (L648-653)
```rust
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
