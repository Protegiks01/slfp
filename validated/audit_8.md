# Audit Report

## Title
**Critical PDA Front-Running Vulnerability in Whitelist Initialization Enables Complete Protocol Access Control Takeover**

## Summary
The whitelist program's `initialize()` function uses a predictable PDA derived from a constant seed and lacks authorization constraints, allowing any attacker to front-run the legitimate initialization and permanently seize control of the resolver whitelist system, thereby controlling all order execution in the fusion protocol.

## Finding Description

The whitelist program contains a critical initialization vulnerability enabling complete access control takeover through three interconnected design flaws:

**1. Predictable PDA Derivation**

The `whitelist_state` PDA uses only a constant seed `"whitelist_state"` without any dynamic components like the deployer's pubkey or program upgrade authority. [1](#0-0) [2](#0-1) 

This deterministic derivation pattern is confirmed in the utility functions: [3](#0-2) 

**2. No Authorization Constraints**

The `initialize()` function accepts ANY signer as the authority without validation against expected deployer, program upgrade authority, or hardcoded pubkey: [4](#0-3) 

The `Initialize` struct confirms there are no authority validation constraints - the `authority` account only requires `Signer` without additional checks: [5](#0-4) 

**3. One-Time Initialization Lock**

The `init` constraint at line 49 ensures the account can only be initialized once, making any front-running attack permanent and irreversible.

**Attack Execution Path:**

1. Attacker monitors blockchain for whitelist program deployment (program ID: `5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S`)
2. Attacker computes the predictable PDA using constant seed
3. Attacker submits `initialize()` transaction with high priority fees
4. Attacker's transaction executes first, setting their pubkey as authority
5. Legitimate initialization fails with "account already initialized" error
6. Attacker permanently controls resolver registration

**Protocol-Wide Impact:**

The whitelist authority controls all resolver access, which is required for critical fusion-swap operations. The `Fill` instruction explicitly requires a valid `resolver_access` account: [6](#0-5) 

The `CancelByResolver` instruction has identical whitelist validation requirements: [7](#0-6) 

Only the whitelist authority can register resolvers through authority-gated operations: [8](#0-7) 

Deregistration is similarly authority-gated: [9](#0-8) 

Even the `set_authority` function requires the current authority's signature, preventing legitimate recovery: [10](#0-9) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables complete protocol compromise with catastrophic consequences:

1. **Total Access Control Takeover**: The attacker gains permanent, irrevocable authority over the whitelist system - the most privileged position in the protocol's security architecture. This control cannot be revoked without redeploying the entire program with a new program ID.

2. **Irreversible Without Redeployment**: Recovery requires redeploying both whitelist and fusion-swap programs, migrating all liquidity, coordinating with all integrators, and invalidating all existing orders. The operational cost and coordination complexity make this effectively a protocol-killing vulnerability.

3. **Protocol-Wide Operational Control**: All order filling and resolver-based cancellations depend on whitelisted resolvers. The attacker controls which entities can execute these core protocol functions.

4. **Economic Exploitation at Scale**: Attacker-controlled resolvers can:
   - Extract MEV from all order fills
   - Execute orders at manipulated prices
   - Selectively censor orders
   - Demand ransom payments for resolver authorization
   - Front-run legitimate resolvers

5. **Complete Lock-Out**: The legitimate 1inch team is permanently prevented from managing their own protocol's access control system.

This breaks the fundamental **Access Control** security invariant - unauthorized actors must not control protocol permissions. It also exploits **PDA Security** weaknesses where predictable PDA derivation enables account takeover.

## Likelihood Explanation

**Likelihood: HIGH**

The attack has extremely high probability due to multiple favorable factors:

1. **Zero Technical Barriers**: Any user with basic Solana/Anchor knowledge can execute this attack. The PDA computation and function call are trivial operations requiring no sophisticated techniques.

2. **Complete Public Information**: The program ID becomes publicly visible immediately upon deployment, providing attackers all necessary information to compute the PDA and prepare the attack.

3. **Massive Economic Incentive**: Complete control over a DeFi protocol's order execution infrastructure provides multi-million dollar incentive through MEV extraction, censorship power, and ransom opportunities.

4. **Reliable Transaction Ordering**: Solana's priority fee mechanism allows attackers to virtually guarantee their transaction processes before the legitimate initialization by paying higher fees.

5. **Unavoidable Attack Window**: The gap between program deployment and initialization is inherent to Solana's architecture and cannot be eliminated through operational procedures.

6. **Well-Known Attack Pattern**: Initialization front-running is a documented vulnerability class actively monitored by sophisticated attackers. Many actors scan for newly deployed programs to exploit such vulnerabilities.

## Recommendation

Implement authorization constraints in the `Initialize` struct to restrict initialization to the expected authority:

**Option 1: Use Program Upgrade Authority**
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

    /// CHECK: Verified against program data
    #[account(constraint = program.programdata_address()? == Some(program_data.key()))]
    pub program: Program<'info, Whitelist>,
    
    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()))]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}
```

**Option 2: Hardcode Expected Authority**
```rust
const EXPECTED_AUTHORITY: Pubkey = pubkey!("YourExpectedAuthorityPubkeyHere");

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        mut,
        constraint = authority.key() == EXPECTED_AUTHORITY @ WhitelistError::Unauthorized
    )]
    pub authority: Signer<'info>,
    
    // ... rest of accounts
}
```

**Option 3: Use Dynamic Seed Including Authority**
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
        seeds = [WHITELIST_STATE_SEED, authority.key().as_ref()],
        bump,
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    pub system_program: Program<'info, System>,
}
```

## Proof of Concept

Add this test to `tests/suits/whitelist.ts`:

```typescript
it("Attacker can front-run initialization and take control", async () => {
  // Simulate attacker generating their own keypair
  const attacker = anchor.web3.Keypair.generate();
  await provider.connection.requestAirdrop(
    attacker.publicKey,
    10 * LAMPORTS_PER_SOL
  );
  
  // Wait for airdrop confirmation
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Attacker computes the predictable PDA
  const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("whitelist_state")],
    program.programId
  );

  // Attacker initializes with themselves as authority
  await program.methods
    .initialize()
    .accountsPartial({
      authority: attacker.publicKey,
    })
    .signers([attacker])
    .rpc();

  // Verify attacker is now the authority
  const whitelistState = await program.account.whitelistState.fetch(
    whitelistStatePDA
  );
  expect(whitelistState.authority.toString()).to.equal(
    attacker.publicKey.toString()
  );

  // Legitimate authority cannot initialize anymore
  await expect(
    program.methods
      .initialize()
      .accountsPartial({
        authority: payer.publicKey,
      })
      .signers([payer])
      .rpc()
  ).to.be.rejected;

  // Attacker can now register their own malicious resolvers
  const maliciousResolver = anchor.web3.Keypair.generate();
  await program.methods
    .register(maliciousResolver.publicKey)
    .accountsPartial({
      authority: attacker.publicKey,
    })
    .signers([attacker])
    .rpc();

  // Legitimate authority cannot register resolvers
  const legitimateResolver = anchor.web3.Keypair.generate();
  await expect(
    program.methods
      .register(legitimateResolver.publicKey)
      .accountsPartial({
        authority: payer.publicKey,
      })
      .signers([payer])
      .rpc()
  ).to.be.rejectedWith("Error Code: Unauthorized");
});
```

## Notes

This vulnerability represents a critical flaw in the protocol's trust model initialization. While the 1inch protocol team is considered a trusted role, the vulnerability exists because the code does not enforce that trust relationship during the initialization phase. The attack does not require compromising the team's keys - it simply exploits the race condition inherent in Solana's deployment model where program deployment and initialization are separate operations.

The severity is elevated because:
1. The vulnerability exists in deployed code, not operational procedures
2. Standard Solana security practices exist to prevent this pattern
3. Recovery requires complete protocol redeployment with massive coordination costs
4. The attack is trivial to execute but devastating in impact

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

**File:** scripts/utils.ts (L126-132)
```typescript
export function findWhitelistStateAddress(programId: PublicKey): PublicKey {
  const [whitelistState] = PublicKey.findProgramAddressSync(
    [anchor.utils.bytes.utf8.encode("whitelist_state")],
    programId
  );

  return whitelistState;
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
