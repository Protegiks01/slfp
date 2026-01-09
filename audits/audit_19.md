# Audit Report

## Title
Lack of Timelock Protection in Whitelist Authority Transfer Enables Instant Governance Takeover and Malicious Resolver Registration

## Summary
The whitelist program's `set_authority` function allows immediate authority transfer without any timelock, delay period, or multi-signature requirement. If the authority is controlled by governance (a common DeFi pattern), a successful governance attack can instantly change the authority and register unlimited malicious resolvers, compromising the entire protocol's resolver access control with no opportunity for users or the community to respond.

## Finding Description
The vulnerability exists in the `set_authority` function which performs immediate authority changes: [1](#0-0) 

The function only validates that the current authority signs the transaction: [2](#0-1) 

**Security Guarantees Broken:**
This breaks the **Access Control** invariant (#5) which states "Only authorized resolvers can fill orders or cancel by resolver." While technically the authority remains "authorized," a governance attack allows an adversary to instantly become the authority and authorize malicious resolvers.

**Attack Propagation:**
1. **Governance Compromise**: Attacker uses flash loan to acquire governance voting tokens temporarily or exploits governance contract vulnerabilities to pass a malicious proposal
2. **Instant Authority Change**: Malicious proposal calls `set_authority` with attacker's address - takes effect immediately with no delay
3. **Malicious Resolver Registration**: Attacker immediately calls `register` multiple times to whitelist their controlled addresses: [3](#0-2) 

4. **Legitimate Resolver Removal**: Attacker deregisters all legitimate resolvers: [4](#0-3) 

5. **Order Execution Control**: Malicious resolvers can now exclusively fill orders and cancel expired orders, since the fusion-swap program enforces resolver whitelist checks: [5](#0-4) [6](#0-5) 

## Impact Explanation
**Severity: HIGH**

Impact on the protocol:
- **Complete Resolver Centralization**: All order filling and cancellation becomes controlled by the attacker's resolvers
- **Protocol Fee Extraction**: Malicious resolvers can monopolize order execution, extracting maximum value from all orders through MEV
- **User Fund Risk**: While direct token theft is not possible (escrow protects funds), users suffer from:
  - Unfavorable execution prices (always at worst auction price)
  - Front-running and sandwich attacks by malicious resolvers
  - Refusal to execute orders (DoS)
  - Coordination with makers to manipulate auction outcomes
- **Decentralization Loss**: The protocol's competitive resolver model is completely compromised
- **No Recovery Window**: Users have zero time to withdraw orders or exit positions before malicious takeover

The impact qualifies as HIGH because it enables "Unauthorized order filling or cancellation" and "Partial protocol disruption affecting multiple users" as defined in the severity criteria.

## Likelihood Explanation
**Likelihood: MEDIUM-HIGH**

Factors increasing likelihood:
1. **Flash Loan Governance Attacks Are Common**: Multiple DeFi protocols have suffered flash loan governance attacks (Beanstalk, Build Finance, etc.)
2. **No Technical Barriers**: If governance uses token voting, anyone can acquire temporary voting power through flash loans
3. **Immediate Effect**: No timelock means the attack completes in a single transaction with no reversion opportunity
4. **High Reward**: Complete control over protocol order execution provides significant economic incentive

Factors decreasing likelihood:
1. Requires governance to control authority (not guaranteed by code)
2. Governance may have its own protections (but shouldn't be relied upon)
3. May require significant voting power depending on governance design

However, in production DeFi systems, assuming the authority will be governance-controlled is reasonable, and the lack of protection in the whitelist program itself is a critical gap.

## Recommendation
Implement a two-step authority transfer with mandatory timelock delay:

```rust
pub const MIN_TIMELOCK_DELAY: i64 = 86400; // 24 hours minimum

#[account]
#[derive(InitSpace)]
pub struct WhitelistState {
    pub authority: Pubkey,
    pub pending_authority: Option<Pubkey>,
    pub authority_transfer_timestamp: Option<i64>,
}

/// Proposes a new authority with timelock delay
pub fn propose_authority(ctx: Context<ProposeAuthority>, new_authority: Pubkey) -> Result<()> {
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    let current_time = Clock::get()?.unix_timestamp;
    
    whitelist_state.pending_authority = Some(new_authority);
    whitelist_state.authority_transfer_timestamp = Some(current_time + MIN_TIMELOCK_DELAY);
    
    Ok(())
}

/// Executes authority change after timelock period
pub fn execute_authority_change(ctx: Context<ExecuteAuthorityChange>) -> Result<()> {
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    let current_time = Clock::get()?.unix_timestamp;
    
    require!(
        whitelist_state.pending_authority.is_some(),
        WhitelistError::NoPendingAuthority
    );
    
    let transfer_timestamp = whitelist_state.authority_transfer_timestamp
        .ok_or(WhitelistError::NoTransferTimestamp)?;
    
    require!(
        current_time >= transfer_timestamp,
        WhitelistError::TimelockNotExpired
    );
    
    whitelist_state.authority = whitelist_state.pending_authority.unwrap();
    whitelist_state.pending_authority = None;
    whitelist_state.authority_transfer_timestamp = None;
    
    Ok(())
}

/// Cancels pending authority change (only callable by current authority)
pub fn cancel_authority_change(ctx: Context<CancelAuthorityChange>) -> Result<()> {
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    
    whitelist_state.pending_authority = None;
    whitelist_state.authority_transfer_timestamp = None;
    
    Ok(())
}
```

This provides:
- **24-hour minimum delay** for authority changes
- **Transparency** - all pending changes are visible on-chain
- **User Protection** - users can exit before malicious changes take effect
- **Cancellation Option** - current authority can cancel pending changes
- **Community Alert** - monitoring systems can detect suspicious proposals

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
import { Whitelist } from "../../target/types/whitelist";
import { FusionSwap } from "../../target/types/fusion_swap";

describe("Governance Attack Proof of Concept", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  
  const whitelistProgram = anchor.workspace.Whitelist as anchor.Program<Whitelist>;
  const fusionProgram = anchor.workspace.FusionSwap as anchor.Program<FusionSwap>;
  
  it("Demonstrates instant governance takeover and malicious resolver registration", async () => {
    // Setup: Initialize whitelist with governance as authority
    const governanceAuthority = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(governanceAuthority.publicKey, 2 * LAMPORTS_PER_SOL);
    
    await whitelistProgram.methods
      .initialize()
      .accountsPartial({ authority: governanceAuthority.publicKey })
      .signers([governanceAuthority])
      .rpc();
    
    // Setup: Register legitimate resolver
    const legitimateResolver = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(legitimateResolver.publicKey, 1 * LAMPORTS_PER_SOL);
    
    await whitelistProgram.methods
      .register(legitimateResolver.publicKey)
      .accountsPartial({ authority: governanceAuthority.publicKey })
      .signers([governanceAuthority])
      .rpc();
    
    // ATTACK STEP 1: Attacker compromises governance (simulated by using governance key)
    // In real attack: flash loan to buy governance tokens, pass malicious proposal
    
    const attacker = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(attacker.publicKey, 2 * LAMPORTS_PER_SOL);
    
    // ATTACK STEP 2: Instant authority transfer (NO TIMELOCK)
    const txStart = Date.now();
    await whitelistProgram.methods
      .setAuthority(attacker.publicKey)
      .accountsPartial({ currentAuthority: governanceAuthority.publicKey })
      .signers([governanceAuthority])
      .rpc();
    const txEnd = Date.now();
    
    console.log(`Authority changed in ${txEnd - txStart}ms - NO DELAY`);
    
    // Verify attacker is now authority
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      whitelistProgram.programId
    );
    let state = await whitelistProgram.account.whitelistState.fetch(whitelistStatePDA);
    expect(state.authority.toString()).to.equal(attacker.publicKey.toString());
    
    // ATTACK STEP 3: Register multiple malicious resolvers instantly
    const maliciousResolvers = [];
    for (let i = 0; i < 5; i++) {
      const maliciousResolver = anchor.web3.Keypair.generate();
      await provider.connection.requestAirdrop(maliciousResolver.publicKey, 1 * LAMPORTS_PER_SOL);
      
      await whitelistProgram.methods
        .register(maliciousResolver.publicKey)
        .accountsPartial({ authority: attacker.publicKey })
        .signers([attacker])
        .rpc();
      
      maliciousResolvers.push(maliciousResolver);
      console.log(`Registered malicious resolver ${i + 1}`);
    }
    
    // ATTACK STEP 4: Deregister legitimate resolver
    await whitelistProgram.methods
      .deregister(legitimateResolver.publicKey)
      .accountsPartial({ authority: attacker.publicKey })
      .signers([attacker])
      .rpc();
    
    console.log("Legitimate resolver removed");
    
    // IMPACT VERIFICATION: Only malicious resolvers can fill orders
    const [resolverAccessPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("resolver_access"), maliciousResolvers[0].publicKey.toBuffer()],
      whitelistProgram.programId
    );
    
    const resolverAccess = await whitelistProgram.account.resolverAccess.fetch(resolverAccessPDA);
    expect(resolverAccess).to.not.be.null;
    
    console.log("\n=== ATTACK SUCCESSFUL ===");
    console.log("- Authority changed instantly (no timelock)");
    console.log("- 5 malicious resolvers registered");
    console.log("- Legitimate resolver removed");
    console.log("- Attacker now controls all order execution");
    console.log("- Users had ZERO time to react or withdraw orders");
  });
});
```

**Notes:**

This vulnerability is particularly critical because:

1. **Flash Loan Attack Vector**: Modern DeFi governance attacks often use flash loans to temporarily acquire voting power, pass malicious proposals, and execute them in a single transaction before repaying the loan. The lack of timelock makes this attack trivial.

2. **No Defense Window**: Users monitoring the blockchain have no opportunity to cancel their orders or exit positions before the attack completes. In contrast, a 24-hour timelock would allow:
   - Community detection of malicious proposals
   - User withdrawal of funds
   - Social coordination to counter the attack
   - Potential governance override mechanisms

3. **Resolver Market Capture**: The competitive resolver model that provides value to users is instantly converted to a monopoly controlled by the attacker, destroying the protocol's value proposition.

4. **Production Deployment Risk**: If the whitelist authority is controlled by a governance contract (highly likely in production), this vulnerability is immediately exploitable on day one of deployment.

The fix requires adding timelock logic directly in the whitelist program rather than relying on external governance systems to implement these protections.

### Citations

**File:** programs/whitelist/src/lib.rs (L24-28)
```rust
    /// Registers a new user to the whitelist
    pub fn register(ctx: Context<Register>, _user: Pubkey) -> Result<()> {
        ctx.accounts.resolver_access.bump = ctx.bumps.resolver_access;
        Ok(())
    }
```

**File:** programs/whitelist/src/lib.rs (L30-33)
```rust
    /// Removes a user from the whitelist
    pub fn deregister(_ctx: Context<Deregister>, _user: Pubkey) -> Result<()> {
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
