# Audit Report

## Title
Whitelist Initialization Front-Running Allows Complete Protocol Takeover

## Summary
The whitelist program's `initialize` instruction lacks authorization checks, allowing any attacker to front-run the legitimate initialization and permanently seize control of the whitelist authority. This grants complete control over resolver registration, enabling protocol monopolization or shutdown.

## Finding Description

The whitelist program contains a critical access control vulnerability in its initialization logic. The `initialize` function accepts any signer as the authority without validation: [1](#0-0) 

The `Initialize` account structure imposes no constraints on who can become the authority: [2](#0-1) 

The authority field is simply `Signer<'info>` with no constraint like `constraint = authority.key() == EXPECTED_AUTHORITY_PUBKEY`. The whitelist state PDA is derived from a constant seed: [3](#0-2) 

This makes the PDA address deterministic and publicly calculable. The `init` constraint at line 49 ensures the account can only be initialized once, meaning the first caller permanently becomes the authority.

**Attack Scenario:**

1. 1inch team deploys the whitelist program (program ID becomes public)
2. Attacker calculates the deterministic whitelist state PDA
3. Attacker submits `initialize` transaction with higher priority fees
4. Attacker's transaction executes first, setting themselves as authority
5. Legitimate initialization fails (account already initialized)
6. Attacker permanently controls whitelist authority

**Protocol Impact:**

The authority has complete control over resolver registration. Both `register` and `deregister` enforce authority-only access: [4](#0-3) [5](#0-4) 

This control is critical because the Fusion Swap protocol requires all order fillers to be whitelisted. The `fill` instruction validates resolver access: [6](#0-5) 

Similarly, `cancel_by_resolver` requires whitelist validation: [7](#0-6) 

Without a valid `resolver_access` PDA, no one can fill orders or perform resolver cancellations. The `set_authority` function only allows the current authority to transfer control: [8](#0-7) 

This makes the takeover permanent without program upgrade.

## Impact Explanation

**Severity: CRITICAL**

1. **Complete Access Control Takeover**: The attacker becomes the permanent whitelist authority with no reset mechanism aside from program upgrade.

2. **Protocol Monopolization**: The attacker can whitelist only themselves, monopolizing all order fills and extracting maximum value from every order.

3. **Protocol Shutdown**: Alternatively, the attacker can deregister all legitimate resolvers and refuse new registrations, rendering the entire Fusion Swap protocol inoperable. All orders become unfillable except through maker cancellation.

4. **Difficult Recovery**: While program upgrade is possible, it requires:
   - Emergency response after attack has occurred
   - Potential protocol downtime
   - Users may have created unfillable orders
   - Significant reputation damage

## Likelihood Explanation

**Likelihood: HIGH**

1. **Public Knowledge**: Program deployments are transparent. Once deployed, the program ID is public and the whitelist state PDA can be calculated by anyone.

2. **Trivial Exploitation**: The attack requires only:
   - Calculating the deterministic PDA
   - Constructing a simple `initialize` transaction
   - Submitting with higher priority fees
   - Minimal SOL for transaction costs

3. **No Technical Barriers**: No special permissions, signatures, or access required.

4. **Unavoidable Time Window**: Program deployment and initialization are necessarily separate transactions on Solana, creating an exploitable window.

5. **High Economic Incentive**: Complete control over a DeFi protocol handling significant trading volume represents enormous value extraction opportunity.

## Recommendation

Add an authorization constraint to the `Initialize` struct:

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

Define `EXPECTED_AUTHORITY_PUBKEY` as a constant in the program with the legitimate authority's public key. This ensures only the intended authority can initialize the whitelist state.

Alternatively, implement a two-step initialization pattern where deployment and initialization can be atomically linked, though this is more complex in Solana's architecture.

## Proof of Concept

**Note**: A complete PoC would demonstrate front-running the initialization transaction. The test would:

1. Deploy the whitelist program
2. Have an attacker transaction initialize the whitelist with attacker as authority
3. Attempt legitimate initialization (should fail)
4. Verify attacker controls authority and can register/deregister resolvers
5. Verify legitimate team cannot call `set_authority`

The vulnerability is evident from code analysis alone - the `initialize` function has zero authorization checks, making front-running trivial for any attacker monitoring program deployments.

## Notes

This vulnerability represents a fundamental access control flaw in the initialization pattern. The deterministic PDA derivation combined with lack of authorization creates a race condition that strongly favors attackers who can monitor the blockchain and submit higher priority transactions. The permanent nature of the takeover (due to `set_authority` requiring current authority signature) makes this a critical pre-deployment issue requiring immediate remediation.

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

**File:** programs/fusion-swap/src/lib.rs (L504-516)
```rust
#[derive(Accounts)]
#[instruction(order: OrderConfig)]
pub struct Fill<'info> {
    /// `taker`, who buys `src_mint` for `dst_mint`
    #[account(mut, signer)]
    taker: Signer<'info>,
    /// Account allowed to fill the order
    #[account(
        seeds = [whitelist::RESOLVER_ACCESS_SEED, taker.key().as_ref()],
        bump = resolver_access.bump,
        seeds::program = whitelist::ID,
    )]
    resolver_access: Account<'info, whitelist::ResolverAccess>,
```

**File:** programs/fusion-swap/src/lib.rs (L640-653)
```rust
#[derive(Accounts)]
#[instruction(order: OrderConfig)]
pub struct CancelByResolver<'info> {
    /// Account that cancels the escrow
    #[account(mut, signer)]
    resolver: Signer<'info>,

    /// Account allowed to cancel the order
    #[account(
        seeds = [whitelist::RESOLVER_ACCESS_SEED, resolver.key().as_ref()],
        bump = resolver_access.bump,
        seeds::program = whitelist::ID,
    )]
    resolver_access: Account<'info, whitelist::ResolverAccess>,
```
