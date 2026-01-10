# Audit Report

## Title
Whitelist Authority Takeover via Unprotected initialize() Function

## Summary
The whitelist program's `initialize()` function lacks validation on who can call it, creating a critical front-running vulnerability during deployment. Any attacker can claim permanent authority over the resolver whitelist by submitting their initialization transaction before the legitimate deployment team, enabling complete protocol monopolization.

## Finding Description

The whitelist program contains an unprotected initialization function that accepts any signer as the authority without validation. [1](#0-0) 

The `Initialize` context structure only requires that the authority is a `Signer<'info>`, with no constraints such as `address`, `constraint`, or `has_one` checks to restrict which specific account can perform initialization. [2](#0-1) 

The `whitelist_state` account is a Program Derived Address (PDA) with a static seed, meaning it can only be initialized once. Once the `init` constraint creates the account, any subsequent initialization attempts will fail. Whoever successfully executes `initialize()` first becomes the permanent authority. [3](#0-2) 

This authority has exclusive control over resolver registrations and deregistrations. Both the `register()` and `deregister()` functions validate that the caller matches the stored authority through explicit constraint checks. [4](#0-3) [5](#0-4) 

The resolver whitelist is critical to protocol operation because the fusion-swap program requires a valid `resolver_access` account for filling orders and canceling expired orders. [6](#0-5) [7](#0-6) 

**Attack Scenario:**
1. Attacker monitors Solana for the whitelist program deployment
2. Upon detecting deployment, attacker immediately submits an `initialize()` transaction with themselves as the signer, using higher priority fees
3. If the attacker's transaction executes before the legitimate initialization, they become the permanent authority
4. Attacker registers only themselves as a resolver, blocking all legitimate resolvers
5. Attacker gains monopoly on order filling and captures all resolver fees and cancellation premiums
6. Protocol cannot function as designed without competitive resolver marketplace

This breaks the fundamental **Access Control** security invariant that only authorized resolvers should participate in the protocol.

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability enables complete protocol compromise through authority takeover:

1. **Resolver Monopoly**: The attacker gains exclusive control over who can be registered as a resolver, maintaining monopolistic access to order filling operations

2. **Revenue Capture**: Only whitelisted resolvers can fill orders and collect fees from the Dutch auction mechanism. The attacker captures 100% of resolver revenue streams

3. **Cancellation Premium Theft**: Resolvers earn cancellation premiums when canceling expired orders through `cancel_by_resolver()`. The attacker gains exclusive access to these rewards. [8](#0-7) 

4. **Protocol Disruption**: The attacker can prevent all legitimate resolvers from participating, effectively shutting down the protocol's order filling mechanism and denying service to all users

5. **Irreversible Takeover**: Once initialized, the authority can only be changed by the current authority via `set_authority()`, meaning the attacker maintains permanent control unless they voluntarily transfer it. [9](#0-8) 

The impact affects **all protocol users** - order makers cannot get their orders filled by legitimate competitive resolvers, and the protocol's intended resolver marketplace is replaced with a malicious monopolist.

## Likelihood Explanation

**MEDIUM-HIGH LIKELIHOOD** - This attack is feasible during deployment window:

1. **Simple Execution**: Requires only a single transaction calling `initialize()` with the attacker as signer - no complex exploit chains or precise timing beyond monitoring for deployment

2. **Front-Running Window**: On Solana, attackers can use higher priority fees and validator connections to front-run legitimate transactions. The deployment-to-initialization window creates opportunity for this attack

3. **Public Visibility**: Program deployments are publicly visible on-chain, providing attackers advance notice to prepare front-running transactions

4. **Low Cost**: Attack costs only transaction fees and account rent (~0.00203928 SOL), making it economically trivial compared to the potential gains from controlling a DEX protocol

5. **High Value Target**: The value of monopolizing resolver access for a major DEX protocol provides strong economic incentive for rational attackers to monitor for this opportunity

While the 1inch team would attempt to initialize immediately upon deployment, the technical vulnerability exists in the code and the attack window is real.

## Recommendation

Add explicit validation to the `initialize()` function to ensure only an authorized deployer can set the initial authority. Several secure patterns exist:

**Option 1**: Hardcode the authorized deployer address
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    require!(
        ctx.accounts.authority.key() == AUTHORIZED_DEPLOYER_PUBKEY,
        WhitelistError::UnauthorizedInitializer
    );
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2**: Use the program upgrade authority as the authorized initializer
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key()),
        constraint = program_data.upgrade_authority_address == Some(authority.key()) 
            @ WhitelistError::UnauthorizedInitializer
    )]
    pub program: Program<'info, System>,
    
    /// CHECK: PDA validation ensures this is the correct program data account
    pub program_data: AccountInfo<'info>,
    
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

**Option 3**: Initialize the program in the same transaction as deployment using a deployment script that atomically deploys and initializes, reducing the attack window to zero.

## Proof of Concept

A complete PoC demonstrating the front-running attack would strengthen this submission. The test should:
1. Deploy the whitelist program
2. Have an attacker call `initialize()` before the legitimate authority
3. Verify the attacker is set as authority
4. Demonstrate the attacker can register themselves and block others
5. Show that `fill()` operations require the attacker's approval

## Notes

This is a **deployment-time vulnerability** rather than a runtime exploit. The vulnerability window exists only between program deployment and successful initialization. However, this represents a genuine security flaw in the code design - secure-by-default Solana programs should implement initialization protection rather than relying solely on deployment procedures. The lack of validation creates unnecessary risk during the critical deployment phase.

The severity assessment assumes standard Solana deployment practices where program code is deployed first, then initialization occurs in a subsequent transaction. If the 1inch team uses atomic deployment+initialization or other protective measures, the practical likelihood decreases, but the code-level vulnerability remains.

### Citations

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

**File:** programs/fusion-swap/src/lib.rs (L404-411)
```rust
        let cancellation_premium = calculate_premium(
            current_timestamp as u32,
            order.expiration_time,
            order.cancellation_auction_duration,
            order.fee.max_cancellation_premium,
        );
        let maker_amount = ctx.accounts.escrow_src_ata.to_account_info().lamports()
            - std::cmp::min(cancellation_premium, reward_limit);
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
