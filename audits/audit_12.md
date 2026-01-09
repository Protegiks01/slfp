# Audit Report

## Title
Whitelist Authority Takeover via Unprotected initialize() Function

## Summary
The `initialize()` function in the whitelist program lacks validation on who can call it, allowing any arbitrary account to claim permanent authority over the whitelist during deployment. This enables complete access control bypass and protocol monopolization.

## Finding Description

The whitelist program's `initialize()` function accepts any signer as the authority without validating their identity. [1](#0-0) 

The `Initialize` context structure only requires that the authority is a `Signer`, with no constraints on which specific address can perform initialization. [2](#0-1) 

Since the `whitelist_state` account is a PDA derived from a static seed `WHITELIST_STATE_SEED`, it can only be initialized once. Whoever successfully calls `initialize()` first becomes the permanent authority.

This authority controls all resolver registrations and deregistrations through the `register()` and `deregister()` functions, which validate that the caller matches the stored authority. [3](#0-2) 

The resolver whitelist is critical because the fusion-swap program requires a valid `resolver_access` account for both filling orders and canceling expired orders by resolver. [4](#0-3) 

**Attack Scenario:**
1. Attacker monitors for the whitelist program deployment
2. Attacker submits their own `initialize()` transaction with themselves as the signer
3. If the attacker's transaction executes first, they become the permanent authority
4. Attacker registers themselves as the only resolver
5. Attacker gains monopoly on order filling and cancellation premiums
6. Legitimate resolvers are blocked from participating in the protocol

This breaks the **Access Control** invariant (only authorized resolvers can fill orders) and the **Account Validation** invariant (all account validations must prevent unauthorized access).

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability enables complete protocol compromise:

1. **Resolver Monopoly**: The attacker controls who can be registered as a resolver, allowing them to maintain exclusive access to order filling
2. **Fee Capture**: Only whitelisted resolvers can fill orders and collect fees from the Dutch auction mechanism. The attacker captures 100% of resolver revenue
3. **Cancellation Premium Theft**: Resolvers earn cancellation premiums when canceling expired orders [5](#0-4)  - the attacker gains exclusive access to these rewards
4. **Protocol Disruption**: The attacker can deregister all legitimate resolvers, preventing any order fills and effectively shutting down the protocol
5. **Irreversible Takeover**: Once initialized, the authority can only be changed by the current authority via `set_authority()` [6](#0-5)  - the attacker maintains permanent control unless they choose to transfer it

The impact affects **all users** of the protocol - makers cannot get their orders filled by legitimate resolvers, and the protocol's competitive resolver marketplace is replaced with a single malicious monopolist.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This attack is extremely feasible:

1. **Simple Execution**: The attack requires only a single transaction call to `initialize()` - no complex exploit chains or timing dependencies
2. **Front-Running Opportunity**: On Solana, transaction ordering within a block is not strictly deterministic. An attacker with higher priority fees or better validator connections can front-run the legitimate deployment
3. **Public Visibility**: Program deployments are publicly visible on-chain, giving attackers advance notice to prepare their front-running transaction
4. **Low Cost**: The attack costs only transaction fees and account rent, making it economically trivial
5. **No Prerequisites**: The attacker needs no special permissions, tokens, or existing protocol participation

The attack window exists from the moment the program is deployed until `initialize()` is successfully called. Given the high value of controlling a DEX protocol's resolver access, rational attackers are highly motivated to monitor for this opportunity.

## Recommendation

Implement authority validation in the `initialize()` function using one of these approaches:

**Option 1: Hardcoded Authority** (Most Secure)
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Define the expected authority at compile time
    const EXPECTED_AUTHORITY: Pubkey = pubkey!("YourExpectedAuthorityPubkeyHere");
    
    require!(
        ctx.accounts.authority.key() == EXPECTED_AUTHORITY,
        WhitelistError::UnauthorizedInitialization
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: Upgrade Authority Check** (More Flexible)
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let program_data_address = Pubkey::find_program_address(
        &[ctx.program_id.as_ref()],
        &bpf_loader_upgradeable::id()
    ).0;
    
    let program_data = ProgramData::try_from_slice(
        &ctx.accounts.program_data.data.borrow()
    )?;
    
    require!(
        ctx.accounts.authority.key() == program_data.upgrade_authority_address.unwrap(),
        WhitelistError::UnauthorizedInitialization
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

Add the corresponding error:
```rust
#[error_code]
pub enum WhitelistError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Unauthorized initialization attempt")]
    UnauthorizedInitialization,
}
```

**Best Practice**: Use Option 1 with a hardcoded multisig authority for maximum security during deployment, then transfer to operational authority if needed.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;
    
    #[test]
    fn test_arbitrary_authority_takeover() {
        // Simulate attacker's wallet
        let attacker = Keypair::new();
        
        // Attacker calls initialize before legitimate authority
        let initialize_accounts = Initialize {
            authority: attacker.clone(),  // Attacker as signer
            whitelist_state: /* PDA account */,
            system_program: /* System program */,
        };
        
        // This call succeeds - attacker becomes authority
        let result = whitelist::initialize(
            Context::new(
                &whitelist::ID,
                &mut initialize_accounts,
                &[],
                BTreeMap::new(),
            )
        );
        
        assert!(result.is_ok());
        
        // Verify attacker is now the authority
        assert_eq!(
            initialize_accounts.whitelist_state.authority,
            attacker.pubkey()
        );
        
        // Now attacker can register themselves as resolver
        let register_accounts = Register {
            authority: attacker.clone(),
            whitelist_state: /* Same PDA */,
            resolver_access: /* Attacker's resolver PDA */,
            system_program: /* System program */,
        };
        
        let result = whitelist::register(
            Context::new(
                &whitelist::ID,
                &mut register_accounts,
                &[],
                BTreeMap::new(),
            ),
            attacker.pubkey()
        );
        
        assert!(result.is_ok());
        
        // Attacker now has exclusive resolver access
        // Legitimate authority's initialize call will fail (account already initialized)
        // Protocol is permanently compromised
    }
}
```

**Reproduction Steps:**
1. Deploy the whitelist program to devnet/testnet
2. Create an attacker keypair
3. Submit `initialize()` transaction with attacker as signer before legitimate deployment script runs
4. Verify attacker's public key is stored in `whitelist_state.authority`
5. Call `register()` to whitelist attacker's address as a resolver
6. Attempt to fill an order using the fusion-swap program - only the attacker's address will be accepted

---

## Notes

This vulnerability represents a critical deployment security flaw. The lack of authority validation in initialization functions is a common pattern error in Solana programs that can lead to complete protocol takeover. The fix must be implemented before mainnet deployment, as there is no recovery mechanism once an unauthorized party claims authority over the whitelist PDA.

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
