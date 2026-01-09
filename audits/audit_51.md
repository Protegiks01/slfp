# Audit Report

## Title
Whitelist Initialization Front-Running Allows Complete Protocol Takeover

## Summary
The `initialize` instruction in the whitelist program lacks authorization checks, allowing any attacker to front-run the legitimate initialization transaction and permanently set themselves as the whitelist authority. This grants the attacker complete control over resolver registration, effectively allowing them to monopolize or completely disable the entire Fusion Swap protocol's order execution system.

## Finding Description

The whitelist program's `initialize` function sets the authority that controls which resolvers can fill orders in the Fusion Swap protocol. However, this function contains a critical vulnerability: **it has no validation to restrict who can call it**. [1](#0-0) 

The `Initialize` account validation structure uses Anchor's `init` constraint with a deterministic PDA derived from a constant seed: [2](#0-1) 

The PDA is derived using only the constant seed `"whitelist_state"`, making it completely deterministic and publicly known: [3](#0-2) 

**Attack Flow:**

1. The 1inch team deploys the whitelist program but hasn't initialized it yet
2. An attacker monitors the blockchain or mempool for the initialization transaction
3. The attacker submits their own `initialize` transaction with higher priority fees
4. The attacker's transaction executes first, setting `whitelist_state.authority = attacker.key()`
5. The legitimate initialization transaction from 1inch fails because the account already exists (Anchor's `init` constraint prevents re-initialization)
6. The attacker now permanently controls the whitelist authority

**Security Invariants Broken:**

- **Invariant #5 (Access Control)**: The attacker can now control who is authorized to fill orders by registering/deregistering resolvers at will
- **Invariant #7 (Account Validation)**: The initialization lacks proper authorization validation to prevent unauthorized access

The whitelist authority has complete control over resolver registration: [4](#0-3) 

Only whitelisted resolvers can fill orders in the Fusion Swap program: [5](#0-4) 

And only whitelisted resolvers can cancel orders by resolver: [6](#0-5) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability results in complete protocol compromise:

1. **Total Access Control Takeover**: The attacker becomes the permanent whitelist authority with no mechanism for the legitimate 1inch team to recover control
2. **Protocol Monopolization**: The attacker can whitelist only themselves as a resolver, monopolizing all order fills and extracting maximum value
3. **Protocol Shutdown**: The attacker can deregister all legitimate resolvers and refuse to whitelist anyone, effectively shutting down the entire Fusion Swap protocol
4. **Permanent Damage**: Since there's no recovery mechanism and the whitelist state cannot be re-initialized, the protocol would need to be completely redeployed with a new program ID

All users who created orders would be unable to have them filled (except by maker cancellation), and the protocol would become completely non-functional. This affects 100% of users and renders the entire deployed infrastructure worthless.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Public Knowledge**: The deployment of Solana programs is public, and the program ID is deterministic
2. **Trivial Exploitation**: Any attacker with basic Solana knowledge can call the initialize function - no sophisticated attack required
3. **No Technical Barriers**: The attacker needs only basic transaction construction knowledge and enough SOL for transaction fees
4. **MEV Opportunity**: Even without malicious intent, MEV bots scanning for front-running opportunities could inadvertently exploit this
5. **Time Window**: There's a critical time window between program deployment and initialization when the vulnerability is exploitable
6. **Deterministic PDA**: The whitelist_state address is publicly calculable, making it trivial to construct the attack transaction

The attack can be executed in minutes by monitoring on-chain deployments or simply calling initialize immediately after observing the program deployment.

## Recommendation

**Immediate Fix**: Add an authorization check to the `initialize` function to ensure only a designated authority can initialize the whitelist:

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
        // Add constraint to verify authority matches expected deployer
        constraint = authority.key() == EXPECTED_AUTHORITY_PUBKEY @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    pub system_program: Program<'info, System>,
}
```

Define the expected authority as a constant:

```rust
// Add at the top of the file
pub const EXPECTED_AUTHORITY_PUBKEY: Pubkey = pubkey!("YourExpectedAuthorityPublicKeyHere");
```

**Alternative Solutions:**

1. **Upgrade Authority Check**: Use Solana's program upgrade authority as the authorized initializer by checking against the program data account
2. **Two-Step Initialization**: Have the program deployed with a hardcoded initial authority, then allow that authority to transfer control
3. **Initialization During Deployment**: Initialize the state in the same transaction as program deployment using an atomic deployment script

**Deployment Best Practice**: Always initialize critical state accounts in the same atomic transaction bundle as program deployment to prevent front-running attacks.

## Proof of Concept

**Attack Reproduction Steps:**

1. Monitor for whitelist program deployment at address `5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S`

2. Calculate the deterministic whitelist_state PDA:
```typescript
const [whitelistState] = PublicKey.findProgramAddressSync(
    [Buffer.from("whitelist_state")],
    new PublicKey("5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S")
);
```

3. Before the legitimate 1inch team calls initialize, submit this transaction:
```typescript
const attackerKeypair = Keypair.generate(); // Or load attacker's keypair

const initializeIx = await whitelistProgram.methods
    .initialize()
    .accountsPartial({
        authority: attackerKeypair.publicKey,
        whitelistState,
    })
    .signers([attackerKeypair])
    .instruction();

// Submit with high priority fee to ensure execution
const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitPrice({ 
        microLamports: 1_000_000 // High priority
    }),
    initializeIx
);

await sendAndConfirmTransaction(connection, tx, [attackerKeypair]);
```

4. Verify attacker is now the authority:
```typescript
const whitelistStateAccount = await whitelistProgram.account.whitelistState.fetch(whitelistState);
console.log("Authority:", whitelistStateAccount.authority.toString());
// Outputs: Authority: <attacker's public key>
```

5. The attacker can now:
   - Register only themselves as a resolver
   - Refuse to register legitimate resolvers
   - Control the entire protocol's order execution

**Result**: The attacker has permanent control over the whitelist, and the legitimate 1inch team cannot recover without redeploying the entire program with a new program ID, invalidating all existing integrations and escrowed funds.

---

**Notes:**

This vulnerability is a textbook example of an unprotected initialization function, a common vulnerability pattern in Solana programs. The lack of authorization checks combined with the deterministic PDA derivation creates a race condition where the first caller wins permanent control. This type of vulnerability has been exploited in production on Solana before and should be treated with maximum urgency.

The fix is straightforward but requires careful coordination during deployment. The program should ideally be deployed and initialized in the same atomic transaction, or use upgrade authority validation to ensure only the legitimate deployer can initialize the state.

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
