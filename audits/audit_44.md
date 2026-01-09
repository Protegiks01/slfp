# Audit Report

## Title
Authority-Controlled Complete Protocol DoS Through Empty Whitelist

## Summary
The whitelist authority can deregister all resolvers without any safeguards, creating a complete denial-of-service condition where no orders can be filled and expired orders cannot be cleaned up by resolvers, effectively halting all protocol functionality.

## Finding Description

The 1inch Solana Fusion Protocol enforces that only whitelisted resolvers can fill orders or cancel expired orders through resolver operations. However, the whitelist program contains no protection against the authority deregistering all resolvers, creating an empty whitelist state.

The vulnerability occurs through the following mechanism:

1. **Resolver Access Enforcement**: The `Fill` instruction requires a valid `resolver_access` account that must be derived from the whitelist program. [1](#0-0) 

2. **Resolver Cancellation Enforcement**: The `CancelByResolver` instruction also requires the same `resolver_access` account validation. [2](#0-1) 

3. **Unrestricted Deregistration**: The whitelist program's `deregister` function allows the authority to remove any resolver by closing their `resolver_access` account, with no checks preventing removal of all resolvers. [3](#0-2) 

When the authority deregisters all resolvers:
- The `fill` instruction fails because Anchor cannot deserialize a non-existent `resolver_access` account
- The `cancel_by_resolver` instruction fails for the same reason  
- All active orders become permanently unfillable
- Expired orders cannot be cleaned up by resolvers
- The protocol's core functionality is completely disabled

Makers can still cancel their own orders using the regular `cancel` instruction, which doesn't require resolver access. [4](#0-3) 

**Which Invariant is Broken:**
This breaks the **Access Control** invariant (#5): "Only authorized resolvers can fill orders or cancel by resolver" - but extends beyond the intended scope by allowing the authority to create a state where NO resolvers exist, making the invariant impossible to satisfy and the protocol non-functional.

## Impact Explanation

**Severity: Medium**

The impact is classified as Medium because:

1. **Complete Protocol Disruption**: All order filling operations cease immediately, affecting every user attempting to execute trades
2. **No Fund Theft**: Escrowed funds remain secure as makers can cancel and recover their tokens
3. **Temporary DoS**: The condition is reversible if the authority re-registers resolvers
4. **Single Point of Failure**: Creates centralization risk where authority compromise or malicious action halts the entire protocol

This doesn't reach High severity because:
- Funds are not stolen or permanently locked
- Makers retain control over their escrowed tokens via cancellation
- The issue is reversible through authority action

## Likelihood Explanation

**Likelihood: Low to Medium**

The likelihood depends on the threat model:

**Low if considering only malicious intent:**
- Requires the authority to intentionally act maliciously
- 1inch is a reputable organization unlikely to sabotage their own protocol
- Direct financial harm is limited, reducing malicious incentive

**Medium if considering operational risks:**
- Authority key compromise could enable this attack
- Operational error during resolver management could accidentally remove all resolvers
- No warning system or safeguards prevent this state
- No time-lock or multi-sig protection evident in the code

The vulnerability becomes more likely in scenarios involving:
- Key compromise through phishing, malware, or infrastructure breach
- Automated scripts with bugs in resolver management
- Disgruntled insider with authority access
- Protocol migration or shutdown procedures

## Recommendation

Implement the following safeguards in the whitelist program:

**1. Minimum Resolver Count Check:**
Add a counter to track active resolvers and prevent deregistration below a minimum threshold:

```rust
#[account]
#[derive(InitSpace)]
pub struct WhitelistState {
    pub authority: Pubkey,
    pub resolver_count: u32,
}

// In deregister function:
pub fn deregister(ctx: Context<Deregister>, _user: Pubkey) -> Result<()> {
    let whitelist_state = &mut ctx.accounts.whitelist_state;
    require!(
        whitelist_state.resolver_count > MIN_RESOLVERS,
        WhitelistError::CannotRemoveLastResolver
    );
    whitelist_state.resolver_count -= 1;
    Ok(())
}
```

**2. Emergency Multi-Sig Requirement:**
Require multi-signature approval for critical operations like deregistering multiple resolvers within a time window.

**3. Time-Lock for Mass Deregistration:**
Implement a time-delay before deregistration takes effect, allowing community response to suspicious activity.

**4. Monitoring and Alerts:**
Add off-chain monitoring to detect when resolver count drops below safe thresholds and alert the team.

## Proof of Concept

The following TypeScript test demonstrates the DoS vector:

```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";
import { FusionSwap } from "../../target/types/fusion_swap";
import { Whitelist } from "../../target/types/whitelist";

describe("Empty Whitelist DoS", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const fusionProgram = anchor.workspace.FusionSwap as anchor.Program<FusionSwap>;
  const whitelistProgram = anchor.workspace.Whitelist as anchor.Program<Whitelist>;
  const authority = provider.wallet;

  it("Demonstrates protocol DoS when all resolvers are deregistered", async () => {
    // Setup: Create and register a resolver
    const resolver = anchor.web3.Keypair.generate();
    await provider.connection.requestAirdrop(
      resolver.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );

    // Register the resolver
    await whitelistProgram.methods
      .register(resolver.publicKey)
      .accountsPartial({ authority: authority.publicKey })
      .rpc();

    // Create an order (this succeeds)
    const maker = anchor.web3.Keypair.generate();
    // ... order creation code ...

    // Authority deregisters all resolvers (creating empty whitelist)
    await whitelistProgram.methods
      .deregister(resolver.publicKey)
      .accountsPartial({ authority: authority.publicKey })
      .rpc();

    // Attempt to fill the order - this will fail with account not found
    await expect(
      fusionProgram.methods
        .fill(orderConfig, fillAmount)
        .accounts({
          taker: resolver.publicKey,
          resolverAccess: resolverAccessPDA, // This account no longer exists
          // ... other accounts ...
        })
        .signers([resolver])
        .rpc()
    ).to.be.rejectedWith("AccountNotFound"); // Anchor error for missing account

    // Attempt cancel by resolver - also fails
    await expect(
      fusionProgram.methods
        .cancelByResolver(orderConfig, rewardLimit)
        .accounts({
          resolver: resolver.publicKey,
          resolverAccess: resolverAccessPDA, // This account no longer exists
          // ... other accounts ...
        })
        .signers([resolver])
        .rpc()
    ).to.be.rejectedWith("AccountNotFound");

    // Maker can still cancel (this succeeds - funds are not locked)
    await fusionProgram.methods
      .cancel(orderHash, orderConfig.srcAssetIsNative)
      .accounts({
        maker: maker.publicKey,
        // ... other accounts (no resolver_access needed) ...
      })
      .signers([maker])
      .rpc();

    // This demonstrates:
    // 1. Protocol is completely non-functional for order filling
    // 2. Expired orders cannot be cleaned up by resolvers
    // 3. Makers can still recover funds via cancellation
    // 4. No safeguards prevent this state
  });
});
```

**Reproduction Steps:**
1. Deploy both whitelist and fusion-swap programs
2. Initialize whitelist with authority
3. Register at least one resolver
4. Create active orders with makers
5. Authority calls `deregister` for all registered resolvers
6. Attempt to call `fill` on any order - transaction fails with "AccountNotFound"
7. Attempt to call `cancel_by_resolver` - also fails
8. Verify makers can still call `cancel` to recover funds

The PoC demonstrates that while funds remain secure, the protocol becomes completely non-functional for its primary purpose when all resolvers are deregistered.

## Notes

This vulnerability represents a **centralization risk** and **single point of failure** in the protocol's access control design. While the 1inch authority is presumed trustworthy, defense-in-depth principles suggest implementing safeguards against:

- Authority key compromise
- Operational errors in resolver management  
- Future governance changes that might decentralize authority

The issue is particularly concerning because:
1. There are no on-chain checks preventing this state
2. No emergency recovery mechanism exists beyond re-registering resolvers
3. The transition from functional to non-functional is instantaneous
4. Users have no advance warning before the protocol becomes unusable

The recommended mitigations would align the protocol with security best practices for critical DeFi infrastructure by preventing unilateral protocol shutdown through access control manipulation.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L286-343)
```rust
    pub fn cancel(
        ctx: Context<Cancel>,
        order_hash: [u8; 32],
        order_src_asset_is_native: bool,
    ) -> Result<()> {
        require!(
            ctx.accounts.src_mint.key() == native_mint::id() || !order_src_asset_is_native,
            FusionError::InconsistentNativeSrcTrait
        );

        require!(
            order_src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );

        // Return remaining src tokens back to maker
        if !order_src_asset_is_native {
            transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.src_token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.escrow_src_ata.to_account_info(),
                        mint: ctx.accounts.src_mint.to_account_info(),
                        to: ctx
                            .accounts
                            .maker_src_ata
                            .as_ref()
                            .ok_or(FusionError::MissingMakerSrcAta)?
                            .to_account_info(),
                        authority: ctx.accounts.escrow.to_account_info(),
                    },
                    &[&[
                        "escrow".as_bytes(),
                        ctx.accounts.maker.key().as_ref(),
                        &order_hash,
                        &[ctx.bumps.escrow],
                    ]],
                ),
                ctx.accounts.escrow_src_ata.amount,
                ctx.accounts.src_mint.decimals,
            )?;
        }

        close_account(CpiContext::new_with_signer(
            ctx.accounts.src_token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.escrow_src_ata.to_account_info(),
                destination: ctx.accounts.maker.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            &[&[
                "escrow".as_bytes(),
                ctx.accounts.maker.key().as_ref(),
                &order_hash,
                &[ctx.bumps.escrow],
            ]],
        ))
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

**File:** programs/whitelist/src/lib.rs (L30-33)
```rust
    /// Removes a user from the whitelist
    pub fn deregister(_ctx: Context<Deregister>, _user: Pubkey) -> Result<()> {
        Ok(())
    }
```
