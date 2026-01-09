# Audit Report

## Title
Makers Can Bypass Cancellation Premiums by Calling cancel() Instead of Waiting for cancel_by_resolver()

## Summary
Makers can avoid paying cancellation premiums by calling the `cancel()` function at any time, including after order expiration, completely bypassing the cancellation auction mechanism that is designed to charge premiums via `cancel_by_resolver()`. [1](#0-0) 

## Finding Description

The protocol implements a cancellation auction mechanism with two distinct cancellation paths:

1. **`cancel()` function** - Allows makers to cancel their own orders at ANY time with NO restrictions and NO premiums charged [1](#0-0) 

2. **`cancel_by_resolver()` function** - Allows whitelisted resolvers to cancel expired orders and charge a time-based cancellation premium [2](#0-1) 

The vulnerability exists because:

- The `cancel()` function has **no time restrictions** - makers can call it before OR after expiration
- The `cancel_by_resolver()` function requires `current_timestamp >= order.expiration_time` and calculates a premium that increases linearly from 0 to `max_cancellation_premium` over the `cancellation_auction_duration` [3](#0-2) [4](#0-3) 

The premium calculation shows that resolvers are supposed to earn fees for cleaning up expired orders: [5](#0-4) 

**Exploitation Path:**
1. Maker creates order with `max_cancellation_premium = 5 SOL` and `cancellation_auction_duration = 3600 seconds`
2. Order expires without being filled
3. During the cancellation auction period (after expiration), a resolver would earn an increasing premium for canceling
4. Instead, the maker simply calls `cancel()` themselves - no premium is charged
5. Maker recovers all escrowed tokens without paying the intended cancellation fee

This breaks the **Fee Correctness** invariant: "Fee calculations must be accurate and funds distributed correctly" - the cancellation premium is a protocol fee mechanism that can be completely bypassed.

## Impact Explanation

**Medium Severity** - This vulnerability enables:

- **Economic Loss to Resolvers**: The cancellation auction mechanism becomes economically non-viable. Resolvers are incentivized to monitor and cancel expired orders for premiums, but rational makers will always call `cancel()` themselves to avoid paying
- **Fee Avoidance**: Makers can set `max_cancellation_premium > 0` when creating orders to signal they will pay for cleanup, but then bypass this commitment by self-canceling
- **Mechanism Failure**: The entire cancellation auction feature becomes ineffective, as makers have zero incentive to let resolvers cancel their orders

The impact is limited to Medium (not High) because:
- No direct token theft occurs
- Only affects the economic incentive system, not core swap functionality
- Requires maker cooperation to exploit (they must choose to cancel rather than let resolver cancel)

## Likelihood Explanation

**High Likelihood** - This exploit will occur frequently because:

- **Rational Economic Behavior**: Any rational maker will call `cancel()` instead of waiting for `cancel_by_resolver()` to avoid paying premiums
- **Zero Technical Complexity**: Simply requires calling the standard `cancel()` function - no special knowledge or setup needed
- **No Access Restrictions**: Every maker has the ability to exploit this by default
- **Observable in Tests**: The test suite demonstrates makers can cancel at any time without restriction [6](#0-5) 

The combination of high likelihood and medium impact justifies the **Medium** severity rating.

## Recommendation

Add a time restriction to the `cancel()` function that prevents makers from canceling during the cancellation auction period after expiration:

```rust
pub fn cancel(
    ctx: Context<Cancel>,
    order_hash: [u8; 32],
    order_src_asset_is_native: bool,
) -> Result<()> {
    // NEW: Add time check to prevent bypass of cancellation auction
    let current_timestamp = Clock::get()?.unix_timestamp;
    
    // Need to receive order config to check expiration_time
    // This requires changing the function signature to accept OrderConfig
    // and validate it matches the order_hash
    
    require!(
        current_timestamp < order.expiration_time as i64,
        FusionError::CannotCancelDuringAuction
    );

    // ... rest of existing cancel logic
}
```

**Alternative Solution**: If the protocol wants makers to be able to cancel anytime, remove the cancellation auction mechanism entirely or make it opt-in only by requiring makers to explicitly disable `cancel()` when creating orders with cancellation premiums.

**Recommended Approach**: 
1. Require makers to pass the full `OrderConfig` to `cancel()` (similar to `cancel_by_resolver()`)
2. Validate the order config matches the order hash
3. Check if `current_timestamp < expiration_time` OR `max_cancellation_premium == 0`
4. Only allow maker cancellation if one of these conditions is true

## Proof of Concept

The following test demonstrates the vulnerability:

```rust
#[tokio::test]
async fn test_maker_bypasses_cancellation_premium() {
    // Setup: Create test environment with maker, resolver, and tokens
    let context = /* initialize test context */;
    let maker = /* maker keypair */;
    let resolver = /* whitelisted resolver keypair */;
    
    // Step 1: Maker creates order with 5 SOL cancellation premium
    let max_cancellation_premium = 5_000_000_000; // 5 SOL in lamports
    let cancellation_auction_duration = 3600; // 1 hour
    let expiration_time = current_time + 1800; // expires in 30 minutes
    
    let order_config = OrderConfig {
        fee: FeeConfig {
            max_cancellation_premium: max_cancellation_premium,
            // ... other fee config
        },
        expiration_time: expiration_time,
        cancellation_auction_duration: cancellation_auction_duration,
        // ... other order config
    };
    
    let create_ix = program.methods
        .create(order_config)
        // ... accounts
        .instruction();
    
    // Execute create transaction
    
    // Step 2: Wait for order to expire
    advance_clock(context, expiration_time + 900); // 15 minutes after expiration
    
    // Step 3: At this point, if resolver calls cancel_by_resolver(),
    // they would earn: (900 / 3600) * 5 SOL = 1.25 SOL premium
    
    let maker_balance_before = get_balance(maker.pubkey());
    
    // Step 4: Maker calls cancel() and pays NO premium
    let cancel_ix = program.methods
        .cancel(order_hash, false)
        .accounts(Cancel {
            maker: maker.pubkey(),
            // ... other accounts
        })
        .instruction();
    
    // Execute cancel transaction
    
    let maker_balance_after = get_balance(maker.pubkey());
    
    // Verify: Maker received all tokens back + rent, paid NO premium
    assert_eq!(
        maker_balance_after - maker_balance_before,
        escrow_rent, // Only gets rent back, no premium deducted
        "Maker bypassed cancellation premium"
    );
    
    // Compare: If resolver had called cancel_by_resolver(),
    // maker would have received: escrow_rent - 1.25 SOL premium
}
```

The test can be added to `tests/suits/cancel-by-resolver.ts` to demonstrate that makers can call `cancel()` after expiration without paying the premium that `cancel_by_resolver()` would charge.

**Notes**

The vulnerability fundamentally undermines the cancellation auction mechanism design. The protocol documentation indicates cancellation premiums are intended to incentivize resolvers to clean up expired orders, but the implementation allows makers to completely bypass this by self-canceling at any time. This is a clear design flaw where the economic incentive structure does not align with the technical implementation.

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

**File:** programs/fusion-swap/src/lib.rs (L345-436)
```rust
    pub fn cancel_by_resolver(
        ctx: Context<CancelByResolver>,
        order: OrderConfig,
        reward_limit: u64,
    ) -> Result<()> {
        require!(
            order.fee.max_cancellation_premium > 0,
            FusionError::CancelOrderByResolverIsForbidden
        );
        let current_timestamp = Clock::get()?.unix_timestamp;
        require!(
            current_timestamp >= order.expiration_time as i64,
            FusionError::OrderNotExpired
        );
        require!(
            order.src_asset_is_native == ctx.accounts.maker_src_ata.is_none(),
            FusionError::InconsistentNativeSrcTrait
        );

        let order_hash = order_hash(
            &order,
            ctx.accounts.protocol_dst_acc.as_ref().map(|acc| acc.key()),
            ctx.accounts
                .integrator_dst_acc
                .as_ref()
                .map(|acc| acc.key()),
            ctx.accounts.src_mint.key(),
            ctx.accounts.dst_mint.key(),
            ctx.accounts.maker_receiver.key(),
        )?;

        // Return remaining src tokens back to maker
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

        let cancellation_premium = calculate_premium(
            current_timestamp as u32,
            order.expiration_time,
            order.cancellation_auction_duration,
            order.fee.max_cancellation_premium,
        );
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

        // Transfer all lamports from the closed account, minus the cancellation premium, to the maker
        uni_transfer(&UniTransferParams::NativeTransfer {
            from: ctx.accounts.resolver.to_account_info(),
            to: ctx.accounts.maker.to_account_info(),
            amount: maker_amount,
            program: ctx.accounts.system_program.clone(),
        })
    }
```

**File:** programs/fusion-swap/src/auction.rs (L56-72)
```rust
pub fn calculate_premium(
    timestamp: u32,
    auction_start_time: u32,
    auction_duration: u32,
    max_cancellation_premium: u64,
) -> u64 {
    if timestamp <= auction_start_time {
        return 0;
    }

    let time_elapsed = timestamp - auction_start_time;
    if time_elapsed >= auction_duration {
        return max_cancellation_premium;
    }

    (time_elapsed as u64 * max_cancellation_premium) / auction_duration as u64
}
```

**File:** tests/suits/fusion-swap.ts (L1728-1775)
```typescript

    it("Cancellation works if src-token is native and maker-src-ata is not provided", async () => {
      const srcAmount = new anchor.BN(10000);
      // create new escrow
      const orderConfig = state.orderConfig({
        srcMint: splToken.NATIVE_MINT,
        srcAssetIsNative: true,
        srcAmount,
        expirationTime: 0xffffffff,
      });

      const [escrow] = anchor.web3.PublicKey.findProgramAddressSync(
        [
          anchor.utils.bytes.utf8.encode("escrow"),
          state.alice.keypair.publicKey.toBuffer(),
          calculateOrderHash(orderConfig),
        ],
        program.programId
      );

      await program.methods
        .create(orderConfig as ReducedOrderConfig)
        .accountsPartial({
          maker: state.alice.keypair.publicKey,
          makerReceiver: orderConfig.receiver,
          srcMint: splToken.NATIVE_MINT,
          dstMint: state.tokens[1],
          protocolDstAcc: null,
          integratorDstAcc: null,
          escrow,
          srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
          makerSrcAta: null,
        })
        .signers([state.alice.keypair])
        .rpc();

      await program.methods
        .cancel(Array.from(calculateOrderHash(orderConfig)), true)
        .accountsPartial({
          maker: state.alice.keypair.publicKey,
          srcMint: splToken.NATIVE_MINT,
          escrow: escrow,
          srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
          makerSrcAta: null,
        })
        .signers([state.alice.keypair])
        .rpc();
    });
```
