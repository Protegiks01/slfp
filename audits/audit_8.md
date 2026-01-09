# Audit Report

## Title
Token-2022 Transfer Fees Cause Incorrect Economic Calculations Leading to Resolver Fund Loss

## Summary
The Fusion Swap protocol uses `TokenInterface` which supports both SPL Token and Token-2022 programs, but fails to account for Token-2022 transfer fee extensions. When orders involve tokens with transfer fees enabled, resolvers receive fewer tokens than expected while still paying the full calculated amount, resulting in direct financial loss.

## Finding Description

The `Fill` struct in the fusion-swap program allows `src_token_program` and `dst_token_program` to be different token program implementations. [1](#0-0) 

The protocol uses Anchor's `TokenInterface` which supports both the original SPL Token program and the newer Token-2022 program. [2](#0-1) 

Token-2022 introduces optional extensions including transfer fees, where a configured percentage of each transfer is automatically withheld by the token program. When the `fill` function executes, it transfers source tokens from escrow to the resolver: [3](#0-2) 

The critical flaw occurs when calculating the destination amount the resolver must pay. The protocol uses the `amount` parameter (the amount transferred FROM escrow) to calculate `dst_amount`: [4](#0-3) 

However, if `src_mint` uses Token-2022 with transfer fees enabled, the resolver's account receives `amount * (1 - fee_rate)`, not the full `amount`. The protocol has no mechanism to query or account for the actual tokens received after fees.

**Attack Scenario:**
1. Attacker creates a Token-2022 mint with 50% transfer fee configured
2. Attacker creates an order selling 1000 tokens of this mint for 500 USDC
3. When a resolver fills the order:
   - Escrow transfers 1000 tokens via `transfer_checked` 
   - Due to 50% transfer fee, resolver receives only 500 tokens (500 go to fee collector)
   - Protocol calculates `dst_amount` based on full 1000 tokens transferred
   - Resolver must pay 500 USDC
   - **Resolver paid 500 USDC for 500 tokens instead of 1000 tokens - 50% loss**

This breaks **Invariant #2 (Token Safety)**: "Token transfers must be properly authorized and accounted for." The protocol fails to properly account for the actual token amounts received versus transferred.

## Impact Explanation

**Severity: HIGH**

This vulnerability causes direct financial loss to resolvers filling orders:
- Any order using Token-2022 mints with transfer fees enabled is affected
- Loss percentage equals the transfer fee percentage (can be up to 100%)
- Affects all resolvers attempting to fill such orders
- No way for resolvers to detect this condition before transaction execution
- Breaks the core economic model of the protocol

The impact qualifies as HIGH severity because it enables:
- Single order compromise through economic exploitation
- Direct token theft from resolvers
- Systematic exploitation across multiple orders using fee tokens

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely because:
- **No privileged access required**: Any user can create Token-2022 mints with transfer fees
- **Simple execution**: Attacker just creates a mint with fees and posts an order
- **No detection mechanism**: Protocol has no validation or warning about transfer fees
- **Economic incentive**: Attacker profits from resolver's loss
- **Token-2022 adoption increasing**: As Token-2022 becomes more prevalent, more tokens will have extensions like transfer fees

The protocol explicitly supports Token-2022 through `TokenInterface`, making this a supported but unsafe configuration rather than an edge case.

## Recommendation

**Immediate Fix**: Add validation to reject tokens with transfer fee extensions, or implement proper accounting for actual received amounts.

**Option 1 - Reject Transfer Fee Tokens (Safer)**:
Add validation in both `create` and `fill` instructions to check if mints have transfer fee extensions enabled and reject them:

```rust
// In fill function, after line 144:
// Check if src_mint has transfer fees
if ctx.accounts.src_mint.to_account_info().owner == &spl_token_2022::id() {
    let mint_data = ctx.accounts.src_mint.to_account_info().try_borrow_data()?;
    let mint = StateWithExtensions::<Mint>::unpack(&mint_data)?;
    require!(
        mint.get_extension::<TransferFeeConfig>().is_err(),
        FusionError::TransferFeesNotSupported
    );
}

// Similar check for dst_mint
```

**Option 2 - Account for Transfer Fees (More Complex)**:
Calculate actual received amounts after transfers and adjust economic calculations accordingly. This requires querying the actual token balances before and after transfers, adding significant complexity and compute costs.

**Recommended Approach**: Option 1 is safer and simpler. Token-2022 transfer fees are incompatible with the protocol's economic model where swap ratios must be precise and deterministic.

## Proof of Concept

```rust
#[test]
fn test_transfer_fee_exploit() {
    // 1. Create Token-2022 mint with 50% transfer fee
    let transfer_fee_config = TransferFeeConfig {
        transfer_fee_basis_points: 5000, // 50%
        maximum_fee: u64::MAX,
        ..Default::default()
    };
    
    let src_mint = create_token_2022_mint_with_extension(
        &mut context,
        &payer,
        &payer.pubkey(),
        9, // decimals
        vec![ExtensionInitializationParams::TransferFeeConfig { 
            transfer_fee_config 
        }],
    );
    
    // 2. Create order selling 1000 tokens for 500 USDC
    let order = OrderConfig {
        src_amount: 1000_000_000_000, // 1000 tokens
        min_dst_amount: 500_000_000,   // 500 USDC minimum
        estimated_dst_amount: 500_000_000,
        // ... other config
    };
    
    // 3. Fill the order
    let resolver_src_balance_before = get_token_balance(&resolver_src_ata);
    let resolver_dst_balance_before = get_token_balance(&resolver_dst_ata);
    
    program.methods
        .fill(order, 1000_000_000_000)
        .accounts(/* ... */)
        .signers([&resolver])
        .rpc()?;
    
    let resolver_src_balance_after = get_token_balance(&resolver_src_ata);
    let resolver_dst_balance_after = get_token_balance(&resolver_dst_ata);
    
    // 4. Verify the exploit
    let src_received = resolver_src_balance_after - resolver_src_balance_before;
    let dst_paid = resolver_dst_balance_before - resolver_dst_balance_after;
    
    // Resolver received only 500 tokens due to 50% fee
    assert_eq!(src_received, 500_000_000_000);
    // But paid for 1000 tokens
    assert_eq!(dst_paid, 500_000_000);
    
    // Expected fair rate: 500 USDC for 1000 tokens = 0.5 USDC per token
    // Actual rate paid: 500 USDC for 500 tokens = 1.0 USDC per token
    // Resolver lost 50% of value
}
```

## Notes

The vulnerability is directly related to the security question about inconsistencies when `src_token_program` and `dst_token_program` are different. While the programs themselves can safely be different (SPL Token vs Token-2022), the protocol fails to handle Token-2022-specific features like transfer fees that create discrepancies between transferred and received amounts.

Additional considerations:
- The same issue affects destination token transfers if `dst_mint` has transfer fees - the maker, protocol, and integrator all receive less than calculated
- The missing `token_program` constraint on `taker_src_ata` [5](#0-4)  is a separate minor issue that causes transaction failures but not fund loss
- Tests confirm Token-2022 support but don't test with transfer fee extensions [6](#0-5)

### Citations

**File:** programs/fusion-swap/src/lib.rs (L6-9)
```rust
    token_interface::{
        close_account, transfer_checked, CloseAccount, Mint, TokenAccount, TokenInterface,
        TransferChecked,
    },
```

**File:** programs/fusion-swap/src/lib.rs (L166-184)
```rust
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.src_token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.escrow_src_ata.to_account_info(),
                    mint: ctx.accounts.src_mint.to_account_info(),
                    to: ctx.accounts.taker_src_ata.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                &[&[
                    "escrow".as_bytes(),
                    ctx.accounts.maker.key().as_ref(),
                    order_hash,
                    &[ctx.bumps.escrow],
                ]],
            ),
            amount,
            ctx.accounts.src_mint.decimals,
        )?;
```

**File:** programs/fusion-swap/src/lib.rs (L186-191)
```rust
        let dst_amount = get_dst_amount(
            order.src_amount,
            order.min_dst_amount,
            amount,
            Some(&order.dutch_auction_data),
        )?;
```

**File:** programs/fusion-swap/src/lib.rs (L560-564)
```rust
    #[account(
        mut,
        constraint = taker_src_ata.mint.key() == src_mint.key()
    )]
    taker_src_ata: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/fusion-swap/src/lib.rs (L566-567)
```rust
    src_token_program: Interface<'info, TokenInterface>,
    dst_token_program: Interface<'info, TokenInterface>,
```

**File:** tests/suits/fusion-swap.ts (L400-448)
```typescript
      it("Execute trade with SPL Token -> Token 2022", async () => {
        const dstTokenProgram = splToken.TOKEN_2022_PROGRAM_ID;
        const dstMint = state.tokens[state.tokens.length - 1]; // Token 2022
        const makerDstAta = state.alice.atas[dstMint.toString()].address;
        const takerDstAta = state.bob.atas[dstMint.toString()].address;
        const escrow = await state.createEscrow({
          escrowProgram: program,
          payer,
          provider,
          orderConfig: {
            dstMint,
          },
        });

        const transactionPromise = () =>
          program.methods
            .fill(escrow.reducedOrderConfig, state.defaultSrcAmount)
            .accountsPartial({
              ...state.buildAccountsDataForFill({
                escrow: escrow.escrow,
                escrowSrcAta: escrow.ata,
                dstMint,
                makerDstAta,
                takerDstAta,
                dstTokenProgram,
              }),
            })
            .signers([state.bob.keypair])
            .rpc();

        const results = await trackReceivedTokenAndTx(
          provider.connection,
          [
            { publicKey: makerDstAta, programId: dstTokenProgram },
            {
              publicKey: state.bob.atas[state.tokens[0].toString()].address,
              programId: splToken.TOKEN_PROGRAM_ID,
            },
            { publicKey: takerDstAta, programId: dstTokenProgram },
          ],
          transactionPromise
        );

        expect(results).to.be.deep.eq([
          BigInt(state.defaultDstAmount.toNumber()),
          BigInt(state.defaultSrcAmount.toNumber()),
          -BigInt(state.defaultDstAmount.toNumber()),
        ]);
      });
```
