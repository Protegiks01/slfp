# Audit Report

## Title
Lack of Account Type Validation in Fill Script Enables Permanent Fund Lock Through Token Account Authority Confusion

## Summary
The fill script (`scripts/fusion-swap/fill.ts`) does not validate that `makerReceiver` is an appropriate account type before filling orders. When `dst_asset_is_native = false` and `makerReceiver` is itself a token account (ATA), the protocol creates a new ATA with the token account as its authority. Since token accounts cannot sign transactions, any tokens sent to this derived ATA become permanently locked and unrecoverable. [1](#0-0) 

## Finding Description

The fill script accepts `makerReceiver` from the order configuration without any account type validation: [2](#0-1) 

In the program's Fill instruction handler, when `order.dst_asset_is_native = false`, tokens are transferred to `maker_dst_ata`, which is an Associated Token Account (ATA) derived with `maker_receiver` as its authority: [3](#0-2) 

The program uses `maker_receiver` as an unchecked account with no validation on its type: [4](#0-3) 

When `dst_asset_is_native = false`, the token transfer goes to `maker_dst_ata`, not directly to `maker_receiver`: [5](#0-4) 

**Attack Scenario:**
1. User creates an order intending to receive SPL tokens (dst_asset_is_native = false)
2. User accidentally provides their existing token account address (an ATA) as the `receiver` parameter instead of their wallet address
3. The create script doesn't validate this mistake
4. A resolver calls the fill script to fill the order
5. The fill script doesn't validate that receiver is a token account
6. The program derives `maker_dst_ata = getAssociatedTokenAddress(dst_mint, [token_account_address])`
7. This creates an ATA with authority = [a token account address]
8. Tokens are transferred to this new ATA
9. To withdraw tokens, the authority (the token account) would need to sign, but token accounts are owned by the Token Program and have no private keys
10. **Tokens are permanently locked with no way to recover them**

This breaks the **Token Safety** invariant: "Token transfers must be properly authorized and accounted for."

## Impact Explanation

**Severity: Medium**

This vulnerability results in permanent loss of user funds in specific scenarios:
- **Affected Users**: Individual makers who accidentally specify a token account as their receiver when creating orders with non-native destination tokens
- **Potential Damage**: Complete loss of destination tokens for the affected order (could range from small amounts to significant sums depending on order size)
- **Recovery**: No recovery mechanism exists - tokens sent to an ATA with a token account as authority are permanently inaccessible

The impact is classified as Medium because:
1. It requires user error in order creation (providing wrong receiver address)
2. It affects individual orders, not the entire protocol
3. However, it results in **permanent and complete fund loss** for affected users
4. The issue is preventable with proper validation

## Likelihood Explanation

**Likelihood: Medium**

The likelihood is assessed as Medium because:

**Factors Increasing Likelihood:**
- Common user confusion between wallet addresses and token account addresses
- Both are valid Solana public keys with identical format (base58-encoded 32 bytes)
- No client-side validation exists to catch this error
- Users copying addresses from explorers might inadvertently copy an ATA address instead of their wallet
- The create script uses default parameters that don't validate receiver type

**Factors Decreasing Likelihood:**
- Requires the maker to make a specific mistake during order creation
- Most wallets display the main wallet address prominently, reducing (but not eliminating) the chance of using an ATA address
- Experienced users are less likely to make this mistake

**Real-World Context:**
In Solana, this type of confusion is not uncommon. Users frequently confuse their wallet address (System Program-owned account) with their token account addresses (Token Program-owned accounts). Block explorers show both types of addresses, and users might copy the wrong one.

## Recommendation

**Immediate Fix for Fill Script:**

Add account type validation in `fill.ts` before executing the fill instruction:

```typescript
async function fill(
  connection: Connection,
  program: Program<FusionSwap>,
  whitelistProgramId: PublicKey,
  takerKeypair: Keypair,
  maker: PublicKey,
  amount: number,
  orderConfig: OrderConfig,
  reducedOrderConfig: ReducedOrderConfig
): Promise<void> {
  // VALIDATION: Check receiver account type matches dst_asset_is_native expectation
  if (!reducedOrderConfig.dstAssetIsNative) {
    try {
      const receiverAccountInfo = await connection.getAccountInfo(orderConfig.receiver);
      
      if (receiverAccountInfo) {
        // Check if receiver is a token account (owned by Token Program)
        const isTokenAccount = 
          receiverAccountInfo.owner.equals(splToken.TOKEN_PROGRAM_ID) ||
          receiverAccountInfo.owner.equals(splToken.TOKEN_2022_PROGRAM_ID);
        
        if (isTokenAccount) {
          throw new Error(
            `VALIDATION ERROR: makerReceiver (${orderConfig.receiver.toString()}) ` +
            `is a token account, but should be a wallet address when dst_asset_is_native = false. ` +
            `Filling this order would result in permanent fund loss. ` +
            `The receiver should be a System Program-owned account (wallet address), not a Token Program-owned account.`
          );
        }
      }
    } catch (error) {
      console.error("Failed to validate receiver account type:", error);
      throw error;
    }
  }

  // ... rest of fill logic
}
```

**Additional Recommendations:**

1. **Create Script Validation**: Add similar validation in `create.ts` to prevent orders from being created with incorrect receiver types
2. **Program-Level Constraint**: Consider adding a program-level check that validates receiver ownership (though this would require breaking changes)
3. **Documentation**: Clearly document that `receiver` parameter must be a wallet address (System Program-owned account) when receiving SPL tokens
4. **User Interface Warnings**: If there's a UI, add warnings when users input addresses that look like token accounts

## Proof of Concept

```typescript
// Proof of Concept: Demonstrating the vulnerability
// This shows how an order with a token account as receiver leads to fund lock

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import * as splToken from "@solana/spl-token";
import { BN } from "@coral-xyz/anchor";

async function demonstrateVulnerability() {
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  // Setup: User has a wallet and an existing token account
  const userWallet = Keypair.generate();
  const srcMint = new PublicKey("So11111111111111111111111111111111111111112"); // Native SOL
  const dstMint = Keypair.generate().publicKey; // Some SPL token
  
  // User's existing token account for srcMint
  const userTokenAccount = await splToken.getAssociatedTokenAddress(
    srcMint,
    userWallet.publicKey
  );
  
  // MISTAKE: User accidentally uses their token account as receiver instead of wallet
  const incorrectReceiver = userTokenAccount; // This is a TOKEN ACCOUNT, not a wallet!
  
  console.log("User Wallet (correct receiver):", userWallet.publicKey.toString());
  console.log("User Token Account (incorrect receiver):", incorrectReceiver.toString());
  
  // When order is filled with dst_asset_is_native = false:
  // 1. Program derives maker_dst_ata with authority = incorrectReceiver (a token account)
  const derivedATA = await splToken.getAssociatedTokenAddress(
    dstMint,
    incorrectReceiver // Authority is a TOKEN ACCOUNT!
  );
  
  console.log("\nDerived ATA for destination tokens:", derivedATA.toString());
  console.log("This ATA has authority:", incorrectReceiver.toString());
  console.log("But this authority is a token account, not a wallet!");
  console.log("\n❌ RESULT: Tokens sent to this ATA are PERMANENTLY LOCKED");
  console.log("❌ Token accounts cannot sign transactions to authorize withdrawals");
  console.log("❌ No recovery mechanism exists");
  
  // Verification: Check account ownership
  const tokenAccountInfo = await connection.getAccountInfo(incorrectReceiver);
  if (tokenAccountInfo) {
    console.log("\nReceiver account owner:", tokenAccountInfo.owner.toString());
    console.log("Is Token Program?", 
      tokenAccountInfo.owner.equals(splToken.TOKEN_PROGRAM_ID) ? "YES ⚠️" : "NO"
    );
  }
}

// Expected Output:
// User Wallet (correct receiver): [wallet pubkey]
// User Token Account (incorrect receiver): [ATA pubkey]
// 
// Derived ATA for destination tokens: [new ATA pubkey]
// This ATA has authority: [ATA pubkey] <- TOKEN ACCOUNT AS AUTHORITY!
// But this authority is a token account, not a wallet!
//
// ❌ RESULT: Tokens sent to this ATA are PERMANENTLY LOCKED
// ❌ Token accounts cannot sign transactions to authorize withdrawals
// ❌ No recovery mechanism exists
```

## Notes

**Root Cause Analysis:**
The vulnerability exists at multiple layers:
1. **Script Layer**: Neither `create.ts` nor `fill.ts` validate account types
2. **Program Layer**: The `Fill` struct uses `UncheckedAccount` for `maker_receiver` with no constraints on account ownership
3. **Design Layer**: The protocol assumes users will provide correct account types, with no defensive validation

**Additional Context:**
- This is particularly dangerous in Solana where token accounts (ATAs) and wallet addresses are both valid `PublicKey` types with identical formats
- The test suite shows proper usage (using wallet keypairs as receivers) but doesn't test error cases with token accounts as receivers
- The issue compounds because the order hash includes the receiver, so once created with wrong receiver, it cannot be changed

**Distinction from Native Asset Transfers:**
When `dst_asset_is_native = true`, SOL is transferred directly to `maker_receiver`. Even if `maker_receiver` is a token account, the SOL can technically be accessed by closing the account, so this scenario is less severe (though still not ideal).

### Citations

**File:** scripts/fusion-swap/fill.ts (L67-85)
```typescript
  const fillIx = await program.methods
    .fill(reducedOrderConfig, new BN(amount * Math.pow(10, srcMintDecimals)))
    .accountsPartial({
      taker: takerKeypair.publicKey,
      resolverAccess,
      maker,
      makerReceiver: orderConfig.receiver,
      srcMint: orderConfig.srcMint,
      dstMint: orderConfig.dstMint,
      escrow,
      escrowSrcAta,
      takerSrcAta,
      protocolDstAcc: orderConfig.fee.protocolDstAcc,
      integratorDstAcc: orderConfig.fee.integratorDstAcc,
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
      dstTokenProgram: splToken.TOKEN_PROGRAM_ID,
    })
    .signers([takerKeypair])
    .instruction();
```

**File:** programs/fusion-swap/src/lib.rs (L210-227)
```rust
            UniTransferParams::TokenTransfer {
                from: ctx
                    .accounts
                    .taker_dst_ata
                    .as_ref()
                    .ok_or(FusionError::MissingTakerDstAta)?
                    .to_account_info(),
                authority: ctx.accounts.taker.to_account_info(),
                to: ctx
                    .accounts
                    .maker_dst_ata
                    .as_ref()
                    .ok_or(FusionError::MissingMakerDstAta)?
                    .to_account_info(),
                mint: *ctx.accounts.dst_mint.clone(),
                amount: maker_dst_amount,
                program: ctx.accounts.dst_token_program.clone(),
            }
```

**File:** programs/fusion-swap/src/lib.rs (L522-524)
```rust
    /// CHECK: maker_receiver only has to be equal to escrow parameter
    #[account(mut)]
    maker_receiver: UncheckedAccount<'info>,
```

**File:** programs/fusion-swap/src/lib.rs (L572-579)
```rust
    #[account(
        init_if_needed,
        payer = taker,
        associated_token::mint = dst_mint,
        associated_token::authority = maker_receiver,
        associated_token::token_program = dst_token_program,
    )]
    maker_dst_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
```
