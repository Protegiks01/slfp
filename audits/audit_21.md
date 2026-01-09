# Audit Report

## Title
Transaction Failure and Potential Account Bricking in Wrapped SOL Order Creation Due to Missing ATA Creation Check

## Summary
The `create()` function in `scripts/fusion-swap/create.ts` attempts to wrap native SOL by transferring it to a derived Associated Token Account (ATA) address without first verifying the account exists or creating it. If the ATA doesn't exist, `SystemProgram.transfer()` creates a System Program-owned account instead of a Token Program-owned account, causing `createSyncNativeInstruction` to fail. This results in transaction failures, wasted gas fees, and creates a potential griefing vector where attackers can frontrun transactions to permanently brick ATA addresses.

## Finding Description

In the create order script, when a user wants to create an order selling wrapped SOL (`srcMint == NATIVE_MINT`), the script performs SOL wrapping preparation: [1](#0-0) 

The vulnerability occurs because:

1. **Address Derivation Only**: `getAssociatedTokenAddress()` only computes the PDA address where the ATA should exist - it does not check if the account actually exists or create it.

2. **Incorrect Account Creation**: `SystemProgram.transfer()` sends SOL to the derived address. If no account exists at that address, Solana automatically creates a **System Program-owned account** with the transferred lamports.

3. **Type Mismatch**: `createSyncNativeInstruction` expects the account to be a **Token Program-owned account** with proper token account data structure. When it encounters a System Program-owned account, the instruction fails.

The program's Create context confirms this is problematic: [2](#0-1) 

The `maker_src_ata` account has no `init` or `init_if_needed` constraint, meaning it must already exist as a valid Token Program account when provided to the program.

This breaks the **Token Safety** and **Atomic Execution** invariants:
- Token operations fail to execute properly when account ownership is incorrect
- The entire transaction fails atomically, but only after wasting gas fees

## Impact Explanation

**High Severity Impact:**

1. **Transaction Failures**: Any user whose wrapped SOL ATA doesn't exist will experience guaranteed transaction failure when attempting to create orders with native SOL as the source token. This affects:
   - New users who haven't used wrapped SOL before
   - Users who closed their wrapped SOL accounts to reclaim rent
   - Users switching wallets or creating orders from fresh accounts

2. **Gas Fee Loss**: Users waste transaction fees on failed transactions, with no clear error message indicating the root cause.

3. **Account Bricking (Griefing Vector)**: An attacker can monitor the mempool for users attempting to create wrapped SOL orders and frontrun them by transferring minimal SOL to the target ATA address. This creates a System Program-owned account at that address, permanently preventing the legitimate user from using that ATA for wrapped SOL operations without first closing the System account.

4. **Protocol Disruption**: Multiple users may be blocked from creating wrapped SOL orders, reducing protocol liquidity and user experience.

## Likelihood Explanation

**High Likelihood:**

1. **Common Scenario**: Many users will not have pre-existing wrapped SOL ATAs, especially:
   - First-time protocol users
   - Users who practice good account hygiene by closing unused ATAs
   - Users creating orders from new wallets

2. **No Validation**: The script performs no existence check before attempting the transfer, guaranteeing failure for affected users.

3. **Frontrunning Feasibility**: On Solana, mempool monitoring and transaction frontrunning are technically feasible, making the griefing attack realistic for motivated attackers.

4. **Silent Failure**: Users receive generic transaction failure errors without understanding they need to manually create the ATA first.

## Recommendation

Add proper ATA existence checking and creation before attempting to wrap SOL:

```typescript
if (srcMint.equals(splToken.NATIVE_MINT)) {
  // Wrap SOL to wSOL
  const makerNativeAta = await splToken.getAssociatedTokenAddress(
    splToken.NATIVE_MINT,
    makerKeypair.publicKey
  );

  // Check if ATA exists, create if necessary
  const ataInfo = await connection.getAccountInfo(makerNativeAta);
  
  if (!ataInfo) {
    // ATA doesn't exist, add instruction to create it
    const createAtaIx = splToken.createAssociatedTokenAccountInstruction(
      makerKeypair.publicKey,  // payer
      makerNativeAta,          // ata
      makerKeypair.publicKey,  // owner
      splToken.NATIVE_MINT     // mint
    );
    tx.add(createAtaIx);
  }

  const transferIx = SystemProgram.transfer({
    fromPubkey: makerKeypair.publicKey,
    toPubkey: makerNativeAta,
    lamports: srcAmount.toNumber(),
  });
  tx.add(transferIx);

  tx.add(splToken.createSyncNativeInstruction(makerNativeAta));
}
```

This matches the pattern used in the test utilities where ATAs are explicitly created before use: [3](#0-2) 

## Proof of Concept

**Reproduction Steps:**

1. Create a new wallet keypair that has never interacted with wrapped SOL (no existing NATIVE_MINT ATA)
2. Fund the wallet with sufficient SOL for the order and gas
3. Attempt to create an order using the create.ts script with `srcMint = NATIVE_MINT`
4. Observe transaction failure when `createSyncNativeInstruction` encounters the System Program-owned account

**Expected Behavior:**
Transaction fails with an error indicating the account has the wrong owner or invalid token account data.

**Griefing Attack PoC:**
1. Monitor mempool for order creation transactions where `srcMint == NATIVE_MINT`
2. Identify the target user's wrapped SOL ATA address
3. Submit a frontrunning transaction with higher priority fee that transfers 1 lamport to the ATA address
4. User's transaction fails because their ATA address is now occupied by a System Program account
5. User must now manually close the System account (if possible) before being able to create wrapped SOL orders

**Test Implementation:**
A Rust/TypeScript test could be created that:
1. Creates a fresh keypair
2. Verifies no NATIVE_MINT ATA exists
3. Attempts to call the vulnerable create function
4. Asserts the transaction fails
5. Verifies a System-owned account was created at the ATA address

## Notes

The vulnerability exists in the client-side script, not the on-chain program. However, it's critical for protocol usability and creates a security issue through the potential griefing attack vector. The fix is straightforward and should be implemented to ensure reliable wrapped SOL order creation.

### Citations

**File:** scripts/fusion-swap/create.ts (L102-117)
```typescript
  if (srcMint == splToken.NATIVE_MINT) {
    // Wrap SOL to wSOL
    const makerNativeAta = await splToken.getAssociatedTokenAddress(
      splToken.NATIVE_MINT,
      makerKeypair.publicKey
    );

    const transferIx = SystemProgram.transfer({
      fromPubkey: makerKeypair.publicKey,
      toPubkey: makerNativeAta,
      lamports: srcAmount.toNumber(),
    });
    tx.add(transferIx);

    tx.add(splToken.createSyncNativeInstruction(makerNativeAta));
  }
```

**File:** programs/fusion-swap/src/lib.rs (L482-489)
```rust
    /// Maker's ATA of src_mint
    #[account(
        mut,
        associated_token::mint = src_mint,
        associated_token::authority = maker,
        associated_token::token_program = src_token_program,
    )]
    maker_src_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
```

**File:** tests/utils/utils.ts (L555-561)
```typescript
      const pubkey = await tokenLibrary.createAssociatedTokenAccount(
        connection,
        payer,
        token,
        keypair.publicKey,
        ...extraArgs
      );
```
