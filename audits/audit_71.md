# Audit Report

## Title
Token-2022 Incompatibility in Fill Script Causes Denial of Service on Order Execution

## Summary
The `fill()` function in `scripts/fusion-swap/fill.ts` hardcodes `TOKEN_PROGRAM_ID` for all token operations, causing incompatibility with Token-2022 tokens. This results in order execution failures when Token-2022 mints are used, as the script derives incorrect Associated Token Account (ATA) addresses and passes wrong token program IDs to the on-chain program.

## Finding Description

The vulnerability exists in the client-side fill script's token program handling. While the on-chain Fusion Swap program properly supports both standard SPL tokens and Token-2022 through the `TokenInterface` abstraction [1](#0-0) , the fill script fails to detect or accommodate Token-2022 tokens.

**Critical Issues:**

1. **Hardcoded Token Program IDs**: The script unconditionally uses `TOKEN_PROGRAM_ID` for both source and destination token programs [2](#0-1) .

2. **Incorrect ATA Derivation**: When deriving the escrow source ATA address, the script calls `getAssociatedTokenAddress` without specifying the token program parameter, causing it to default to `TOKEN_PROGRAM_ID` [3](#0-2) . Similarly for the taker's source ATA [4](#0-3) .

3. **Missing Token Program Detection**: The script lacks any logic to determine which token program a mint uses. The utility function `getTokenDecimals()` calls `getMint()` but doesn't extract or use the program ID information [5](#0-4) .

**Execution Flow Breakdown:**

When a maker creates an order with Token-2022 tokens using proper token program specification (as shown in test utilities [6](#0-5) ), the escrow and ATAs are correctly created with `TOKEN_2022_PROGRAM_ID`. However, when a resolver attempts to fill using the production script:

1. The script derives escrow ATA address using `TOKEN_PROGRAM_ID` → **Wrong address**
2. The script passes `TOKEN_PROGRAM_ID` to the program → **Account validation fails**
3. The on-chain program validates ATAs using the `associated_token::token_program` constraint [7](#0-6) 
4. Transaction reverts due to account mismatch

**Invariants Violated:**

- **Token Safety**: Token transfers cannot execute properly when wrong program IDs are used
- **Account Validation**: The script bypasses proper account derivation by not checking token program types

## Impact Explanation

**Medium Severity** - This vulnerability causes a Denial of Service condition for Token-2022 orders:

1. **Order Unfillability**: Any order created with Token-2022 tokens (either `srcMint` or `dstMint`) cannot be filled using the provided client script
2. **Funds Temporarily Locked**: Maker's tokens remain locked in escrow until manual cancellation
3. **Protocol Functionality Break**: As Token-2022 adoption grows in the Solana ecosystem, this creates a significant usability gap
4. **No Direct Fund Loss**: Makers can cancel orders to recover funds; funds are not permanently lost or stolen
5. **Resolver DoS**: Resolvers waste gas attempting to fill orders that will always fail

The impact is not High or Critical because:
- No funds can be stolen or permanently lost
- The on-chain program's security model prevents exploitation
- Recovery mechanism exists (maker cancellation)
- Issue is isolated to client script, not core protocol logic

## Likelihood Explanation

**High Likelihood** - This issue will occur predictably:

1. **Growing Token-2022 Usage**: Token-2022 is increasingly adopted for its advanced features (transfer fees, transfer hooks, etc.)
2. **Automatic Failure**: Any legitimate attempt to fill a Token-2022 order with the provided script will fail
3. **No Attack Required**: This is an operational bug, not requiring malicious intent
4. **User-Facing Impact**: Both order creators and resolvers will encounter this issue in normal operations

The combination of high likelihood and medium impact justifies immediate remediation.

## Recommendation

**Fix 1: Add Token Program Detection**

Modify `scripts/utils.ts` to detect and return the token program:

```typescript
export async function getMintInfo(
  connection: Connection,
  mint: PublicKey
): Promise<{ decimals: number; programId: PublicKey }> {
  const mintAccount = await splToken.getMint(connection, mint);
  // Token-2022 mints will have owner = TOKEN_2022_PROGRAM_ID
  const programId = mintAccount.owner;
  return { decimals: mintAccount.decimals, programId };
}
```

**Fix 2: Update Fill Script**

Modify `scripts/fusion-swap/fill.ts` to use detected token programs:

```typescript
// Detect token programs
const srcMintInfo = await getMintInfo(connection, orderConfig.srcMint);
const dstMintInfo = await getMintInfo(connection, orderConfig.dstMint);

// Derive ATAs with correct program IDs
const escrowSrcAta = await splToken.getAssociatedTokenAddress(
  orderConfig.srcMint,
  escrow,
  true,
  srcMintInfo.programId  // Use detected program
);

const takerSrcAta = await splToken.getAssociatedTokenAddress(
  orderConfig.srcMint,
  takerKeypair.publicKey,
  false,
  srcMintInfo.programId  // Use detected program
);

// Pass correct programs to instruction
const fillIx = await program.methods
  .fill(reducedOrderConfig, new BN(amount * Math.pow(10, srcMintInfo.decimals)))
  .accountsPartial({
    // ... other accounts
    srcTokenProgram: srcMintInfo.programId,  // Dynamic
    dstTokenProgram: dstMintInfo.programId,  // Dynamic
  })
  .instruction();
```

**Fix 3: Update Create and Cancel Scripts Similarly**

Apply the same pattern to `scripts/fusion-swap/create.ts` [8](#0-7)  and `scripts/fusion-swap/cancel.ts` [9](#0-8) .

## Proof of Concept

**Reproduction Steps:**

1. Deploy the Fusion Swap program
2. Create a Token-2022 mint with any extension (e.g., transfer fee)
3. Create an order using Token-2022 as srcMint:
   ```bash
   # Order creation would need to specify TOKEN_2022_PROGRAM_ID
   # Currently create.ts also has the same bug
   ```
4. Attempt to fill the order using the provided `fill.ts` script
5. Observe transaction failure with account validation error

**Expected Error:**
```
Error: AnchorError caused by account: escrow_src_ata. 
Error Code: ConstraintAssociatedToken. 
Error Message: An associated token account constraint was violated.
```

**Test Case Verification:**

The test suite correctly handles Token-2022 by explicitly passing token programs [10](#0-9) , demonstrating that the on-chain program supports Token-2022 but the production scripts do not.

## Notes

- The on-chain program has proper Token-2022 support through `TokenInterface` abstraction
- This is purely a client-side script issue, not a protocol vulnerability
- Test utilities demonstrate the correct implementation pattern that should be applied to production scripts
- Token-2022 extensions requiring extra accounts (e.g., transfer hooks) would require additional program modifications beyond this fix

### Citations

**File:** programs/fusion-swap/src/lib.rs (L6-9)
```rust
    token_interface::{
        close_account, transfer_checked, CloseAccount, Mint, TokenAccount, TokenInterface,
        TransferChecked,
    },
```

**File:** programs/fusion-swap/src/lib.rs (L551-557)
```rust
    #[account(
        mut,
        associated_token::mint = src_mint,
        associated_token::authority = escrow,
        associated_token::token_program = src_token_program,
    )]
    escrow_src_ata: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** scripts/fusion-swap/fill.ts (L46-50)
```typescript
  const escrowSrcAta = await splToken.getAssociatedTokenAddress(
    orderConfig.srcMint,
    escrow,
    true
  );
```

**File:** scripts/fusion-swap/fill.ts (L57-60)
```typescript
  const takerSrcAta = await splToken.getAssociatedTokenAddress(
    orderConfig.srcMint,
    takerKeypair.publicKey
  );
```

**File:** scripts/fusion-swap/fill.ts (L81-82)
```typescript
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
      dstTokenProgram: splToken.TOKEN_PROGRAM_ID,
```

**File:** scripts/utils.ts (L61-67)
```typescript
export async function getTokenDecimals(
  connection: Connection,
  mint: PublicKey
): Promise<number> {
  const mintAccount = await splToken.getMint(connection, mint);
  return mintAccount.decimals;
}
```

**File:** tests/utils/utils.ts (L324-329)
```typescript
    const escrowAta = await splToken.getAssociatedTokenAddress(
      orderConfig.srcMint,
      escrow,
      true,
      srcTokenProgram
    );
```

**File:** scripts/fusion-swap/create.ts (L51-51)
```typescript
  srcTokenProgram: PublicKey = splToken.TOKEN_PROGRAM_ID
```

**File:** scripts/fusion-swap/cancel.ts (L52-52)
```typescript
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
```

**File:** tests/suits/fusion-swap.ts (L400-428)
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
```
