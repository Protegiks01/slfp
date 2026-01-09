# Audit Report

## Title
Token2022 Orders Cannot Be Cancelled Using Provided Script Due to Missing Token Program Parameter

## Summary
The `cancel.ts` script hardcodes `TOKEN_PROGRAM_ID` when deriving the escrow ATA and invoking the cancel instruction, preventing cancellation of orders created with Token2022 (TOKEN_2022_PROGRAM_ID). Users who create Token2022 orders cannot cancel them using the provided script.

## Finding Description
The 1inch Solana Fusion Protocol supports both standard SPL tokens and Token2022 tokens. When creating an order, users can specify which token program to use via the `srcTokenProgram` parameter. [1](#0-0) 

However, the `cancel.ts` script has a critical limitation. At line 39-43, it derives the escrow ATA using `getAssociatedTokenAddress` with only three parameters (mint, owner, allowOwnerOffCurve), omitting the fourth parameter for the token program. [2](#0-1) 

When the token program parameter is omitted, it defaults to `TOKEN_PROGRAM_ID`. Additionally, at line 52, the script explicitly passes `TOKEN_PROGRAM_ID` to the cancel instruction. [3](#0-2) 

The on-chain `Cancel` instruction validates that the provided `escrow_src_ata` matches the expected ATA derived from the mint, escrow authority, and token program. [4](#0-3) 

**The Problem:**
- Associated Token Account addresses are derived from: `[wallet, token_program, mint]`
- Token2022 uses a different program ID (`TOKEN_2022_PROGRAM_ID`)
- Same mint + owner with different token programs = different ATA addresses
- If an order is created with Token2022, the cancel script derives the wrong ATA address
- The on-chain program rejects the transaction due to account validation failure

This breaks the **Token Safety** and **Escrow Integrity** invariants by preventing legitimate cancellations of Token2022 orders.

## Impact Explanation
**Severity: Medium**

Users who create orders with Token2022 tokens face the following impacts:

1. **Cannot Cancel Orders**: The provided `cancel.ts` script will fail, either during the account lookup phase (lines 85-91) or during on-chain validation
2. **Potential Fund Lock**: Users without technical expertise cannot easily recover their escrowed tokens
3. **Requires Technical Workaround**: Users must manually modify the script to pass the correct token program parameter
4. **User Experience Degradation**: The protocol advertises Token2022 support (verified in tests [5](#0-4) ) but doesn't provide working client tooling

This is **not** a critical vulnerability because:
- Funds are not permanently lost (on-chain program is secure)
- Technical users can work around it by modifying the script
- The on-chain program correctly validates accounts and prevents invalid operations

However, it qualifies as **Medium severity** because:
- Affects all Token2022 users
- Prevents a core protocol operation (cancellation)
- Could lead to operational fund lock for non-technical users
- Creates asymmetry between order creation (works) and cancellation (broken)

## Likelihood Explanation
**Likelihood: High**

This issue **will occur** for any user who:
1. Creates an order with a Token2022 mint (protocol supports this)
2. Attempts to cancel the order using the provided `cancel.ts` script

The test suite demonstrates that Token2022 cancellations work correctly when the proper token program is specified. [6](#0-5) 

However, the provided user-facing script lacks this functionality, making the issue highly likely to affect real users in production.

## Recommendation
Modify the `cancel.ts` script to:

1. Add a prompt asking users which token program their order uses
2. Pass the token program parameter to `getAssociatedTokenAddress`
3. Use the specified token program when building the cancel instruction

**Fixed Code Structure:**

```typescript
// In main() function, add after line 71:
const srcTokenProgramInput = prompt(
  "Enter token program (TOKEN_PROGRAM_ID/TOKEN_2022_PROGRAM_ID): "
);
const srcTokenProgram = 
  srcTokenProgramInput === "TOKEN_2022_PROGRAM_ID" 
    ? splToken.TOKEN_2022_PROGRAM_ID 
    : splToken.TOKEN_PROGRAM_ID;

// Update line 85-89 to include token program:
const escrowSrcAtaAddr = await splToken.getAssociatedTokenAddress(
  srcMint,
  escrowAddr,
  true,
  srcTokenProgram  // Add 4th parameter
);

// Update cancel() function signature and calls to accept srcTokenProgram
// Update line 39-43 and line 52 to use the provided token program
```

Alternatively, detect the token program automatically by querying the mint account and checking its owner program.

## Proof of Concept

**Reproduction Steps:**

1. Create a Token2022 mint
2. Create an order using `create.ts` with `srcTokenProgram = TOKEN_2022_PROGRAM_ID`
3. Attempt to cancel the order using the unmodified `cancel.ts` script
4. Observe failure due to incorrect ATA derivation

**Expected vs Actual Behavior:**

```typescript
// What happens now:
const escrowAta = await splToken.getAssociatedTokenAddress(
  token2022Mint,
  escrow,
  true
  // Missing: TOKEN_2022_PROGRAM_ID
);
// Result: Derives ATA for TOKEN_PROGRAM_ID (wrong address)

// What should happen:
const escrowAta = await splToken.getAssociatedTokenAddress(
  token2022Mint,
  escrow,
  true,
  splToken.TOKEN_2022_PROGRAM_ID  // Correct program
);
// Result: Derives ATA for TOKEN_2022_PROGRAM_ID (correct address)
```

The test suite at lines 558-600 confirms correct cancellation when the token program is properly specified. [5](#0-4) 

**Notes**

The issue is NOT with the `allowOwnerOffCurve` parameter (which is correctly set to `true` for PDA owners), but rather the **missing fourth parameter** for the token program. The protocol's test infrastructure correctly handles this (see `tests/utils/utils.ts` lines 324-329 [7](#0-6) ), but the user-facing script does not implement the same pattern.

### Citations

**File:** scripts/fusion-swap/create.ts (L51-51)
```typescript
  srcTokenProgram: PublicKey = splToken.TOKEN_PROGRAM_ID
```

**File:** scripts/fusion-swap/cancel.ts (L39-43)
```typescript
  const escrowSrcAta = await splToken.getAssociatedTokenAddress(
    srcMint,
    escrow,
    true
  );
```

**File:** scripts/fusion-swap/cancel.ts (L52-52)
```typescript
      srcTokenProgram: splToken.TOKEN_PROGRAM_ID,
```

**File:** programs/fusion-swap/src/lib.rs (L619-626)
```rust
    /// ATA of src_mint to store escrowed tokens
    #[account(
        mut,
        associated_token::mint = src_mint,
        associated_token::authority = escrow,
        associated_token::token_program = src_token_program,
    )]
    escrow_src_ata: InterfaceAccount<'info, TokenAccount>,
```

**File:** tests/suits/fusion-swap.ts (L558-600)
```typescript
      it("Cancel escrow with Token 2022", async () => {
        const tokenProgram = splToken.TOKEN_2022_PROGRAM_ID;
        const srcMint = state.tokens[state.tokens.length - 2]; // Token 2022

        const escrow = await state.createEscrow({
          escrowProgram: program,
          payer,
          provider,
          orderConfig: {
            srcMint,
          },
          srcTokenProgram: tokenProgram,
        });

        const orderHash = calculateOrderHash(escrow.orderConfig);

        const transactionPromise = () =>
          program.methods
            .cancel(Array.from(orderHash), false)
            .accountsPartial({
              maker: state.alice.keypair.publicKey,
              srcMint,
              escrow: escrow.escrow,
              srcTokenProgram: tokenProgram,
            })
            .signers([state.alice.keypair])
            .rpc();

        const results = await trackReceivedTokenAndTx(
          provider.connection,
          [
            {
              publicKey: state.alice.atas[srcMint.toString()].address,
              programId: tokenProgram,
            },
          ],
          transactionPromise
        );

        expect(results).to.be.deep.eq([
          BigInt(state.defaultSrcAmount.toNumber()),
        ]);
      });
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
