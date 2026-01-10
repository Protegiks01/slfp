# Audit Report

## Title
Token-2022 Incompatibility in Fill Script Causes Denial of Service on Order Execution

## Summary
The production fill script `scripts/fusion-swap/fill.ts` hardcodes `TOKEN_PROGRAM_ID` for all token operations and fails to properly derive Associated Token Account addresses for Token-2022 tokens. This causes all fill attempts for orders containing Token-2022 tokens to fail, resulting in temporary fund locking and denial of service for these orders.

## Finding Description

The 1inch Solana Fusion Protocol's on-chain program correctly supports both SPL Token and Token-2022 through the `TokenInterface` abstraction. [1](#0-0) 

The Fill instruction handler accepts separate token program accounts for source and destination tokens. [2](#0-1) 

The on-chain program validates that escrow ATAs are created with the correct token program using the `associated_token::token_program` constraint. [3](#0-2) 

However, the production fill script contains three critical incompatibilities:

**Issue 1: Hardcoded Token Program IDs**

The script unconditionally passes `TOKEN_PROGRAM_ID` for both source and destination token programs, regardless of the actual token program used by the mints. [4](#0-3) 

**Issue 2: Incorrect Escrow ATA Derivation**

When deriving the escrow source ATA address, the script calls `getAssociatedTokenAddress` with only three parameters, omitting the token program parameter. [5](#0-4) 

Without the token program parameter, `getAssociatedTokenAddress` defaults to `TOKEN_PROGRAM_ID`, causing it to derive the wrong ATA address for Token-2022 tokens.

**Issue 3: Incorrect Taker ATA Derivation**

Similarly, the taker's source ATA is derived without specifying the token program. [6](#0-5) 

**Issue 4: No Token Program Detection Logic**

The script's utility function `getTokenDecimals()` fetches mint information but only extracts decimals, not the token program. [7](#0-6) 

**Correct Implementation Reference**

The test utilities demonstrate the proper approach by passing the token program parameter to `getAssociatedTokenAddress`. [8](#0-7) 

The test suite includes successful Token-2022 fill operations where token programs are correctly specified. [9](#0-8) 

And explicit passing of token program IDs to the fill instruction. [10](#0-9) 

**Execution Flow When Vulnerability Triggers:**

1. Maker creates an order with Token-2022 tokens using proper token program specification
2. Escrow and ATAs are correctly created on-chain with `TOKEN_2022_PROGRAM_ID`
3. Resolver attempts to fill using the production script:
   - Script derives escrow ATA using default `TOKEN_PROGRAM_ID` → generates wrong address
   - Script derives taker ATA using default `TOKEN_PROGRAM_ID` → generates wrong address  
   - Script passes `TOKEN_PROGRAM_ID` to the program for both token programs
4. On-chain program's account validation constraints fail because:
   - Provided ATA addresses don't match actual ATAs created with `TOKEN_2022_PROGRAM_ID`
   - Token program parameters don't match the actual token programs
5. Transaction reverts with account constraint error

## Impact Explanation

**Medium Severity** - This vulnerability causes a Denial of Service condition specifically for Token-2022 orders:

**Primary Impacts:**
1. **Order Unfillability**: Any order with Token-2022 tokens (source or destination) cannot be filled using the production script
2. **Temporary Fund Locking**: Maker's tokens remain locked in escrow until manual cancellation
3. **Resolver Resource Waste**: Resolvers waste transaction fees on fill attempts that always fail
4. **Protocol Usability Degradation**: As Token-2022 adoption grows in Solana ecosystem, this creates an expanding compatibility gap

**Mitigating Factors (why not High/Critical):**
- No permanent fund loss (makers can cancel to recover funds)
- No fund theft possible (on-chain program security model intact)
- Recovery mechanism exists through order cancellation
- Issue isolated to client script, not core protocol logic
- On-chain program remains secure and functions correctly

## Likelihood Explanation

**High Likelihood** - This issue will occur predictably in production:

1. **Growing Ecosystem Adoption**: Token-2022 is increasingly adopted for transfer fees, transfer hooks, confidential transfers, and other advanced features
2. **Automatic Failure**: Every fill attempt for Token-2022 orders will fail deterministically
3. **No Attack Required**: This is an operational bug affecting legitimate users
4. **User-Facing Impact**: Both order creators and resolvers encounter this during normal protocol usage
5. **Script is Production Tool**: This is the official fill script that resolvers are expected to use

## Recommendation

Implement token program detection and proper ATA derivation:

```typescript
// Add utility to detect token program from mint
async function getTokenProgram(
  connection: Connection, 
  mint: PublicKey
): Promise<PublicKey> {
  const mintInfo = await splToken.getMint(connection, mint);
  return mintInfo.owner; // Returns TOKEN_PROGRAM_ID or TOKEN_2022_PROGRAM_ID
}

// In fill() function:
const srcTokenProgram = await getTokenProgram(connection, orderConfig.srcMint);
const dstTokenProgram = await getTokenProgram(connection, orderConfig.dstMint);

// Derive ATAs with correct token program
const escrowSrcAta = await splToken.getAssociatedTokenAddress(
  orderConfig.srcMint,
  escrow,
  true,
  srcTokenProgram  // Pass detected program
);

const takerSrcAta = await splToken.getAssociatedTokenAddress(
  orderConfig.srcMint,
  takerKeypair.publicKey,
  false,
  srcTokenProgram  // Pass detected program
);

// Pass detected programs to instruction
.accountsPartial({
  // ... other accounts
  srcTokenProgram,
  dstTokenProgram,
})
```

## Proof of Concept

```typescript
import { splToken } from "@solana/spl-token";
import { Connection, Keypair } from "@solana/web3.js";

// Scenario: Order created with Token-2022 mint
const token2022Mint = /* some Token-2022 mint address */;
const escrow = /* escrow PDA address */;

// Current (broken) code - derives wrong ATA for Token-2022
const wrongAta = await splToken.getAssociatedTokenAddress(
  token2022Mint,
  escrow,
  true
  // Missing TOKEN_2022_PROGRAM_ID parameter
);

// Correct code - derives right ATA for Token-2022
const correctAta = await splToken.getAssociatedTokenAddress(
  token2022Mint,
  escrow,
  true,
  splToken.TOKEN_2022_PROGRAM_ID  // Explicitly specify Token-2022
);

console.log("Wrong ATA:", wrongAta.toBase58());
console.log("Correct ATA:", correctAta.toBase58());
// These will be different addresses!

// When script passes wrongAta to fill instruction,
// on-chain constraint validation fails because
// actual escrow ATA was created at correctAta
```

## Notes

This vulnerability is valid under the defined scope because:
1. Client scripts (`scripts/`) are explicitly listed as in-scope components
2. The issue causes concrete operational impact (DoS + temporary fund locking)
3. All technical claims are verified with code citations
4. Token-2022 is a production-ready Solana feature with growing adoption

While the on-chain program is secure and correctly implements Token-2022 support, the production client tooling creates a critical usability gap that will affect real users as Token-2022 adoption increases.

### Citations

**File:** programs/fusion-swap/src/lib.rs (L6-9)
```rust
    token_interface::{
        close_account, transfer_checked, CloseAccount, Mint, TokenAccount, TokenInterface,
        TransferChecked,
    },
```

**File:** programs/fusion-swap/src/lib.rs (L551-556)
```rust
    #[account(
        mut,
        associated_token::mint = src_mint,
        associated_token::authority = escrow,
        associated_token::token_program = src_token_program,
    )]
```

**File:** programs/fusion-swap/src/lib.rs (L566-567)
```rust
    src_token_program: Interface<'info, TokenInterface>,
    dst_token_program: Interface<'info, TokenInterface>,
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

**File:** tests/utils/utils.ts (L278-279)
```typescript
    srcTokenProgram = splToken.TOKEN_PROGRAM_ID,
    dstTokenProgram = splToken.TOKEN_PROGRAM_ID,
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

**File:** tests/suits/fusion-swap.ts (L450-478)
```typescript
      it("Execute trade with Token 2022 -> SPL Token", async () => {
        const srcTokenProgram = splToken.TOKEN_2022_PROGRAM_ID;
        const srcMint = state.tokens[state.tokens.length - 2]; // Token 2022
        const takerSrcAta = state.bob.atas[srcMint.toString()].address;

        const escrow = await state.createEscrow({
          escrowProgram: program,
          payer,
          provider,
          orderConfig: {
            srcMint,
          },
          srcTokenProgram,
        });

        const transactionPromise = () =>
          program.methods
            .fill(escrow.reducedOrderConfig, state.defaultSrcAmount)
            .accountsPartial({
              ...state.buildAccountsDataForFill({
                escrow: escrow.escrow,
                escrowSrcAta: escrow.ata,
                srcMint,
                takerSrcAta,
                srcTokenProgram,
              }),
            })
            .signers([state.bob.keypair])
            .rpc();
```
