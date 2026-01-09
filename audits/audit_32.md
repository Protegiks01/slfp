# Audit Report

## Title
Missing wSOL ATA Creation in Fill Script Causes Transaction Failure for Native SOL Orders

## Summary
The `fill.ts` script fails to create or verify the existence of the taker's wSOL associated token account (ATA) when `srcAssetIsNative` is true. This causes fill transactions to fail with "Account does not exist" errors, preventing legitimate order execution and creating a denial-of-service condition for all native SOL orders where the resolver lacks a pre-existing wSOL ATA.

## Finding Description

When an order is created with native SOL as the source asset (`srcAssetIsNative = true`), the source mint is set to `NATIVE_MINT` (wSOL). The fill script computes the taker's wSOL ATA address but never checks if it exists or creates it before attempting the fill transaction. [1](#0-0) 

The program's Fill instruction requires `taker_src_ata` to be a valid, existing TokenAccount with no `init_if_needed` constraint: [2](#0-1) 

The script passes this computed address directly to the program without any account initialization: [3](#0-2) 

When the transaction executes, the program attempts to transfer escrowed wSOL from `escrow_src_ata` to `taker_src_ata`: [4](#0-3) 

If `taker_src_ata` doesn't exist, the transaction fails immediately with an account not found error.

**Contrast with test setup**: The test infrastructure pre-creates ATAs for all users including NATIVE_MINT, which masks this issue: [5](#0-4) [6](#0-5) 

**Contrast with create script**: The `create.ts` script properly handles wSOL by wrapping SOL when needed: [7](#0-6) 

The fill script lacks equivalent handling for the taker side.

## Impact Explanation

**Severity: HIGH**

This vulnerability breaks the **Token Safety** and **Account Validation** invariants by failing to ensure required accounts exist before transaction execution.

**Impact scope:**
- All orders with `srcAssetIsNative = true` are unfillable by resolvers who don't have pre-existing wSOL ATAs
- Affects protocol availability and order execution guarantees
- Creates market inefficiency as orders remain unfilled despite willing resolvers
- Makers' escrowed SOL remains locked until order expiration or manual cancellation

While this does NOT enable SOL theft (the transaction fails atomically and escrow remains secure), it creates a critical availability issue that prevents core protocol functionality.

## Likelihood Explanation

**Likelihood: HIGH**

This issue will occur in every production scenario where:
1. An order is created with native SOL as source asset (common use case)
2. A resolver attempts to fill the order without a pre-existing wSOL ATA (common for new resolvers or those primarily dealing with regular SPL tokens)

The likelihood is HIGH because:
- Native SOL orders are a core feature of the protocol
- New resolver wallets typically don't have wSOL ATAs created by default
- The script provides no error checking or guidance about this requirement
- The issue is completely hidden during testing due to test setup pre-creating all ATAs

## Recommendation

Add ATA existence check and creation logic to the fill script before building the transaction. The script should:

1. Check if the taker's wSOL ATA exists
2. If not, prepend a `createAssociatedTokenAccountInstruction` to the transaction
3. Ensure the ATA is created before the fill instruction executes

**Fix for `scripts/fusion-swap/fill.ts`:**

Add before building the fill transaction (around line 46):

```typescript
// Check and create taker's src ATA if needed (especially for native SOL)
const takerSrcAtaInfo = await connection.getAccountInfo(takerSrcAta);
if (!takerSrcAtaInfo) {
  const createAtaIx = splToken.createAssociatedTokenAccountInstruction(
    takerKeypair.publicKey, // payer
    takerSrcAta,             // ata
    takerKeypair.publicKey, // owner
    orderConfig.srcMint,     // mint
    splToken.TOKEN_PROGRAM_ID
  );
  tx.add(createAtaIx);
}
```

This mirrors the approach used in the test utilities and ensures the required account exists before the fill instruction attempts to access it.

## Proof of Concept

**Reproduction Steps:**

1. Create a fresh Solana wallet with no prior wSOL ATA
2. Register the wallet as a whitelisted resolver
3. Create an order with `srcAssetIsNative = true` and `srcMint = NATIVE_MINT`
4. Attempt to fill the order using the fill.ts script with the fresh wallet
5. Transaction fails with: `Error: Account does not exist <taker_wSOL_ATA_address>`

**Expected behavior:** Transaction should either:
- Automatically create the taker's wSOL ATA and complete the fill
- Provide clear error message about missing ATA with instructions

**Actual behavior:** Transaction fails with cryptic account error, order remains unfilled

**Test verification:** The issue is masked in tests because `createAtasUsers` pre-creates ATAs: [8](#0-7) 

This test passes because Bob's wSOL ATA was created during test setup at line 229 of utils.ts, not during the fill operation.

## Notes

While the security question asks about "SOL theft," the actual vulnerability is **transaction failure leading to denial of service**, not theft. The escrow mechanism and atomic transaction execution prevent any theft scenario - if the transaction fails, the escrow remains locked and secure. However, this still represents a HIGH severity issue because it prevents core protocol functionality (order filling) for a significant use case (native SOL orders).

The fix is straightforward and follows established patterns from both the create script and test utilities. Implementation should be prioritized to ensure production resolvers can successfully fill native SOL orders.

### Citations

**File:** scripts/fusion-swap/fill.ts (L57-60)
```typescript
  const takerSrcAta = await splToken.getAssociatedTokenAddress(
    orderConfig.srcMint,
    takerKeypair.publicKey
  );
```

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

**File:** programs/fusion-swap/src/lib.rs (L165-184)
```rust
        // Escrow => Taker
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

**File:** programs/fusion-swap/src/lib.rs (L559-564)
```rust
    /// Taker's ATA of src_mint
    #[account(
        mut,
        constraint = taker_src_ata.mint.key() == src_mint.key()
    )]
    taker_src_ata: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** tests/utils/utils.ts (L223-223)
```typescript
    instance.tokens.push(splToken.NATIVE_MINT);
```

**File:** tests/utils/utils.ts (L537-577)
```typescript
export async function createAtasUsers(
  usersKeypairs: Array<anchor.web3.Keypair>,
  tokens: Array<anchor.web3.PublicKey>,
  provider: anchor.AnchorProvider | BanksClient,
  payer: anchor.web3.Keypair,
  tokenProgram = splToken.TOKEN_PROGRAM_ID
): Promise<Array<User>> {
  let users: Array<User> = [];

  const [tokenLibrary, connection, extraArgs] =
    provider instanceof anchor.AnchorProvider
      ? [splToken, provider.connection, [undefined, tokenProgram]]
      : [splBankrunToken, provider, [tokenProgram]];

  for (let i = 0; i < usersKeypairs.length; ++i) {
    const keypair = usersKeypairs[i];
    const atas = {};
    for (const token of tokens) {
      const pubkey = await tokenLibrary.createAssociatedTokenAccount(
        connection,
        payer,
        token,
        keypair.publicKey,
        ...extraArgs
      );
      atas[token.toString()] = await tokenLibrary.getAccount(
        connection,
        pubkey,
        undefined,
        tokenProgram
      );
      debugLog(
        `User_${i} :: token = ${token.toString()} :: ata = ${atas[
          token.toString()
        ].address.toBase58()}`
      );
    }
    users.push({ keypair, atas });
    debugLog(`User_${i} ::`, users[i].keypair.publicKey.toString(), "\n");
  }
  return users;
```

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

**File:** tests/suits/fusion-swap.ts (L264-307)
```typescript
    it("Execute the trade with native tokens => tokens", async () => {
      const escrow = await state.createEscrow({
        escrowProgram: program,
        payer,
        provider,
        orderConfig: {
          srcMint: splToken.NATIVE_MINT,
        },
      });

      const transactionPromise = () =>
        program.methods
          .fill(escrow.reducedOrderConfig, state.defaultSrcAmount)
          .accountsPartial(
            state.buildAccountsDataForFill({
              srcMint: splToken.NATIVE_MINT,
              escrow: escrow.escrow,
              escrowSrcAta: escrow.ata,
              takerSrcAta:
                state.bob.atas[splToken.NATIVE_MINT.toString()].address,
            })
          )
          .signers([state.bob.keypair])
          .rpc();

      const results = await trackReceivedTokenAndTx(
        provider.connection,
        [
          state.alice.atas[state.tokens[1].toString()].address,
          state.bob.atas[splToken.NATIVE_MINT.toString()].address,
          state.bob.atas[state.tokens[1].toString()].address,
        ],
        transactionPromise
      );
      await expect(
        splToken.getAccount(provider.connection, escrow.ata)
      ).to.be.rejectedWith(splToken.TokenAccountNotFoundError);

      expect(results).to.be.deep.eq([
        BigInt(state.defaultDstAmount.toNumber()),
        BigInt(state.defaultSrcAmount.toNumber()),
        -BigInt(state.defaultDstAmount.toNumber()),
      ]);
    });
```
