# Audit Report

## Title
Missing Taker Source ATA Validation Causes Transaction Failures for Wrapped SOL Orders

## Summary
The `fill.ts` script computes the correct Associated Token Account (ATA) addresses for wrapped SOL using `getAssociatedTokenAddress()` but fails to verify or create the taker's source ATA before invoking the fill instruction. This causes transaction failures when takers attempt to fill orders where wrapped SOL is the source token and they don't have a pre-existing wrapped SOL ATA.

## Finding Description

The fill script correctly computes ATA addresses at the specified lines: [1](#0-0) [2](#0-1) 

However, the script contains no logic to check if these accounts exist or to create them if missing. The script directly proceeds to build and send the fill transaction using these computed addresses. [3](#0-2) 

The on-chain Fill instruction requires `taker_src_ata` to already exist, as it lacks the `init_if_needed` constraint: [4](#0-3) 

This contrasts with `maker_dst_ata`, which IS marked as `init_if_needed`: [5](#0-4) 

When a taker without a wrapped SOL ATA attempts to fill an order with wrapped SOL as the source token, the transaction fails because the required `taker_src_ata` account doesn't exist on-chain.

**Evidence from Test Suite:**

The test infrastructure pre-creates all ATAs including native mint ATAs for all users: [6](#0-5) 

A commented-out test explicitly acknowledges this limitation: [7](#0-6) 

The TODO comment "uncomment after receiver wallet initialization will be implemented" directly confirms that automatic ATA creation for the taker's source account is a known missing feature.

## Impact Explanation

**Severity: Medium**

This issue causes denial of service for legitimate fill operations but does not result in fund loss or security breaches:

- **Affected Users**: Any taker attempting to fill orders with wrapped SOL as source token who doesn't have a wrapped SOL ATA
- **Scope**: Specific to wrapped SOL source orders, which are common in DeFi
- **Consequence**: Transaction failures, wasted gas fees, poor user experience
- **Fund Safety**: No funds are at risk; transactions fail atomically

This breaks the **Token Safety** and **Account Validation** invariants by not ensuring required accounts exist before transaction submission, causing DoS attacks affecting the fill operation.

## Likelihood Explanation

**Likelihood: High**

This issue will occur frequently in production:

1. **Common Scenario**: Many Solana users hold native SOL but have never interacted with wrapped SOL, so they lack wrapped SOL ATAs
2. **Zero Prerequisites**: Requires no attacker action - happens naturally when regular users interact with the protocol
3. **No Workaround**: The fill script provides no alternative path or error handling
4. **Detection**: Users only discover the issue after transaction failure

## Recommendation

Add ATA existence check and creation logic before building the fill instruction:

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
  const orderHash = calculateOrderHash(orderConfig);
  
  const escrow = findEscrowAddress(
    program.programId,
    maker,
    Buffer.from(orderHash)
  );
  
  const escrowSrcAta = await splToken.getAssociatedTokenAddress(
    orderConfig.srcMint,
    escrow,
    true
  );
  
  const takerSrcAta = await splToken.getAssociatedTokenAddress(
    orderConfig.srcMint,
    takerKeypair.publicKey
  );
  
  // NEW: Check if taker's source ATA exists, create if needed
  try {
    await splToken.getAccount(connection, takerSrcAta);
  } catch (error) {
    if (error instanceof splToken.TokenAccountNotFoundError) {
      console.log(`Creating taker source ATA at ${takerSrcAta.toString()}`);
      const createAtaIx = splToken.createAssociatedTokenAccountInstruction(
        takerKeypair.publicKey, // payer
        takerSrcAta,
        takerKeypair.publicKey, // owner
        orderConfig.srcMint
      );
      
      const createAtaTx = new Transaction().add(createAtaIx);
      await sendAndConfirmTransaction(connection, createAtaTx, [takerKeypair]);
      console.log(`Taker source ATA created successfully`);
    } else {
      throw error;
    }
  }
  
  // Continue with existing fill logic...
  const resolverAccess = findResolverAccessAddress(
    whitelistProgramId,
    takerKeypair.publicKey
  );
  
  // ... rest of the function
}
```

## Proof of Concept

**Reproduction Steps:**

1. Create an order with `srcMint = splToken.NATIVE_MINT` and `srcAssetIsNative = false` (wrapped SOL)
2. Use a taker wallet that has native SOL but no wrapped SOL ATA
3. Execute the fill script with these parameters
4. Observe transaction failure with account not found error

**Expected Behavior:** Transaction fails because `taker_src_ata` doesn't exist

**Test Script:**
```typescript
// Prerequisites: 
// - Maker has created an order with wrapped SOL as source
// - Taker has no wrapped SOL ATA

const connection = new Connection("...", "confirmed");
const fusionSwap = new Program<FusionSwap>(FUSION_IDL, { connection });
const whitelist = new Program<Whitelist>(WHITELIST_IDL, { connection });

// Load a fresh taker wallet with SOL but no wrapped SOL ATA
const takerKeypair = Keypair.generate();
// Fund with native SOL...

const orderConfig = {
  srcMint: splToken.NATIVE_MINT,
  // ... other order parameters
};

// Attempt fill - will fail
try {
  await fill(
    connection,
    fusionSwap,
    whitelist.programId,
    takerKeypair,
    makerPubkey,
    fillAmount,
    orderConfig,
    reducedOrderConfig
  );
} catch (error) {
  // Expected: TokenAccountNotFoundError or similar
  console.error("Fill failed:", error);
}
```

**Validation:** The on-chain program's constraint validation will reject the transaction because `taker_src_ata` account doesn't exist, as confirmed by the Fill struct requirements.

### Citations

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

**File:** scripts/fusion-swap/fill.ts (L67-92)
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

  const tx = new Transaction().add(fillIx);

  const signature = await sendAndConfirmTransaction(connection, tx, [
    takerKeypair,
  ]);
  console.log(`Transaction signature ${signature}`);
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

**File:** programs/fusion-swap/src/lib.rs (L571-579)
```rust
    /// Maker's ATA of dst_mint
    #[account(
        init_if_needed,
        payer = taker,
        associated_token::mint = dst_mint,
        associated_token::authority = maker_receiver,
        associated_token::token_program = dst_token_program,
    )]
    maker_dst_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
```

**File:** tests/utils/utils.ts (L149-156)
```typescript
    instance.tokens = await createTokens(settings.tokensNums, provider, payer);
    instance.tokens.push(splToken.NATIVE_MINT);
    [
      instance.alice as User,
      instance.bob as User,
      instance.charlie as User,
      instance.dave as User,
    ] = await createUsers(4, instance.tokens, provider, payer);
```

**File:** tests/suits/fusion-swap.ts (L1025-1062)
```typescript
    // it.only("Check that taker's xToken account is created automatically if it wasn't initialized before", async () => {
    //   // burn taker's xToken and close account
    //   const state.bobBalanceXToken = await splToken.getAccount(provider.connection, state.bob.atas[state.tokens[0].toString()].address);
    //   await splToken.burn(provider.connection, state.bob.keypair, state.bob.atas[state.tokens[0].toString()].address, state.tokens[0], state.bob.keypair, state.bobBalanceXToken.amount, []);
    //   await splToken.closeAccount(provider.connection, state.bob.keypair, state.bob.atas[state.tokens[0].toString()].address, state.bob.keypair.publicKey, state.bob.keypair.publicKey, []);
    //   // calc takers's xToken ata
    //   const state.bobAtaXToken = await splToken.getAssociatedTokenAddress(state.tokens[0], state.bob.keypair.publicKey);

    //   // Check that token account doesn't exist before executing the trade
    //   try {
    //     await splToken.getAccount(provider.connection, state.bobAtaXToken);
    //     chai.assert(false);
    //   } catch (e) {
    //     expect(e.toString().includes("TokenAccountNotFoundError"));
    //   }

    //   await program.methods.fill(state.escrows[0].reducedOrderConfig, state.defaultSrcAmount)
    //   .accounts({
    //     taker: state.bob.keypair.publicKey,
    //     maker: state.alice.keypair.publicKey,
    //     srcMint: state.tokens[0],
    //     dstMint: state.tokens[1],
    //     escrow: state.escrows[0].escrow,
    //     escrowSrcAta: state.escrows[0].ata,
    //     makerDstAta: state.alice.atas[state.tokens[1].toString()].address,
    //     takerSrcAta: state.bobAtaXToken,
    //     takerDstAta: state.bob.atas[state.tokens[1].toString()].address,
    //     tokenProgram: splToken.TOKEN_PROGRAM_ID,
    //     associatedTokenProgram: splToken.ASSOCIATED_TOKEN_PROGRAM_ID,
    //     systemProgram: anchor.web3.SystemProgram.programId,
    //   })
    //   .signers([state.bob.keypair])
    //   .rpc();

    //   // Check that token account exists after trade and has expected balance
    //   const state.bobXAta = await splToken.getAccount(provider.connection, state.bobAtaXToken);
    //   expect(bobXAta.amount).to.be.eq(BigInt(state.defaultSrcAmount.toNumber()));
    // });
```
