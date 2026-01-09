# Audit Report

## Title
Order ID Input Validation Bypass in Client Script Leading to Unexpected Order Creation Behavior

## Summary
The `create.ts` script at line 151 uses `Number()` to parse the order ID from user input without validation, allowing negative numbers, floats, and extremely large values that undergo silent type coercion when serialized to `u32`. This causes order hash mismatches, potential escrow PDA collisions, and transaction failures. [1](#0-0) 

## Finding Description

The vulnerability exists in the client-side order creation flow. When a user enters an order ID, it's parsed using JavaScript's `Number()` function without validation: [1](#0-0) 

This orderId is then passed through the order configuration and used to calculate the order hash: [2](#0-1) 

The order hash calculation serializes the orderId using Borsh with a `u32` schema: [3](#0-2) 

The on-chain program expects a `u32` type for the order ID: [4](#0-3) 

**Attack Vector:**

When special JavaScript number values are serialized to `u32`, they undergo type coercion:
- **Floats** (e.g., 1.5, 3.14) → truncated to integers (1.5 becomes 1)
- **Large numbers** (e.g., 4294967296) → wrapped via modulo 2^32 (4294967296 becomes 0)
- **Negative numbers** (e.g., -1) → two's complement representation (becomes 4294967295)

This creates **order hash collisions** where different user inputs produce the same order hash, leading to:

1. **Escrow PDA Collisions**: The order hash is used as a seed for escrow PDA derivation: [5](#0-4) 

2. **Transaction Failures**: When attempting to create an order with a colliding escrow PDA, the `init` constraint fails because the account already exists: [6](#0-5) 

**Exploitation Steps:**

1. User creates order with orderId = 1.5 (intent: ID 1.5)
   - Serializes as u32 value 1
   - Order hash calculated with id=1
   - Escrow created with PDA derived from hash containing id=1

2. User later tries to create order with orderId = 1 (intent: ID 1)
   - Serializes as u32 value 1
   - Same order hash calculated
   - Transaction FAILS because escrow PDA already exists

3. User is confused why "different" orders have the same escrow

## Impact Explanation

**Severity: Medium**

The impact includes:

1. **Denial of Service**: Users accidentally creating orders with wrapped/truncated IDs block themselves from creating subsequent orders with the "actual" numeric value due to PDA collision.

2. **Order Management Confusion**: Users who enter floats or large numbers don't realize their order ID was modified, making it difficult to track and manage orders. When attempting to fill or cancel, they must use the truncated value, not their original input.

3. **Temporary Fund Lock**: If a user creates an order with an unintended ID and can't find it due to ID mismatch, their tokens remain locked in escrow until they figure out the correct ID or wait for expiration.

4. **Potential Front-Running**: A malicious actor monitoring mempool could observe a pending order creation and front-run it with a crafted ID that wraps/truncates to the same value, causing the legitimate transaction to fail. However, this requires the attacker to use the same maker keypair, limiting practical exploitability.

This breaks the **Account Validation** invariant by allowing client-side inputs that don't properly validate against the on-chain u32 type constraint.

## Likelihood Explanation

**Likelihood: Medium**

This issue can occur through:

1. **User Error**: Users accidentally entering decimal values (e.g., "1.5" instead of "1" or "2")
2. **Copy-Paste Mistakes**: Users pasting large numbers from external sources
3. **Testing/Development**: Developers using negative numbers during testing without realizing the wrap-around

The likelihood is medium because:
- The script accepts any numeric input without validation
- Users may not understand u32 type constraints
- No warning or error message alerts users to type coercion
- The issue is silent - transaction succeeds with wrong ID or fails mysteriously

## Recommendation

Add input validation in the `create.ts` script before using the orderId:

```typescript
const orderIdInput = prompt("Enter order id: ");
const orderId = Number(orderIdInput);

// Validate orderId
if (!Number.isInteger(orderId)) {
  throw new Error("Order ID must be an integer, got: " + orderIdInput);
}
if (orderId < 0) {
  throw new Error("Order ID must be non-negative, got: " + orderId);
}
if (orderId > 4294967295) {
  throw new Error("Order ID must be within u32 range (0 to 4294967295), got: " + orderId);
}
if (!Number.isFinite(orderId)) {
  throw new Error("Order ID must be a finite number, got: " + orderIdInput);
}
```

Additionally, update the prompt to guide users:

```typescript
const orderIdInput = prompt("Enter order id (integer from 0 to 4294967295): ");
```

## Proof of Concept

```typescript
// Demonstration of the issue
import * as borsh from "borsh";

const schema = { struct: { id: "u32" } };

// Test Case 1: Float truncation
const float_value = { id: 1.9 };
const float_serialized = borsh.serialize(schema, float_value);
console.log("Float 1.9 serializes to:", new DataView(float_serialized.buffer).getUint32(0, true)); 
// Output: 1 (truncated)

// Test Case 2: Large number wrap
const large_value = { id: 4294967296 }; // u32_max + 1
const large_serialized = borsh.serialize(schema, large_value);
console.log("Large 4294967296 serializes to:", new DataView(large_serialized.buffer).getUint32(0, true));
// Output: 0 (wrapped)

// Test Case 3: Negative number wrap
const negative_value = { id: -1 };
const negative_serialized = borsh.serialize(schema, negative_value);
console.log("Negative -1 serializes to:", new DataView(negative_serialized.buffer).getUint32(0, true));
// Output: 4294967295 (two's complement)

// These different inputs produce different u32 values but user expects different IDs
// This causes confusion and potential PDA collisions
```

**Real-World Scenario:**

1. User wants to create order with ID 100.5
2. Script accepts input without validation
3. Borsh serializes as ID 100
4. Order created with ID 100 (not 100.5)
5. User later searches for order ID 100.5 → not found
6. User confused, potential support burden
7. If user previously created order with ID 100, transaction fails with PDA collision error

## Notes

The vulnerability is limited in scope because:
- It only affects the user's own orders (collision requires same maker keypair)
- No unauthorized access or token theft occurs
- Tokens remain safely locked in escrow
- The issue is primarily user experience and transaction failure

However, it represents a meaningful security concern because silent type coercion can lead to unexpected behavior, fund locking, and denial of service for users who don't understand why their transactions fail.

### Citations

**File:** scripts/fusion-swap/create.ts (L151-151)
```typescript
  const orderId = Number(prompt("Enter order id: "));
```

**File:** scripts/utils.ts (L147-149)
```typescript
export function calculateOrderHash(orderConfig: OrderConfig): Uint8Array {
  const values = {
    id: orderConfig.id,
```

**File:** scripts/utils.ts (L186-188)
```typescript
const orderConfigSchema = {
  struct: {
    id: "u32",
```

**File:** programs/fusion-swap/src/lib.rs (L445-459)
```rust
    #[account(
        seeds = [
            "escrow".as_bytes(),
            maker.key().as_ref(),
            &order_hash(
                &order,
                protocol_dst_acc.clone().map(|acc| acc.key()),
                integrator_dst_acc.clone().map(|acc| acc.key()),
                src_mint.key(),
                dst_mint.key(),
                maker_receiver.key(),
            )?,
        ],
        bump,
    )]
```

**File:** programs/fusion-swap/src/lib.rs (L469-476)
```rust
    #[account(
        init,
        payer = maker,
        associated_token::mint = src_mint,
        associated_token::authority = escrow,
        associated_token::token_program = src_token_program,
    )]
    escrow_src_ata: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/fusion-swap/src/lib.rs (L732-733)
```rust
pub struct OrderConfig {
    id: u32,
```
