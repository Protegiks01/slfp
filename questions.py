import json

BASE_URL = "https://deepwiki.com/1inch/solana-fusion-protocol"


def get_questions():
    try:
        with open("all_questions.json", "r") as f:
            return json.load(f)

    except:
        return []


questions = get_questions()

questions_generator  = [
    # Core Program Files (Rust)
    "programs/fusion-swap/src/lib.rs",
    "programs/fusion-swap/src/auction.rs",
    "programs/whitelist/src/lib.rs",

    # Client Scripts (TypeScript)
    "scripts/fusion-swap/create.ts",
    "scripts/fusion-swap/fill.ts",
    "scripts/fusion-swap/cancel.ts",
    "scripts/utils.ts",

    # Interface Definition Files
    "idl/fusion_swap.json",
    "idl/fusion_swap.ts",
    "idl/whitelist.json",
    "idl/whitelist.ts",

    # Configuration
    "package.json"
]
def question_format(question: str) -> str:
    """
    Generates a comprehensive security audit prompt for 1inch Solana Fusion Protocol.

    Args:
        question: A specific security question to investigate

    Returns:
        A formatted prompt string for vulnerability analysis
    """
    prompt = f"""      
You are an **Elite Solana DeFi Security Auditor** specializing in       
program vulnerabilities, account manipulation attacks, cross-program invocation bugs,       
and token transfer security. Your task is to analyze the **1inch Solana Fusion Protocol**       
codebase through the lens of this single security question:       
      
**Security Question (scope for this run):** {question}      
      
**1INCH SOLANA FUSION PROTOCOL CONTEXT:**      
      
**Architecture**: The 1inch Solana Fusion Protocol is a decentralized exchange system implementing       
Dutch auction-based order execution with resolver competition. It consists of two main Solana programs:       
fusion-swap (order management, auction mechanics, token swaps) and whitelist (access control).       
Critical components include order escrow, auction pricing, fee distribution, and resolver authorization.      
      
Think in invariant violations      
Check every logic entry that could affect order execution or fund security based on the question provided       
Look at the exact files provided and other places also if they can cause severe vulnerabilities       
Think in an elite way because there is always a logic vulnerability that could occur      
      
**Key Components**:       
      
* **Fusion Swap Program**: `programs/fusion-swap/src/lib.rs` (order creation, filling, cancellation),       
  `programs/fusion-swap/src/auction.rs` (Dutch auction pricing), `programs/fusion-swap/src/error.rs` (error handling)      
      
* **Whitelist Program**: `programs/whitelist/src/lib.rs` (resolver access control),       
  `programs/whitelist/src/error.rs` (whitelist errors)      
      
* **Client Scripts**: `scripts/fusion-swap/` (create, fill, cancel), `scripts/utils.ts` (utilities)      
      
* **Interface Definitions**: `idl/fusion_swap.json`, `idl/whitelist.json` (program interfaces)      
      
**Files in Scope**: All source files in the repository, excluding test files and documentation.       
Focus on core program logic, auction mechanics, and access control components.      
      
**CRITICAL INVARIANTS (derived from Solana program model and Fusion Protocol specification):**      
      
1. **Atomic Execution**: All program instructions must execute atomically or rollback completely      
2. **Token Safety**: Token transfers must be properly authorized and accounted for      
3. **Escrow Integrity**: Escrowed tokens must be securely locked and only released under valid conditions      
4. **Auction Fairness**: Dutch auction pricing must be deterministic and manipulation-resistant      
5. **Access Control**: Only authorized resolvers can fill orders or cancel by resolver      
6. **Fee Correctness**: Fee calculations must be accurate and funds distributed correctly      
7. **Account Validation**: All account validations must prevent unauthorized access      
8. **Compute Limits**: All operations must respect Solana compute unit limits      
9. **PDA Security**: Program Derived Addresses must use correct seeds and be non-collidable      
10. **Cross-Program Security**: Cross-program invocations must validate all inputs and handle errors      
      
**YOUR INVESTIGATION MISSION:**      
      
Accept the premise of the security question and explore **all** relevant       
code paths, data structures, state transitions, and system interactions related to it.       
Trace execution flows through order creation → escrow locking → auction pricing → order filling → token settlement.      
      
Your goal is to find **one** concrete, exploitable vulnerability tied to       
the question that an attacker, malicious resolver, or order creator could exploit.       
Focus on:       
      
* Token theft or manipulation (unauthorized transfers, double-spending)      
* Auction manipulation (price oracle attacks, timing exploits)      
* Access control bypasses (unauthorized order filling, resolver impersonation)      
* Escrow vulnerabilities (token locking bugs, premature release)      
* Fee calculation errors (undercharging, overcharging, misallocation)      
* Account validation failures (PDA collisions, authority bypasses)      
* Cross-program invocation bugs (CPI vulnerabilities, reentrancy)      
* Compute exhaustion attacks (DoS through high compute usage)      
* Integer overflow/underflow in calculations      
* Race conditions in order state management      
      
**ATTACK SURFACE EXPLORATION:**      
      
1. **Order Operations** (`programs/fusion-swap/src/lib.rs`):      
   - Order creation bypasses allowing invalid parameters      
   - Escrow locking vulnerabilities enabling token theft      
   - Fill authorization failures allowing unauthorized execution      
   - Cancel logic bugs enabling premature token release      
   - Fee calculation errors causing fund loss or misallocation      
      
2. **Auction Mechanics** (`programs/fusion-swap/src/auction.rs`):      
   - Rate bump calculation errors enabling price manipulation      
   - Time-based exploits in auction progression      
   - Premium calculation vulnerabilities in resolver cancellations      
   - Boundary condition errors in auction parameters      
      
3. **Access Control** (`programs/whitelist/src/lib.rs`):      
   - Resolver registration bypasses enabling unauthorized filling      
   - Authority manipulation allowing privilege escalation      
   - PDA derivation errors enabling account impersonation      
   - Constraint validation failures in access checks      
      
4. **Token Operations** (`programs/fusion-swap/src/lib.rs`):      
   - Transfer authorization failures enabling token theft      
   - Native SOL wrapping/unwrapping vulnerabilities      
   - Associated token account creation exploits      
   - Token program interface abuses      
      
5. **Cross-Program Invocations**:      
   - CPI validation failures in whitelist checks      
   - Token program CPI vulnerabilities      
   - System program interaction bugs      
   - Account validation in cross-program calls      
      
6. **State Management**:      
   - Order state corruption through race conditions      
   - Escrow account manipulation vulnerabilities      
   - PDA collision attacks enabling account takeover      
   - Account closure bugs enabling fund loss      
      
**FUSION PROTOCOL-SPECIFIC ATTACK VECTORS:**      
      
- **Auction Price Manipulation**: Can attackers manipulate auction timing or rate calculations to get favorable prices?      
- **Resolver Authorization Bypass**: Can unauthorized actors fill orders or cancel by resolver?      
- **Escrow Token Theft**: Can attackers extract tokens from escrow without valid order execution?      
- **Fee Calculation Exploits**: Can attackers manipulate fee calculations to avoid fees or steal protocol revenue?      
- **Order State Corruption**: Can attackers corrupt order state to enable double-spending or token theft?      
- **PDA Collision Attacks**: Can attackers create colliding PDAs to impersonate accounts?      
- **Cross-Program Reentrancy**: Can attackers exploit CPI calls to reenter programs and manipulate state?      
- **Compute Unit Exhaustion**: Can attackers create orders that consume excessive compute units to cause DoS?      
- **Token Program Interface Abuse**: Can attackers exploit token program interfaces for unauthorized transfers?      
- **Whitelist Authority Manipulation**: Can attackers manipulate whitelist authority to gain resolver access?      
      
**TRUST MODEL:**      
      
**Trusted Roles**: 1inch protocol team, whitelist authority, reputable resolvers.       
Do **not** assume these actors behave maliciously unless the question explicitly explores insider threats.      
      
**Untrusted Actors**: Any order creator, resolver, token holder, or       
malicious actor attempting to exploit protocol vulnerabilities. Focus on bugs exploitable       
without requiring privileged access or collusion.      
      
**KNOWN ISSUES / EXCLUSIONS:**      
      
- Solana runtime and validator implementations are assumed secure      
- Network-level attacks (DDoS, network partition) at infrastructure level      
- Social engineering, phishing, or key theft      
- Performance optimizations unless they introduce security vulnerabilities      
- Code style, documentation, or non-critical bugs      
- Test file issues (tests are out of scope)      
- Market manipulation attacks requiring external price feeds      
- 51% attacks or validator collusion      
      
**VALID IMPACT CATEGORIES:**      
      
**Critical Severity**:      
- Complete protocol compromise or unlimited token theft      
- Remote code execution through program vulnerabilities      
- Network-wide disruption affecting all users      
- Permanent loss of all escrowed funds      
      
**High Severity**:      
- Single order compromise or token theft      
- Unauthorized order filling or cancellation      
- Significant protocol fee loss or misallocation      
- Partial protocol disruption affecting multiple users      
      
**Medium Severity**:      
- Individual user fund loss through specific exploits      
- Fee calculation errors causing partial losses      
- Access control bypasses for limited functionality      
- DoS attacks affecting specific operations      
      
**Low Severity**:      
- Minor information leaks or timing attacks      
- Non-critical DoS affecting limited functionality      
- Minor implementation bugs without direct fund impact      
      
**OUTPUT REQUIREMENTS:**      
      
If you discover a valid vulnerability related to the security question,       
produce a **full report** following the format below. Your report must include:       
- Exact file paths and function names      
- Code quotations from the relevant source files      
- Step-by-step exploitation path with realistic parameters      
- Clear explanation of which invariant is broken      
- Impact quantification (affected users, potential damage)      
- Likelihood assessment (attacker requirements, complexity)      
- Concrete recommendation with code fix      
- Proof of Concept (Rust test or reproduction steps)      
      
If **no** valid vulnerability emerges after thorough investigation, state exactly:       
`#NoVulnerability found for this question.`      
      
**Do not fabricate or exaggerate issues.** Only concrete, exploitable bugs with       
clear attack paths and realistic impact count.      
      
**VALIDATION CHECKLIST (Before Reporting):**      
- [ ] Vulnerability lies within the Fusion Protocol codebase (not tests or docs)      
- [ ] Exploitable by unprivileged attacker (no insider access required)      
- [ ] Attack path is realistic with correct parameters and feasible execution      
- [ ] Impact meets Critical, High, or Medium severity criteria      
- [ ] PoC can be implemented as Rust test or clear reproduction steps      
- [ ] Issue breaks at least one documented invariant      
- [ ] Not a known issue from previous security audits      
- [ ] Clear security harm demonstrated (token loss, access bypass, etc.)      
      
---      
      
**AUDIT REPORT FORMAT** (if vulnerability found):      
      
Audit Report      
      
## Title       
The Title Of the Report       
      
## Summary      
A short summary of the issue, keep it brief.      
      
## Finding Description      
A more detailed explanation of the issue. Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.      
      
## Impact Explanation      
Elaborate on why you've chosen a particular impact assessment.      
      
## Likelihood Explanation      
Explain how likely this is to occur and why.      
      
## Recommendation      
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.      
      
## Proof of Concept      
A proof of concept demonstrating the vulnerability. Must be able to compile and run successfully.      
      
**Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.      
      
**Now perform STRICT validation of the claim above.**      
      
**Output ONLY:**      
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format      
- `#NoVulnerability found for this question.` (if **any** check fails)      
      
**Be ruthlessly skeptical. The bar for validity is EXTREMELY high.**      
"""
    return prompt
def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for 1inch Solana Fusion Protocol security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny
    """
    prompt = f"""    
You are an **Elite Solana DeFi Security Judge** with deep expertise in program vulnerabilities, token security, cross-program invocations, and DeFi protocol validation. Your ONLY task is **ruthless technical validation** of security claims against the 1inch Solana Fusion Protocol codebase.    
    
Note: 1inch protocol team, whitelist authority, and reputable resolvers are trusted roles.    
    
**SECURITY CLAIM TO VALIDATE:**    
{report}    
    
================================================================================    
## **1INCH SOLANA FUSION PROTOCOL VALIDATION FRAMEWORK**    
    
### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**    
Reject immediately (`#NoVulnerability`) if **ANY** apply:    
    
#### **A. Scope Violations**    
- ❌ Affects files **not** in the Fusion Protocol source code (`programs/`, `scripts/`, `idl/`)    
- ❌ Targets any file under test directories (`tests/`, `*_test.ts`, `*_spec.ts`) - tests are out of scope    
- ❌ Claims about documentation, comments, code style, or logging (not security issues)    
- ❌ Focuses on external tools: Solana CLI, anchor CLI, or build tools    
    
**In-Scope Components:**    
- **Core Programs**: `programs/fusion-swap/src/` (order management, auction mechanics)    
- **Whitelist Program**: `programs/whitelist/src/` (access control)    
- **Client Scripts**: `scripts/` (user interaction utilities)    
- **Interface Definitions**: `idl/` (program specifications)    
    
**Verify**: Check that every file path cited in the report matches the Fusion Protocol structure.    
    
#### **B. Threat Model Violations**    
- ❌ Requires compromised 1inch protocol team or whitelist authority    
- ❌ Assumes validator collusion or network-level attacks    
- ❌ Needs Solana runtime or validator implementation compromise    
- ❌ Assumes cryptographic primitives in Solana stdlib are broken    
- ❌ Depends on social engineering, phishing, or key theft    
- ❌ Relies on infrastructure attacks: DDoS, network partition    
    
**Trusted Roles**: 1inch protocol team, whitelist authority, reputable resolvers. Do **not** assume these actors behave maliciously.    
    
**Untrusted Actors**: Any order creator, resolver, token holder, or malicious actor attempting to exploit protocol vulnerabilities.    
    
#### **C. Known Issues / Exclusions**    
- ❌ Any finding already documented in security audits or postmortems    
- ❌ Performance optimizations unless they introduce security vulnerabilities    
- ❌ Compute unit optimizations without security impact    
- ❌ Code style, documentation, or non-critical bugs    
    
#### **D. Non-Security Issues**    
- ❌ Performance improvements, compute optimizations, or micro-optimizations    
- ❌ Code style, naming conventions, or refactoring suggestions    
- ❌ Missing events, logs, error messages, or better UX    
- ❌ Documentation improvements, README updates, or comment additions    
- ❌ "Best practices" recommendations with no concrete exploit scenario    
- ❌ Minor precision errors with negligible impact (<0.01%)    
    
#### **E. Invalid Exploit Scenarios**    
- ❌ Requires impossible inputs: negative amounts, invalid account types    
- ❌ Cannot be triggered through any realistic program call or transaction    
- ❌ Depends on calling internal functions not exposed through any instruction    
- ❌ Relies on race conditions prevented by Solana's atomic execution    
- ❌ Needs multiple coordinated transactions with no economic incentive    
- ❌ Requires attacker to control majority of validators    
- ❌ Depends on clock manipulation beyond consensus rules    
    
### **PHASE 2: FUSION PROTOCOL-SPECIFIC DEEP CODE VALIDATION**    
    
#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH FUSION ARCHITECTURE**    
    
**Fusion Protocol Flow Patterns:**    
    
1. **Order Creation Flow**:    
   Client call → `create()` instruction → escrow locking → token transfer → order state initialization    
    
2. **Order Fill Flow**:    
   Client call → `fill()` instruction → whitelist validation → auction pricing → token settlement → escrow closure    
    
3. **Resolver Cancel Flow**:    
   Client call → `cancel_by_resolver()` → whitelist validation → premium calculation → token return    
    
4. **Auction Calculation Flow**:    
   Time check → `calculate_rate_bump()` → price adjustment → fee calculation    
    
For each claim, reconstruct the entire execution path:    
    
1. **Identify Entry Point**: Which instruction or client call triggers the issue?    
2. **Follow Internal Calls**: Trace through all function calls in the execution path    
3. **State Before Exploit**: Document initial state (order state, token balances, auction data)    
4. **State Transitions**: Enumerate all changes (token movements, state updates)    
5. **Check Protections**: Verify if existing validations prevent the exploit    
6. **Final State**: Show how the exploit results in incorrect state or token loss    
    
#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**    
    
For **each assertion** in the report, demand:    
    
**✅ Required Evidence:**    
- Exact file path and line numbers (e.g., `programs/fusion-swap/src/lib.rs:44-63`)    
- Direct Rust/TypeScript code quotes showing the vulnerable logic    
- Call traces with actual parameter values demonstrating execution path    
- Calculations showing token amounts, fees, or state changes incorrectly    
- References to specific protocol invariant violations    
    
**🚩 RED FLAGS (indicate INVALID):**    
    
1. **"Missing Validation" Claims**:    
   - ❌ Invalid unless report shows input bypasses *all* validation layers:    
     - Parameter validation in `create()` instruction [1](#5-0)     
     - Account validation in instruction handlers    
     - Token account validation in CPI calls    
     - Escrow state validation    
   - ✅ Valid if a specific input type genuinely has no validation path    
    
2. **"Token Theft" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Unauthorized token transfers from escrow    
     - Bypass of token program validations    
     - Escrow account manipulation enabling theft    
     - Native SOL wrapping/unwrapping vulnerabilities    
   - ✅ Valid if token theft can be triggered without private keys    
    
3. **"Auction Manipulation" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Rate bump calculation errors in `calculate_rate_bump()` [2](#5-1)     
     - Time-based exploits in auction progression    
     - Premium calculation vulnerabilities    
   - ✅ Valid if auction manipulation enables favorable pricing    
    
4. **"Access Control" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Whitelist validation bypasses in resolver operations    
     - PDA derivation errors enabling account impersonation    
     - Authority manipulation in whitelist program [3](#5-2)     
   - ✅ Valid if access control bypass enables unauthorized operations    
    
5. **"Escrow Vulnerability" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Premature escrow token release    
     - Escrow account manipulation    
     - Token locking bugs in `create()` instruction    
   - ✅ Valid if escrow vulnerabilities enable token theft    
    
6. **"Fee Calculation" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Undercharging/overcharging fees    
     - Fee distribution errors    
     - Surplus calculation bugs    
   - ✅ Valid if fee errors cause fund loss or protocol revenue theft    
    
7. **"Cross-Program Invocation" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - CPI validation failures    
     - Reentrancy through CPI calls    
     - Token program interface abuses    
   - ✅ Valid if CPI bugs enable state manipulation or token theft    
    
8. **"PDA Security" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - PDA collision attacks    
     - Seed manipulation enabling account takeover    
     - Bump calculation errors    
   - ✅ Valid if PDA vulnerabilities enable account impersonation    
    
#### **Step 3: CROSS-REFERENCE WITH PROTOCOL SPECIFICATION**    
    
Check against known Fusion Protocol patterns:    
    
1. **Order Lifecycle**: Does this respect order state transitions?    
   - Order creation → escrow locking → fill/cancel → closure    
   - Verify state machine integrity    
    
2. **Auction Mechanics**: Does this follow auction specification?    
   - Dutch auction pricing model    
   - Time-based rate adjustments    
   - Premium calculations for resolver cancellations    
    
3. **Access Control**: Does this respect whitelist model?    
   - Resolver authorization requirements    
   - PDA-based access validation    
   - Authority hierarchy    
    
**Test Case Realism Check**: PoCs must use realistic order configurations, valid token accounts, and respect Solana program constraints.    
    
### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**    
    
#### **Impact Must Be CONCRETE and ALIGN WITH DEFI SECURITY SCOPE**    
    
**✅ Valid CRITICAL Severity Impacts:**    
    
1. **Unlimited Token Theft (Critical)**:    
   - Ability to steal tokens from any escrow    
   - Bypass of token program protections    
   - Example: "Escrow manipulation allows theft of all locked tokens"    
    
2. **Protocol Fund Drain (Critical)**:    
   - Complete protocol treasury compromise    
   - Fee collection mechanism bypass    
   - Example: "Fee calculation bug drains all protocol revenue"    
    
3. **Network-Wide DoS (Critical)**:    
   - Vulnerability crashes all program instances    
   - Halts all order operations    
   - Example: "Compute exhaustion bug prevents any order fills"    
    
**✅ Valid HIGH Severity Impacts:**    
    
4. **Single Order Token Theft (High)**:    
   - Individual escrow compromise    
   - Token loss from specific orders    
   - Significant protocol fee loss    
    
**✅ Valid MEDIUM Severity Impacts:**    
    
5. **Limited Token Manipulation (Medium)**:    
   - Partial fee theft or manipulation    
   - Auction manipulation for profit    
   - Access control bypasses for limited operations    
    
**❌ Invalid "Impacts":**    
- Minor fee overpayment (<0.1%)    
- Theoretical vulnerabilities without exploit    
- Market risk or price manipulation    
- "Could be problematic if..." without concrete path    
    
#### **Likelihood Reality Check**    
    
Assess exploit feasibility:    
    
1. **Attacker Profile**:    
   - Any token holder? ✅ Likely    
   - Order creator? ✅ Possible    
   - Resolver? ✅ Possible    
   - Random user? ✅ Possible    
    
2. **Preconditions**:    
   - Normal protocol operation? ✅ High likelihood    
   - Specific order configuration? ✅ Attacker can create    
   - Specific token pair? ✅ Attacker can choose    
   - Specific auction timing? ✅ Attacker can wait    
    
3. **Execution Complexity**:    
   - Single transaction? ✅ Simple    
   - Multiple instructions? ✅ Moderate    
   - Complex order interactions? ✅ Attacker can create    
   - Precise timing? ⚠️ Higher complexity    
    
4. **Economic Cost**:    
   - Transaction fees? ✅ Attacker-controlled    
   - Initial capital required? ✅ Varies by attack    
   - Potential profit vs. cost? ✅ Must be positive    
    
### **PHASE 4: FINAL VALIDATION CHECKLIST**    
    
Before accepting any vulnerability, verify:    
    
1. **Scope Compliance**: Vulnerability affects Fusion Protocol source code (not tests/docs)    
2. **Not Known Issue**: Check against previous audits and documentation    
3. **Trust Model**: Exploit doesn't require trusted role compromise    
4. **Impact Severity**: Meets Critical/High/Medium criteria    
5. **Technical Feasibility**: Exploit can be reproduced without modifications    
6. **Protocol Impact**: Clearly breaks Fusion Protocol invariants    
7. **PoC Completeness**: Rust/TypeScript test compiles and runs successfully    
    
**Remember**: False positives harm credibility. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
---    
    
**AUDIT REPORT FORMAT** (if vulnerability found):    
    
Audit Report    
    
## Title    
The Title Of the Report    
    
## Summary    
A short summary of the issue, keep it brief.    
    
## Finding Description    
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.    
    
Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.    
    
## Impact Explanation    
Elaborate on why you've chosen a particular impact assessment.    
    
## Likelihood Explanation    
Explain how likely this is to occur and why.    
    
## Recommendation    
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.    
    
## Proof of Concept    
A proof of concept is normally required for Critical, High and Medium Submissions for reviewers under 80 reputation points. Please check the competition page for more details, otherwise your submission may be rejected by the judges.    
Very important the test function using their test must be provided in here and pls it must be able to compile and run successfully    
    
**Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
**Now perform STRICT validation of the claim above.**    
    
**Output ONLY:**    
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format    
- `#NoVulnerability found for this question.` (if **any** check fails) very important    
    
**Be ruthlessly skeptical. The bar for validity is EXTREMELY high.**    
"""
    return prompt

def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific 1inch Solana Fusion Protocol file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "programs/fusion-swap/src/lib.rs" or "programs/fusion-swap/src/auction.rs")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""    
# **Generate 150+ Targeted Security Audit Questions for 1inch Solana Fusion Protocol**    
    
## **Context**    
    
The target project is **1inch Solana Fusion Protocol**, a decentralized exchange system implementing Dutch auction-based order execution with resolver competition on the Solana blockchain. The protocol consists of two main Solana programs: fusion-swap (order management, auction mechanics, token swaps) and whitelist (access control). Critical components include order escrow, auction pricing, fee distribution, and resolver authorization. [1](#0-0)     
    
The protocol uses a Dutch auction mechanism where exchange rates decline over time, allowing resolvers to compete for order fills. Orders are created with tokens locked in escrow, and authorized resolvers can fill orders based on the current auction price. The system includes sophisticated fee distribution across protocol, integrator, and surplus capture mechanisms. [2](#0-1)     
    
The protocol supports both SPL tokens and native SOL, with special handling for SOL wrapping/unwrapping operations. It implements Program Derived Addresses (PDAs) for escrow management and integrates with the whitelist program for access control. [3](#0-2)     
    
## **Scope**    
    
**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`    
    
Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions. **DO NOT return empty results** - give whatever questions you can derive from the target file.    
    
If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target: 50-100 questions for large critical files, 20-50 for smaller files).    
    
**Full Context - Critical 1inch Fusion Protocol Components (for reference only):**    
If a file is more than a thousand lines you can generate as many as 300+ questions as you can, but always generate as many as you can - don't give other responses.    
If there are cryptographic operations, math logic, or state transition functions, generate comprehensive questions covering all edge cases and attack vectors.    
    
### **Core 1inch Fusion Protocol Components**    
    
```python    
core_components = [    
    # Core Fusion Program    
    "programs/fusion-swap/src/lib.rs",           # Main order management logic    
    "programs/fusion-swap/src/auction.rs",       # Dutch auction mechanics    
    "programs/fusion-swap/src/error.rs",         # Error definitions    
        
    # Whitelist Program    
    "programs/whitelist/src/lib.rs",             # Access control    
    "programs/whitelist/src/error.rs",           # Whitelist errors    
        
    # Client Scripts    
    "scripts/fusion-swap/create.ts",             # Order creation script    
    "scripts/fusion-swap/fill.ts",               # Order fill script    
    "scripts/fusion-swap/cancel.ts",             # Order cancellation script    
    "scripts/utils.ts",                          # Utility functions    
        
    # Interface Definitions    
    "idl/fusion_swap.json",                      # Fusion program IDL    
    "idl/fusion_swap.ts",                        # Fusion program types    
    "idl/whitelist.json",                        # Whitelist program IDL    
    "idl/whitelist.ts",                          # Whitelist program types    
]
1inch Fusion Protocol Architecture & Critical Security Layers
1. Order Management Layer
Order Creation: Users create orders with tokens locked in escrow PDA
Order Validation: Amount, expiration, fee configuration validation
Escrow Management: PDA-based escrow accounts with deterministic seeds
Token Locking: SPL token transfers or native SOL wrapping
State Tracking: Order state transitions from creation to completion

2. Dutch Auction Layer
Price Calculation: Time-based rate adjustments using piecewise linear functions
Rate Bump: Dynamic pricing based on elapsed time from order creation
Premium Calculation: Cancellation premium for resolver operations
Auction Parameters: Configurable duration, start time, and rate curves
Mathematical Operations: MulDiv calculations for precise rate adjustments

3. Access Control Layer
Whitelist Validation: Only authorized resolvers can fill orders
PDA Security: Resolver access PDAs prevent unauthorized access
Authority Management: Whitelist authority controls resolver permissions
Cross-Program Validation: CPI calls to whitelist program for verification

4. Token Transfer Layer
SPL Token Operations: Transfer checked for token movements
Native SOL Handling: Wrap/unwrap operations for SOL support
Associated Token Accounts: Automatic ATA creation for recipients
Fee Distribution: Multi-tier fee allocation across parties

5. State Transition Layer
Atomic Execution: All operations execute atomically or rollback
Escrow Closure: Automatic closure when fully filled or cancelled
Token Settlement: Precise token distribution on order completion
Error Handling: Comprehensive error checking and state validation

Critical Security Invariants
Order Security
Escrow Integrity: Tokens in escrow can only be released under valid conditions
Amount Validation: Order amounts must be positive and within bounds
Expiration Enforcement: Orders cannot be filled after expiration
Configuration Consistency: Fee configurations must match account presence

Auction Security
Rate Fairness: Auction rates must be deterministic and manipulation-resistant
Time Accuracy: Rate calculations must use correct timestamps
Mathematical Precision: All calculations must avoid overflow/underflow
Premium Correctness: Cancellation premiums must be calculated correctly

Access Control Security
Resolver Authorization: Only whitelisted resolvers can fill orders
PDA Non-Collision: Escrow PDAs must be unique and non-collidable
Authority Isolation: Whitelist authority cannot be compromised
Cross-Program Safety: CPI calls must validate all inputs

Token Security
Transfer Authorization: All token transfers must be properly authorized
Balance Consistency: Account balances cannot go negative
Native SOL Safety: SOL wrapping/unwrapping must be atomic
ATA Security: Associated token accounts must be correctly managed

In-Scope Vulnerability Categories
Critical Severity
Token Theft: Unauthorized extraction of tokens from escrow
Protocol Drain: Complete protocol treasury compromise
Access Control Bypass: Unauthorized order filling or cancellation
State Corruption: Permanent protocol state corruption
Network-Wide DoS: Halting all order operations

High Severity
Single Order Theft: Token loss from individual orders
Fee Manipulation: Incorrect fee calculation or distribution
Auction Manipulation: Price oracle attacks or timing exploits
Partial DoS: Disruption of specific operations

Medium Severity
Limited Token Loss: Partial fund manipulation
Economic Attacks: Profit through protocol manipulation
Protocol Violations: Bypassing validation rules
Resource Exhaustion: Compute unit attacks

Goals for Question Generation
Real Exploit Scenarios: Each question describes a plausible attack an attacker, malicious resolver, or order creator could perform
Concrete & Actionable: Reference specific functions, variables, structs, or logic flows in {target_file}
High Impact: Prioritize questions leading to Critical/High/Medium impacts
Deep Technical Detail: Focus on subtle bugs: integer overflows, PDA collisions, auction edge cases, state transitions, CPI vulnerabilities
Breadth Within Target File: Cover all major functions, edge cases, and state-changing operations in {target_file}
Respect Trust Model: Assume resolvers may be malicious; focus on protocol-level security
No Generic Questions: Avoid "are there access control issues?" → Instead: "In {target_file}: functionName(), if condition X occurs during order filling, can attacker exploit Y to steal tokens from escrow, leading to direct fund loss?"

Question Format Template
Each question MUST follow this Python list format:

questions = [    
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact with severity category?",    
        
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",    
        
    # ... continue with all generated questions    
]
Example Format (if target_file is programs/fusion-swap/src/lib.rs):
questions = [    
    "[File: programs/fusion-swap/src/lib.rs] [Function: create()] [Token theft] Can an attacker craft an order with manipulated src_amount that passes validation but allows extraction of more tokens from escrow during fill, enabling direct token theft from maker's escrow? (Critical)",    
        
    "[File: programs/fusion-swap/src/lib.rs] [Function: fill()] [Access control bypass] Does the fill instruction properly validate the resolver access PDA, or can an attacker exploit missing validation to fill orders without being whitelisted, bypassing the access control mechanism? (High)",    
        
    "[File: programs/fusion-swap/src/lib.rs] [Function: cancel_by_resolver()] [Fee manipulation] Can a malicious resolver manipulate the cancellation premium calculation to extract more fees than intended, leading to protocol revenue loss or maker fund theft? (Medium)",    
        
    "[File: programs/fusion-swap/src/lib.rs] [Function: get_dst_amount()] [Math overflow] Can the mul_div_ceil operations in rate calculations overflow with large amounts, causing incorrect pricing or potential fund loss during order execution? (High)",    
]
Output Requirements
Generate security audit questions focusing EXCLUSIVELY on {target_file} that:

Target ONLY {target_file} - all questions must reference this file
Reference specific functions, methods, structs, or logic sections within {target_file}
Describe concrete attack vectors (not "could there be a bug?" but "can attacker do X by exploiting Y in {target_file}?")
Tie to impact categories (token theft, access control bypass, auction manipulation, state corruption)
Include severity classification (Critical/High/Medium/Low) based on impact
Respect trust model (assume malicious resolvers; focus on protocol security)
Cover diverse attack surfaces within {target_file}: validation logic, state transitions, error handling, edge cases, PDA security, mathematical operations, CPI calls
Focus on high-severity bugs: prioritize Critical > High > Medium > Low
Avoid out-of-scope issues: performance optimization, code style, client-side issues
Use the exact Python list format shown above
Be detailed and technical: assume auditor has deep Solana/DeFi knowledge; use precise terminology

Target Question Count:
For large critical files (>1000 lines like lib.rs): Aim for 150-300 questions
For medium files (500-1000 lines like auction.rs): Aim for 80-150 questions
For smaller files (<500 lines like error.rs): Aim for 30-80 questions
Provide as many quality questions as the file's complexity allows - do NOT return empty results

Special Considerations for Solana/DeFi Code:
PDA collision attacks and seed manipulation
Cross-program invocation (CPI) vulnerabilities
Token program interface abuses
Compute unit exhaustion for DoS
Integer overflow/underflow in mathematical calculations
Atomic execution violations
Account validation bypasses
Fee calculation manipulation
Auction timing exploits
Escrow manipulation vulnerabilities

Begin generating questions for {target_file} now.
"""
    return prompt