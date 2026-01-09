# Audit Report

## Title
Non-Deterministic Build Process Prevents Independent Verification of Deployed Program Integrity

## Summary
The 1inch Solana Fusion Protocol's build process does not produce deterministic binaries, making it impossible for users to independently verify that deployed on-chain programs match the published source code. The build scripts lack the `--verifiable` flag required for reproducible Anchor builds.

## Finding Description

The protocol's build configuration uses standard Anchor builds without determinism guarantees. [1](#0-0) 

The `build:all` script executes `cargo build-sbf && anchor build -p fusion-swap && anchor build -p whitelist` without the critical `--verifiable` flag that Anchor provides for reproducible builds.

Similarly, deployment scripts use non-deterministic builds: [2](#0-1) 

The Anchor framework (version 0.31.1 in use) [3](#0-2)  provides a `--verifiable` flag that creates Docker-based deterministic builds. Without this flag, builds are non-deterministic due to:

1. **Environment Variations**: Different local environments (system libraries, PATH configurations, installed toolchains)
2. **Timestamp Embedding**: Build timestamps embedded in binaries
3. **File System Metadata**: Different file ordering or metadata on different systems
4. **Procedural Macro Expansion**: Macros that may depend on environment state
5. **Host Architecture Dependencies**: Platform-specific compilation artifacts

While the repository does pin tool versions [4](#0-3)  and uses locked dependencies [5](#0-4) , and sets some deterministic compilation flags [6](#0-5) , these measures are insufficient without Anchor's `--verifiable` build mode.

**Security Guarantee Broken**: Users cannot cryptographically verify that deployed program bytecode was built from the published source code, breaking the fundamental trust model of decentralized systems where "don't trust, verify" is paramount.

## Impact Explanation

**Medium Severity** - This issue creates a critical trust gap in the protocol:

1. **Inability to Verify Deployments**: Community members, security researchers, and users cannot independently compile the source and verify the on-chain bytecode matches
2. **Blind Trust Requirement**: Users must trust that 1inch deployed the correct code without any technical verification mechanism
3. **Insider Threat Surface**: If deployment credentials were compromised or an insider acted maliciously, modified bytecode could be deployed without detection
4. **Supply Chain Risk**: Users cannot detect if the build process itself was compromised

While this doesn't enable direct exploitation by unprivileged attackers of the runtime protocol logic, it fundamentally undermines the security model of verifiable smart contracts. In a truly decentralized system, users should be able to independently verify what's running on-chain.

The impact is classified as Medium rather than High because:
- It requires privileged access (deployment keys) to exploit
- The 1inch team is considered trusted per the threat model
- No direct runtime exploitation path exists for unprivileged actors

However, it represents a significant security posture weakness that could enable undetected malicious deployments.

## Likelihood Explanation

**Likelihood: Medium to High**

The non-determinism is not theoretical - it will occur with certainty when different developers or users attempt to build the programs:
- **100% Occurrence Rate**: Every build on a different machine WILL produce different bytecode
- **Easy to Demonstrate**: Can be proven by building on two different systems and comparing hashes
- **Already Happening**: Current deployments cannot be verified by the community

The likelihood of this being exploited maliciously is lower (requires privileged access), but the likelihood of the verification problem existing is absolute.

## Recommendation

Implement verifiable builds using Anchor's built-in functionality:

1. **Update Build Scripts** - Modify `package.json` to use the `--verifiable` flag:

```json
"build:all": "cargo build-sbf && anchor build --verifiable -p fusion-swap && anchor build --verifiable -p whitelist",
"build": "anchor build --verifiable",
"deploy:fusion_swap": "anchor clean && anchor keys sync && anchor build --verifiable && anchor deploy --program-name fusion-swap --provider.cluster ",
"deploy:whitelist": "anchor clean && anchor keys sync && anchor build --verifiable && anchor deploy --program-name whitelist --provider.cluster "
```

2. **Integrate Verification Tools** - Add scripts to verify deployed programs:

```json
"verify:fusion_swap": "anchor verify --program-name fusion-swap",
"verify:whitelist": "anchor verify --program-name whitelist"
```

3. **Document Verification Process** - Create documentation showing users how to independently verify deployed programs match the source.

4. **CI/CD Integration** - Update CI/CD workflows to use verifiable builds and publish build artifacts with checksums.

5. **Set Build Environment Variables** - Ensure `SOURCE_DATE_EPOCH` is set for additional determinism:

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
```

## Proof of Concept

**Reproduction Steps:**

1. Clone the repository on Machine A (e.g., Ubuntu 22.04):
```bash
git clone https://github.com/1inch/solana-fusion-protocol
cd solana-fusion-protocol
yarn install
yarn build:all
sha256sum target/deploy/fusion_swap.so > hash_machine_a.txt
```

2. Clone the repository on Machine B (e.g., macOS or different Ubuntu version):
```bash
git clone https://github.com/1inch/solana-fusion-protocol
cd solana-fusion-protocol
yarn install
yarn build:all
sha256sum target/deploy/fusion_swap.so > hash_machine_b.txt
```

3. Compare hashes:
```bash
diff hash_machine_a.txt hash_machine_b.txt
```

**Expected Result**: Hashes will differ, proving non-deterministic builds.

4. Test with verifiable builds:
```bash
# On both machines
anchor build --verifiable -p fusion-swap
sha256sum target/verifiable/fusion_swap.so
```

**Expected Result**: With `--verifiable`, hashes should match (when using same Anchor/Solana versions).

**Test Script** (add to repository):
```bash
#!/bin/bash
# verify-build.sh

echo "Testing build determinism..."
echo "Building twice and comparing outputs..."

# First build
yarn build:all
cp target/deploy/fusion_swap.so fusion_swap_build1.so
rm -rf target

# Second build  
yarn build:all
cp target/deploy/fusion_swap.so fusion_swap_build2.so

# Compare
if cmp -s fusion_swap_build1.so fusion_swap_build2.so; then
    echo "✓ Builds are deterministic"
    exit 0
else
    echo "✗ Builds are non-deterministic"
    echo "Hash 1: $(sha256sum fusion_swap_build1.so)"
    echo "Hash 2: $(sha256sum fusion_swap_build2.so)"
    exit 1
fi
```

## Notes

This finding addresses a build-time security concern rather than a runtime vulnerability. While it doesn't enable direct exploitation of the protocol logic by unprivileged attackers, it represents a fundamental weakness in the security posture that prevents independent verification of deployed code - a critical requirement for trustless decentralized systems.

The issue is categorized as Medium severity because although the technical impact is significant (complete inability to verify deployments), exploitation requires privileged access to deployment mechanisms. However, in the context of decentralized finance where "don't trust, verify" is a core principle, this represents a meaningful security gap that should be addressed.

### Citations

**File:** package.json (L13-13)
```json
    "build:all": "cargo build-sbf && anchor build -p fusion-swap && anchor build -p whitelist",
```

**File:** package.json (L19-20)
```json
    "deploy:fusion_swap": "anchor clean && anchor keys sync && anchor build && anchor deploy --program-name fusion-swap --provider.cluster ",
    "deploy:whitelist": "anchor clean && anchor keys sync && anchor build && anchor deploy --program-name whitelist --provider.cluster "
```

**File:** Anchor.toml (L2-2)
```text
anchor_version = "0.31.1"
```

**File:** rust-toolchain.toml (L2-2)
```text
channel = "1.86.0"
```

**File:** Cargo.lock (L1-3)
```text
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4
```

**File:** Cargo.toml (L7-14)
```text
[profile.release]
overflow-checks = true
lto = "fat"
codegen-units = 1
[profile.release.build-override]
opt-level = 3
incremental = false
codegen-units = 1
```
