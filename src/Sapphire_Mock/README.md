# Sapphire Mock

Solidity smart contracts that simulate an [Oasis Sapphire](https://docs.oasis.io/dapp/sapphire/)
confidential EVM environment on a local Anvil chain. Part of the Sybil-Resistant Identity PoC.

The [ROFL Mock](../ROFL_Mock/) (Python FastAPI service) produces signed registration and connection
payloads; these contracts verify those signatures and manage on-chain state.

---

## Contracts

| Contract | Description |
|---|---|
| `SapphireMock` | Library — simulates the Sapphire randomness precompile |
| `IdentityRegistry` | Verifies ROFL signatures and records user registration state |
| `ConnectionManager` | Two-step connection handshake keyed by a Poseidon commitment |

---

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge`, `anvil`, `cast`)
- The ROFL Mock server running and its signing address known

---

## Install dependencies

Dependencies are already committed under `lib/`. If you need to reinstall from scratch:

```bash
forge install
```

---

## Run tests

No running chain is required — Forge provides its own in-process EVM.

```bash
forge test -vvv
```

All 13 tests should pass (6 unit + 1 fuzz for `IdentityRegistry`, 6 unit for `ConnectionManager`).

---

## Deploy to local Anvil

**1. Start Anvil**

```bash
anvil
```

**2. Deploy**

The deploy script uses Anvil account #9 as the deployer (key is hardcoded for local dev).
Set `ROFL_MOCK_ADDRESS` to the Ethereum address derived from the ROFL Mock's signing key.

```bash
ROFL_MOCK_ADDRESS=0x<rofl_mock_signing_address> \
  forge script script/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast
```

The script deploys three contracts in order and prints their addresses:

```
Poseidon:           0x...
IdentityRegistry:   0x...
ConnectionManager:  0x...
```

Pass these addresses to the ROFL Mock and Client configuration as needed.

---

## CC duality — Keccak (ROFL) vs Poseidon (on-chain)

The connection commitment `CC_AB` is computed twice, by two different algorithms, for two
different purposes:

| Side | Algorithm | Purpose |
|---|---|---|
| ROFL Mock (Python) | `Keccak256(addr_lo_bytes \|\| addr_hi_bytes)` | Embedded in the signed JSON payload |
| Contract (Solidity) | `Poseidon([uint160(lo), uint160(hi)])` | Storage key for the `connections` mapping |

**Why two algorithms?**

- Keccak256 is native to Python/web3 tooling and easy to reproduce off-chain.
- Poseidon is ZK-friendly and consistent with the broader circuit architecture of the project.

**How the contract bridges them:**

When `establishConnection` is called, the contract:
1. Accepts `roflCC` (the Keccak-based value) from the caller.
2. Recomputes the same Keccak over `(uint160(min), uint160(max))` and checks `roflCC` matches —
   this confirms the caller is not substituting a different identity pair.
3. Independently computes `expectedCC` via Poseidon and uses *that* as the storage key.

This is intentional and not a bug. The `roflCC` parameter is consumed only for the identity
consistency check; `expectedCC` drives all state.

---

## Known limitations of the Sapphire simulation

### Randomness is not cryptographically secure

`SapphireMock.randomBytes()` simulates the Sapphire secure-randomness precompile using:

```solidity
keccak256(abi.encodePacked(block.timestamp, block.prevrandao, caller))
```

On a public EVM this is manipulable by block proposers. **Do not use in production.**
On real Sapphire, the precompile sources entropy from the TEE.

### Contract-level signing precompile is omitted

On real Oasis Sapphire, `Sapphire.sign(bytes32 digest)` produces a TEE-attested secp256k1
signature from the contract's key — a capability that does not exist on standard EVM.

This mock omits that step entirely. When a connection is completed, `ConnectionEstablished(ccS)`
emits the final commitment `ccS` **unsigned**. On real Sapphire the commitment would be signed
by the contract's enclave key, providing cryptographic proof of TEE involvement.

The commitment `ccS = Poseidon(expectedCC, S)` is itself a proof of completed handshake —
it binds the identity pair (via `expectedCC`) to the secret `S` generated on-chain — but it
carries no TEE attestation in this mock.


## Gas Report

```
forge test --gas-report
╭-----------------------------------------------------------+-----------------+--------+--------+--------+---------╮
| lib/poseidon-sol/contracts/Poseidon.sol:Poseidon Contract |                 |        |        |        |         |
+==================================================================================================================+
| Deployment Cost                                           | Deployment Size |        |        |        |         |
|-----------------------------------------------------------+-----------------+--------+--------+--------+---------|
| 2029710                                                   | 9170            |        |        |        |         |
|-----------------------------------------------------------+-----------------+--------+--------+--------+---------|
|                                                           |                 |        |        |        |         |
|-----------------------------------------------------------+-----------------+--------+--------+--------+---------|
| Function Name                                             | Min             | Avg    | Median | Max    | # Calls |
|-----------------------------------------------------------+-----------------+--------+--------+--------+---------|
| hash                                                      | 196384          | 196384 | 196384 | 196384 | 10      |
╰-----------------------------------------------------------+-----------------+--------+--------+--------+---------╯

╭------------------------------------------------------+-----------------+--------+--------+--------+---------╮
| src/ConnectionManager.sol:ConnectionManager Contract |                 |        |        |        |         |
+=============================================================================================================+
| Deployment Cost                                      | Deployment Size |        |        |        |         |
|------------------------------------------------------+-----------------+--------+--------+--------+---------|
| 858255                                               | 4059            |        |        |        |         |
|------------------------------------------------------+-----------------+--------+--------+--------+---------|
|                                                      |                 |        |        |        |         |
|------------------------------------------------------+-----------------+--------+--------+--------+---------|
| Function Name                                        | Min             | Avg    | Median | Max    | # Calls |
|------------------------------------------------------+-----------------+--------+--------+--------+---------|
| establishConnection                                  | 30227           | 257493 | 287534 | 491198 | 9       |
╰------------------------------------------------------+-----------------+--------+--------+--------+---------╯

╭----------------------------------------------------+-----------------+--------+--------+--------+---------╮
| src/IdentityRegistry.sol:IdentityRegistry Contract |                 |        |        |        |         |
+===========================================================================================================+
| Deployment Cost                                    | Deployment Size |        |        |        |         |
|----------------------------------------------------+-----------------+--------+--------+--------+---------|
| 717378                                             | 3234            |        |        |        |         |
|----------------------------------------------------+-----------------+--------+--------+--------+---------|
|                                                    |                 |        |        |        |         |
|----------------------------------------------------+-----------------+--------+--------+--------+---------|
| Function Name                                      | Min             | Avg    | Median | Max    | # Calls |
|----------------------------------------------------+-----------------+--------+--------+--------+---------|
| embeddingToAddress                                 | 2463            | 2463   | 2463   | 2463   | 264     |
|----------------------------------------------------+-----------------+--------+--------+--------+---------|
| registerProfile                                    | 70891           | 118597 | 119205 | 121150 | 275     |
|----------------------------------------------------+-----------------+--------+--------+--------+---------|
| registrationState                                  | 2616            | 2616   | 2616   | 2616   | 275     |
|----------------------------------------------------+-----------------+--------+--------+--------+---------|
| reputation                                         | 2538            | 2538   | 2538   | 2538   | 1       |
╰----------------------------------------------------+-----------------+--------+--------+--------+---------╯
```