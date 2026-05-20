# Implementation of the Sybil-resistant Identity System

This is the main implementation of the system designed in the [thesis](../doc/thesis.pdf).
The implementation is divided into five parts:

+ **ZK Random Walks & ZK Proof of Paths:** Implementation of ZK circuits for ZK random walks and ZK proof of paths.
Two different circuit approaches are implemented for ZK random walks, and for both ZK random walks and ZK proof of paths, there are practical examples.
+ **Client:** A application on the entity side that communicates with ROFL and calls transactions on Sapphire smart contracts.
+ **ROFL Mock:** A component that represents a program running inside the Oasis ROFL Trusted Execution Environment. It processes and responds to the `register` and `connect` requests from the Client and signs the result with its private key.
+ **Sapphire Mock:** A component that represents confidential smart contracts on the Oasis Sapphire network.
+ **Relayer:** A component that listens to events emitted by the smart contracts on Sapphire and inserts connection commitments into a on-chain Merkle tree.


## [ZK Random Walks & ZK Proof of Paths](./zk_logic/)

Both ZK random walks and ZK proof of paths uses the [Plonky2](https://github.com/0xPolygonZero/plonky2) proof system.
Detailed description of the circuits is in the [thesis](../doc/thesis.pdf).
There is one notable abstraction compared to the original design, as it is a PoC implementation.
The Bloom filter for ensuring path distinctiveness is replaced with a simple array of nullifiers.

Two different approaches of ZK random walks are implemented:

+ **Linear:** One separate compiled circuit per recursion depth, so it is required to have $l + 1$ circuits, where $l$ is the required length of the path.
This approach is possible because the number of recursive steps is predictable.
Each circuit embeds the Verification Key (VK) of the previous circuit (a specific, public component used in non-interactive ZKPs), but there must also be a base circuit without prior recursion.
Linear setup: $\texttt{BaseCircuit} \rightarrow \texttt{StepCircuit[0]} \rightarrow \texttt{StepCircuit[1]} \rightarrow \dots \rightarrow \texttt{StepCircuit[l]}$.
The advantage is that each circuit is smaller and simpler compared to the Cyclic circuit.
This positively affects the proof time, verification time, and circuit size.
+ **Cyclic:**A single self-referential circuit for all recursion steps that verifies its own previous proof via a special Plonky2's recursive method.
This method uses a dummy inner proof that bypasses all constraints during the first step, and a recursive real proof with the full constraint set in every other step.
The advantage is that there is only one universal circuit for any required path length.
However, it is more complex, which negatively affects the proof time, verification time, and circuit size.


The implementation is divided into the following parts:

+ [**Merkle tree utils:**](./zk_logic/merkle_utils/) Utilities for constructing Merkle tries and sparse Merkle tries, primarily for testing.
The Poseidon implementation of Plonky2 is used as a hash function.
+ [**Merkle proof gadgets for ZK circuits:**](./zk_logic/merkle_circuit/) Both linear and cyclic circuits use Merkle inclusion proofs and Merkle non-inclusion proofs; these circuit gadgets are separated here and used in both approaches, so the implementation is not repeated.
+ **ZK random walk circuit** [**linear**](./zk_logic/circuit_lib_linear/) **&** [**cyclic**](./zk_logic/circuit_lib_cyclic/)**:** Implementation of both linear and cyclic circuits with the use of Merkle gadgets.
+ **Prover, verifier, and examples** [**linear**](./zk_logic/prover_linear/) **&** [**cyclic**](./zk_logic/prover_cyclic/)**:** Implementation of prover and verifier APIs for both linear and cyclic approaches with the same template.
There are three prover methods and one verifier method:
  - `setup()`: Compiles the circuit and, in the linear variant, builds the base circuit and a separate circuit for each step.
  In the cyclic variant, a single unified circuit is built.
  - `prove_base()`: Generates the base proof for the linear variant and the dummy proof for the cyclic variant.
  - `prove_step()`: Takes the previous proof (or the base/dummy proof) and the necessary inputs, and extends the proof by one step.
  - `verify_walk_proof()`: Takes the circuit and the proof as parameters and verifies their validity.
+ [**ZK proof of paths circuit and examples:**](./zk_logic/aggregator/) Implementation of the ZK circuit, and prover and verifier APIs.
There are two prover methods and one verifier method:
  - `setup()`: Compiles the circuit and, in the linear variant, builds the base circuit and a separate circuit for each step.
  In the cyclic variant, a single unified circuit is built.
  - `prove()`: Takes `k` ZK random walk proofs and generate an aggregated proof.
  - `verify_aggregated_proof()`: Takes the circuit and the proof as parameters and verifies their validity.


_Implementation:_ **Rust (Nightly)**  
_Dependencies:_ see **Cargo.toml** for individual packages

### Examples

**ZK Random Walks Examples**

Two examples were made for both the linear and cyclic variants.
+ [`three_hop_linear.rs`](./zk_logic/prover_linear/examples/three_hop_linear.rs) & [`three_hop_cyclic.rs`](./zk_logic/prover_cyclic/examples/three_hop_cyclic.rs): This example shows a ZK random walk with base plus three steps.
The three-step walk is a sufficient example, as each step requires the same computational effort.
+ [`large_tries_linear.rs`](./zk_logic/prover_linear/examples/large_tries_linear.rs) & [`large_tries_linear.rs`](./zk_logic/prover_cyclic/examples/large_tries_cyclic.rs): This example shows only base plus one step, but with Merkle tries of depth 20 and the sparse Merkle tree of depth 32.
It demonstrates the efficiency when more hash operations are required, as the `three_hop_*.rs` is trivial with only four elements in Merkle tries.


**ZK Proof of Paths Examples**

Two examples were made, both examples use the linear variant of the ZK random walk:
+ [`aggregate_three.rs`](./zk_logic/aggregator/examples/aggregate_three.rs): Aggregates three ZK random walks.
+ [`aggregate_six.rs`](./zk_logic/aggregator/examples/aggregate_six.rs): Aggregates six ZK random walks.


## [Client](./Client/)

The implementation is divided into the following parts:

+ [`config.py`](./Client/config.py): Load client configuration (ROFL url, blockchain RPC url, smart contract addresses and ABIs).
+ [`register_cmd.py`](./Client/register_cmd.py): Registers a new user identity using 2D photo. A required parameter is a path to a JSON file containing `SK` and `PK`, and a path to a 2D face photo. The Client reads a JSON file, loads the photo, signs the payload, and sends a POST request to ROFL. If ROFL finds a match, the registration is rejected without an on-chain transaction. If no match is found, then the client saves the returned embedding from ROFL and uses the signed ROFL result to call an on-chain transaction to register a new identity. 
+ [`connect_cmd.py`](./Client/connect_cmd.py): Initialize a connection with other entity. A required parameter is a path to a JSON file containing `SK`, `PK`, the `ID` of the entity to connect with, and a path to a 2D face photo of this entity. The Client reads the JSON file, loads the photo, loads the entity's stored embedding, signs the payload, and sends a POST request to ROFL. If there is a match between the sent embedding and the embedding from the sent photo, then ROFL returns a signed connection commitment that is used to call an on-chain transaction to register a new connection. If there is no match, no on-chain transaction is sent.
+ [`chain.py`](./Client/chain.py): Send connection establishment transaction to the blockchain.
+ [`cli.py`](./Client/cli.py): Command Line Interface for the client application.


_Implementation:_ **Python 3.12+**  
_Dependencies:_ see [Client/requirements.txt](./Client/requirements.txt)


### Usage

```bash
python3 -m src.client.cli register config_register.json
python3 -m src.client.cli connect  config_connect.json
```

### Configuration Examples

#### Client config

```json
{
  "api_url": "http://localhost:8000",
  "rpc_url": "http://localhost:8545",
  "registry_address": "0xA15BB66138824a1c7167f5E85b957d04Dd34E468",
  "registry_abi_path": "abi/IdentityRegistry.json",
  "connection_manager_address": "0xb19b36b1456E65E3A6D514D3F715f204BD59f431",
  "connection_manager_abi_path": "abi/ConnectionManager.json"
}
```

#### `register` config

```json
{
  "SK": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "PK": "0x048318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5",
  "photo_path": "./sample_photos/brad.jpg"
}
```

#### `connect` config

```json
{
  "SK_A": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "PK_A": "0x048318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5",
  "ID_B": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "photo_B_path": "./sample_photos/keanu.jpg"
}
```

## [ROFL Mock](./ROFL_Mock/)

The implementation is divided into the following parts:

+ [`config.py`](./ROFL_Mock/app/config.py): Loads configuration form `.env`.
+ [`crypto.py`](./ROFL_Mock/app/crypto.py): Functions for cryptographic operations (ECDSA signatures, AES encryption/decryption, Ethereum address derivation, etc.)
+ [`database.py`](./ROFL_Mock/app/database.py): Logic for access to PostgreSQL database.
+ [`embedding.py`](./ROFL_Mock/app/embedding.py): Wrapper for FaceNet model. 2D facial image embedding extraction.
+ [`models.py`](./ROFL_Mock/app/models.py): Request/response schemas for endpoints.
+ [`routes/`](./ROFL_Mock/app/routes/): Implementation of _register_ and _connect_ endpoints. 
+ [`main.py`](./ROFL_Mock/app/main.py): App entry point. Initialize FastAPI, and registers routes, create DB pool, etc.


_Implementation:_ **Python 3.12+**  
_Dependencies:_ Docker & see [ROFL_Mock/requirements.txt](./ROFL_Mock/requirements.txt)


### Running the Server (ROFL Mock)

The application that runs in ROFL is containerized. The PostgreSQL database also runs inside the container.

```bash
docker compose up --build
```

### `.env` Example

```bash
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_DB=rofldb
POSTGRES_USER=rofl
POSTGRES_PASSWORD=roflpass

SK_ROFL=0x72ad0c21afd2c74612ea9df2f0b12b8964b0988484aaff73c9fba8e8ec12c163
PK_ROFL=0x04be09c3f7d81114651b1474ed0de4fbcb720765d4c94842a15ebc1187d4ad3dc956c189ef55f89e209799e041223d956f9486460de3c809f35f95ff2c73c9b3bc
ADDRESS_ROFL=0x06f7fcd662714b099a6b1c14958fd6d826745616
SYM_KEY=3c1d02eeb369aa3b5310d7602fd5282b80f2ca358b605afc6f91dd9baa8ef70e
DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
SIMILARITY_THRESHOLD=0.85
```


## [Sapphire Mock](./Sapphire_Mock/)

The implementation is divided into the following parts:

+ [`IdentityRegistry.sol`](./Sapphire_Mock/src/IdentityRegistry.sol): On-chain registry of identities and their states. Users can call the `registerProfile()` function to register a new identity.
+ [`ConnectionManager.sol`](./Sapphire_Mock/src/ConnectionManager.sol): On-chain registry of established connections. Users can call the `establishConnection()` function to establish a new connection.
+ [`IncrementalMerkleTree.sol`](./Sapphire_Mock/src/IncrementalMerkleTree.sol): Implementation of an on-chain Incremental Merkle Tree

### Contract Deployment on Anvil

```bash
ROFL_MOCK_ADDRESS=0x<rofl_mock_signing_address> \
  forge script script/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast
```

_Implementation:_ **Solidity 0.8.24+**  
_Dependencies:_ [Foundry](https://book.getfoundry.sh/getting-started/installation), [openzeppelin-contracts](https://docs.openzeppelin.com/contracts), and [poseidon-sol](https://github.com/yuriko627/poseidon-sol)


## [Relayer](./Relayer/)


Relayer is a very simple application. It is implemented in [relayer.py](./Relayer/relayer.py). It takes connection commitments emitted in `ConnectionManager` events and calls the `insert()` function in the Merkle tree smart contract. Relayer also requires a configuration `config.json` (see example).


### Configuration Example

```json
{
  "rpc_url": "http://localhost:8545",
  "relayer_private_key": "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
  "connection_manager_address": "0xb19b36b1456E65E3A6D514D3F715f204BD59f431",
  "connection_manager_abi_path": "abi/ConnectionManager.json",
  "merkle_tree_address": "0x8ce361602B935680E8DeC218b820ff5056BeB7af",
  "merkle_tree_abi_path": "abi/IncrementalMerkleTree.json",
  "poll_interval_seconds": 2
}
```


### Usage

```bash
python relayer.py
```