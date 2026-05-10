# ROFL Mock Client

A `click`-based CLI for interacting with the ROFL Mock TEE server.

---

## Setup

```bash
cd Client
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

Run all commands from the `Client/` directory with the virtual environment active.

```bash
python3 -m src.client.cli register config_register.json
python3 -m src.client.cli connect  config_connect.json
```

---

## Configuration

### `register` config

```json
{
  "api_url": "http://localhost:8000",
  "SK": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "PK": "0x04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "photo_path": "/path/to/face/image.jpg"
}
```

| Field | Description |
|---|---|
| `api_url` | Base URL of the running ROFL Mock server |
| `SK` | Your 32-byte ECDSA private key, `0x`-prefixed hex |
| `PK` | Your uncompressed ECDSA public key (`04` + 64 bytes), `0x`-prefixed hex |
| `photo_path` | Absolute or relative path to a face photo (JPEG / PNG) |

### `connect` config

```json
{
  "api_url": "http://localhost:8000",
  "SK_A": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "PK_A": "0x04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "ID_B": "0xdddddddddddddddddddddddddddddddddddddddd",
  "photo_B_path": "/path/to/b_face.jpg"
}
```

| Field | Description |
|---|---|
| `SK_A` | Party A's private key |
| `PK_A` | Party A's uncompressed public key |
| `ID_B` | Party B's Ethereum address (the `ID` field from B's `/register` response) |
| `photo_B_path` | Path to a live photo of party B |

> **Note:** The embedding for `ID_B` is loaded automatically from `registered_embeddings/<ID_B>.json`, which is written by the `register` command after a successful registration. Party B must have registered before A can establish a connection with them.

---

## Embedding store

Successful registrations (`match_result: false`) are automatically saved to `registered_embeddings/<ID>.json`:

```
Client/
└── registered_embeddings/
    ├── 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266.json
    └── 0x70997970C51812dc3A010C7d01b50e0d17dc79C8.json
```

The `connect` command reads B's embedding from this directory using `ID_B` from the config — no manual copy-paste needed.

---

## Output

Both commands pretty-print the JSON response from the server.

The `register` command additionally prints:
- A `WARNING` line when `match_result` is `true` (duplicate detected, registration rejected).
- The path to the saved embedding file when registration succeeds.
- The on-chain transaction hash when registration is submitted to `IdentityRegistry`.

The `connect` command additionally prints:
- The on-chain transaction hash when a connection is submitted to `ConnectionManager`.

---

## Shared Infrastructure Config

Both commands read shared infrastructure settings (RPC URL, contract addresses, ABI paths) from `Client/config.json`. This file is **not committed** to the repo because contract addresses differ per deployment.

### Setup

```bash
cp Client/config.json.example Client/config.json
# then fill in the deployed addresses
```

### Schema

```json
{
  "api_url": "http://localhost:8000",
  "rpc_url": "http://localhost:8545",
  "registry_address": "0x<IdentityRegistry address>",
  "registry_abi_path": "abi/IdentityRegistry.json",
  "connection_manager_address": "0x<ConnectionManager address>",
  "connection_manager_abi_path": "abi/ConnectionManager.json"
}
```

| Field | Description |
|---|---|
| `api_url` | Base URL of the running ROFL Mock server |
| `rpc_url` | JSON-RPC endpoint of the local Anvil chain |
| `registry_address` | Deployed `IdentityRegistry` contract address |
| `registry_abi_path` | Path to the ABI file, relative to `Client/` |
| `connection_manager_address` | Deployed `ConnectionManager` contract address |
| `connection_manager_abi_path` | Path to the ABI file, relative to `Client/` |

### Getting contract addresses

Contract addresses are printed by the deploy script and also recorded in the Foundry broadcast directory:

```bash
cd src/Sapphire_Mock
forge script script/Deploy.s.sol --broadcast
# addresses are printed to stdout and saved under broadcast/
```

### Getting ABI files

The ABI files are exported by `forge build` and then copied into `Client/abi/`:

```bash
cd src/Sapphire_Mock
forge build
cp out/IdentityRegistry.sol/IdentityRegistry.json ../Client/abi/IdentityRegistry.json
cp out/ConnectionManager.sol/ConnectionManager.json ../Client/abi/ConnectionManager.json
```

> `Client/abi/` is gitignored — re-run the copy after any contract change.
