# Relayer

Watches `ConnectionManager` for `ConnectionEstablished` events and inserts each `ccS` commitment into the `IncrementalMerkleTree` on-chain.

---

## Prerequisites

1. **Anvil** must be running:
   ```bash
   anvil
   ```

2. **Sapphire Mock deployed** with the relayer account's address passed as `RELAYER_ADDRESS`:
   ```bash
   ROFL_MOCK_ADDRESS=0x<ROFL_MOCK_ADDRESS> \
     forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
   ```
   Note the printed addresses — you will need `ConnectionManager` and `IncrementalMerkleTree`.

3. **Relayer account** — any Ethereum key pair. Anvil's default funded accounts work well for local testing. Derive the address from a private key:
   ```bash
   python3 -c "from eth_account import Account; print(Account.from_key('0x<PRIVATE_KEY>').address)"
   ```
   Ensure this address has enough ETH on Anvil to pay gas (~1.2M gas per insert).

---

## Setup

```bash
cd src/Relayer

python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy the example config and fill in the deployed addresses:

```bash
cp config.json.example config.json
$EDITOR config.json
```

`config.json` fields:

| Field | Description |
|---|---|
| `rpc_url` | Anvil HTTP endpoint (default `http://localhost:8545`) |
| `relayer_private_key` | `0x`-prefixed private key of the relayer account |
| `connection_manager_address` | Deployed `ConnectionManager` address |
| `connection_manager_abi_path` | Path to ABI (relative to `Relayer/`), default `abi/ConnectionManager.json` |
| `merkle_tree_address` | Deployed `IncrementalMerkleTree` address |
| `merkle_tree_abi_path` | Path to ABI (relative to `Relayer/`), default `abi/IncrementalMerkleTree.json` |
| `poll_interval_seconds` | Polling interval in seconds (default `2`) |

---

## Run

```bash
python relayer.py
```

---

## Expected log output

A successful end-to-end flow produces three log lines per connection:

```
2026-05-10 23:59:53,100 INFO  Connected to http://localhost:8545 (chain id 31337)
2026-05-10 23:59:53,101 INFO  Relayer address: 0xA0Ee7A142d267C1f36714E4a8F75612F20a79720
2026-05-10 23:59:53,102 INFO  Starting poll from block 42

2026-05-10 23:59:55,210 INFO  ConnectionEstablished event: ccS=0x1376acde649b226345ac9cb3cfadf6714ac106cab3e6dfdc6d69aec93e1c88d1
2026-05-10 23:59:55,830 INFO  Inserted ccS into Merkle tree. tx=0xabcd...ef01
2026-05-10 23:59:55,831 INFO  LeafInserted: leaf=0x1376acde..., index=0, root=0x2a3f...
```

---

## Exporting ABIs after redeployment

If the contracts are redeployed, regenerate the ABI files from the Foundry build artifacts:

```bash
cd src/Sapphire_Mock
forge build

cat out/IncrementalMerkleTree.sol/IncrementalMerkleTree.json | \
  python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" \
  > ../Relayer/abi/IncrementalMerkleTree.json

cat out/ConnectionManager.sol/ConnectionManager.json | \
  python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" \
  > ../Relayer/abi/ConnectionManager.json
```

---

## Known limitations

- **Tree capacity**: `IncrementalMerkleTree` uses `DEPTH = 4`, so it holds at most **16 leaves**. On the 17th `ConnectionEstablished` event the relayer logs a `TreeFull` error and continues polling — it does not crash.
- **No replay protection**: if the relayer restarts mid-block it may skip events that arrived in blocks already processed before the restart. For a production system, persist `last_block` to disk.
