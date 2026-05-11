# Sybil-Resistant-Identity-System
Implementation of my thesis Sybil-Resistant Identity Systems in Decentralized Environments at FIT, Brno University of Technology.


## Dependencies

+ Python 3.12+
+ Rust (nightly)
+ Docker & Docker Compose
+ Foundry (Forge & Anvil)


## Set Up

### 1. Set up `.env`

Add `.env` to `src/ROFL_Mock`, see example in the `src/ROFL_Mock/README.md`

### 2. Run `init.sh` / `make`

```
make
```


## Execution Tutorial

1. Run Anvil.
2. Deploy Smart Contract with `make deploy_smart_contracts`.
3. Start up the Rofl Mock with `make rofl_compose_up`.
4. Run Relayer with `make run_relayer`.
5. User Client to execute register and create connections between users. There are already prepared `register_*.json` and `connect_*.json` configurations in `src/Client/register_configs/` and `src/Client/connect_configs/`. Possible execution:

```bash
cd src/Client/

# Register entities A and B (see logs in the terminal)
.venv/bin/python3 -m cli register register_configs/register_A.json
.venv/bin/python3 -m cli register register_configs/register_B.json

# Connect entities A and B (see logs in the terminal)
.venv/bin/python3 -m cli connect connect_configs/connect_AB.json
.venv/bin/python3 -m cli connect connect_configs/connect_BA.json

# See Relayer logs in terminal.
# See Anvil logs in terminal.
# After entities are connected Relayer execute transaction and adds connection commitment to the deployed Merkle Tree.
```

6. Clean up.
  - Stop the Relayer.
  - Stop the ROFL with `make rofl_compose_down`.
  - Stop the Anvil.
