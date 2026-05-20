# Makefile for Sybil-Resistant Identity System
# Authot: Michal Ľaš (xlasmi00)
# Date: 2026-05-11

SIMULATION_NETWORK_DIR=simulations/network_simulation

.PHONY: init clean export_abi run_example_simulations run_attack_simulations run_big_simulation open_simulation_results deploy_smart_contracts rofl_compose_up rofl_compose_down run_relayer test_zk test_smart_contracts run_zk_linear_three_hop run_zk_linear_large_tries run_zk_cyclic_large_tries run_zk_cyclic_three_hop run_zk_aggregator_three run_zk_aggregator_six


all: init export_abi

# Set up & Clean up
# ------------------------------------------------------------------

init:
	bash ./init.sh


clean:
	bash ./clean.sh

clean_simulation_outputs:
	rm -rf simulations_output/


export_abi:
	cd src/Client && mkdir -p abi
	cd src/Relayer && mkdir -p abi
	cd src/Sapphire_Mock && forge build && cat out/IdentityRegistry.sol/IdentityRegistry.json | python3 -c   "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Client/abi/IdentityRegistry.json && cat out/ConnectionManager.sol/ConnectionManager.json | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Client/abi/ConnectionManager.json && cat out/IncrementalMerkleTree.sol/IncrementalMerkleTree.json | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Relayer/abi/IncrementalMerkleTree.json && cat out/ConnectionManager.sol/ConnectionManager.json | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Relayer/abi/ConnectionManager.json


# Network Simulation
# ------------------------------------------------------------------

run_example_simulations:
	simulations/.venv/bin/python3 $(SIMULATION_NETWORK_DIR)/runner.py --config $(SIMULATION_NETWORK_DIR)/configurations/example_config.json


run_attack_simulations:
	simulations/.venv/bin/python3 $(SIMULATION_NETWORK_DIR)/runner.py --config $(SIMULATION_NETWORK_DIR)/configurations/attacks_config.json


run_big_simulation:
	simulations/.venv/bin/python3 $(SIMULATION_NETWORK_DIR)/runner.py --config $(SIMULATION_NETWORK_DIR)/configurations/big_graph_config.json


open_simulation_results:
	firefox simulations_output/


# Run commands
# ------------------------------------------------------------------

deploy_smart_contracts:
	cd src/Sapphire_Mock && ROFL_MOCK_ADDRESS=0x06F7FCD662714B099A6B1C14958FD6D826745616 forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast


rofl_compose_up:
	sudo docker compose -f ./src/ROFL_Mock/docker-compose.yml up -d


rofl_compose_down:
	sudo docker compose -f ./src/ROFL_Mock/docker-compose.yml down


run_relayer:
	src/Relayer/.venv/bin/python3 src/Relayer/relayer.py


run_zk_linear_three_hop:
	cd src/zk_logic && cargo run -p prover_linear --example three_hop_linear --release

run_zk_linear_large_tries:
	cd src/zk_logic && cargo run -p prover_linear --example large_tries_linear --release

run_zk_cyclic_large_tries:
	cd src/zk_logic && cargo run -p prover_cyclic --example large_tries_cyclic --release

run_zk_cyclic_three_hop:
	cd src/zk_logic && cargo run -p prover_cyclic --example three_hop_cyclic --release

run_zk_aggregator_three:
	cd src/zk_logic && cargo run -p aggregator --example aggregate_three --release

run_zk_aggregator_six:
	cd src/zk_logic && cargo run -p aggregator --example aggregate_six --release


# Tests
# ------------------------------------------------------------------

test_zk:
	cd src/zk_logic && cargo test --release


test_smart_contracts:
	cd src/Sapphire_Mock && forge test


test_smart_contracts_gas_report:
	cd src/Sapphire_Mock && forge test --gas-report