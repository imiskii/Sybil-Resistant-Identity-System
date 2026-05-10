

# TODO: Init
# Install python requirements
# cargo build
# install submodules


export_abi:
	cd src/Client && mkdir -p abi
	cd src/Sapphire_Mock && forge build && cat out/IdentityRegistry.sol/IdentityRegistry.json | python3 -c   "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Client/abi/IdentityRegistry.json && cat out/ConnectionManager.sol/ConnectionManager.json | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Client/abi/ConnectionManager.json && cat out/IncrementalMerkleTree.sol/IncrementalMerkleTree.json | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Relayer/abi/IncrementalMerkleTree.json && cat out/ConnectionManager.sol/ConnectionManager.json | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['abi'], indent=2))" > ../Relayer/abi/ConnectionManager.json


clean:
	rm -rf simulations/network_simulation/__pycache__
	cd src/zk_logic && cargo clean
	rm src/Client/register_embeddings/*.json
	rm -rf src/ROFL_Mock/app/__pycache__
	rm -rf src/Client/__pycache__
	rm -rf src/Client/abi/
	rm -rf src/Relayer/__pycache__
	rm -rf src/Relayer/abi/
	cd src/Sapphire_Mock && forge clean
	rm -rf src/Sapphire_Mock/cache/
	rm -rf src/Sapphire_Mock/broadcast/
	rm -rf src/Sapphire_Mock/out/