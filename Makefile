


clean:
    rm -rf simulations/network_simulation/__pycache__
    cd src/zk_logic && cargo clean
    rm src/Client/register_embeddings/*.json
    rm -rf src/ROFL_Mock/app/__pycache__
    rm -rf src/Client/__pycache__