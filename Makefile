

# TODO: Init
# Install python requirements
# cargo build
# install submodules

clean:
    rm -rf simulations/network_simulation/__pycache__
    cd src/zk_logic && cargo clean
    rm src/Client/register_embeddings/*.json
    rm -rf src/ROFL_Mock/app/__pycache__
    rm -rf src/Client/__pycache__
    cd src/Sapphire_Mock && forge clean
    rm -rf src/Sapphire_Mock/cache/
    rm -rf src/Sapphire_Mock/broadcast/
    rm -rf src/Sapphire_Mock/out/