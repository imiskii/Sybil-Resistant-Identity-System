#!/bin/bash

# Project's initialization script
# ---------------------------------
cd "$(dirname "$0")"

# Delete generated files
# ---------------------------------
echo "Deleting generated files..."
rm -rf simulations/network_simulation/lib/
rm -rf simulations/network_simulation/__pycache__
rm -rf src/Client/__pycache__
rm -rf src/ROFL_Mock/app/__pycache__
rm -rf src/Relayer/__pycache__
rm -rf src/Client/abi/
rm -rf src/Client/registered_embeddings/
rm -rf src/Relayer/abi/
echo "Deleting generated files completed."; echo

# Delete all python environments
# ---------------------------------
echo "Deleting Python environments..."
PYTHON_ENV_DIRS=(
    "simulations"
    "src/Client"
    "src/ROFL_Mock"
    "src/Relayer"
)

delete_env() {
    local dir="$1"
    echo "Deleting Python environment in $dir"
    rm -rf "$dir/.venv"
    echo "Deleted virtual environment in $dir/.venv"
}

for dir in "${PYTHON_ENV_DIRS[@]}"; do
    delete_env "$dir"
done
echo "Deleting Python environments completed."; echo


# Clean zk_logic
# ---------------------------------
echo "Cleaning zk_logic..."

if command -v cargo &> /dev/null; then
    (cd src/zk_logic && cargo clean)
    rm src/zk_logic/Cargo.lock
    echo "Cleaning of zk_logic completed."; echo
else
    echo "Error: Cargo is not installed. Skipping cleaning of zk_logic."
    echo "Install Rust and Cargo by following the instructions at https://www.rust-lang.org/tools/install."; echo
fi


# Clean smart contracts (src/Sapphire_Mock)
# ---------------------------------
echo "Cleaning smart contracts in src/Sapphire_Mock..."

if command -v forge &> /dev/null; then
    (cd src/Sapphire_Mock && forge clean)
    rm -rf src/Sapphire_Mock/cache/
    rm -rf src/Sapphire_Mock/broadcast/
    rm -rf src/Sapphire_Mock/out/
    echo "Clening of smart contracts in src/Sapphire_Mock completed."; echo
else
    echo "Error: Forge is not installed. Skipping cleaning of smart contracts in src/Sapphire_Mock."
    echo "Install Foundry by following the instructions at https://book.getfoundry.sh/getting-started/installation."; echo
fi


# Removing docker image
# ---------------------------------
echo "Removing Docker images for ROFL_Mock and postgres:15-alpine..."
sudo docker rmi rofl_mock-app:latest
sudo docker rmi postgres:15-alpine
echo "Removing Docker images completed."; echo

