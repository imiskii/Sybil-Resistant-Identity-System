#!/bin/bash

# Project's initialization script
# ---------------------------------
cd "$(dirname "$0")"


# Install submodules
# ---------------------------------
echo "Initializing git submodules..."
git submodule update --init --recursive
echo "Git submodules initialized."; echo


# Initialize all python environments
# ---------------------------------
echo "Setting up Python environments..."
PYTHON_ENV_DIRS=(
    "simulations"
    "src/Client"
    "src/ROFL_Mock"
    "src/Relayer"
)

setup_env() {
    local dir="$1"
    echo "Setting up Python environment in $dir"
    
    # Create the .venv if it doesn't exist
    if [ ! -d "$dir/.venv" ]; then
        echo "Creating virtual environment in $dir/.venv"
        python3 -m venv "$dir/.venv"
    else
        echo "Virtual environment already exists in $dir/.venv"
    fi

    # Upgrade pip and install dependencies
    local pip_path="$dir/.venv/bin/pip"
    if [ -f "$pip_path" ]; then
        echo "Upgrading pip in $dir/.venv"
        "$pip_path" install --upgrade pip
        echo "Installing dependencies from $dir/requirements.txt"
        "$pip_path" install -r "$dir/requirements.txt"
    else
        echo "Error: pip not found in $dir/.venv/bin/pip"
    fi

    echo "Finished setting up environment in $dir"
}

if command -v python3 &> /dev/null; then
    for dir in "${PYTHON_ENV_DIRS[@]}"; do
        setup_env "$dir"
    done
    echo "Python environments setup completed."; echo
else
    echo "Error: Python 3 is not installed. Skipping Python environment setup."
    echo "Install Python 3 by following the instructions at https://www.python.org/downloads/."; echo
fi


# Compile zk_logic
# ---------------------------------
echo "Compiling zk_logic..."

if command -v cargo &> /dev/null; then
    (cd src/zk_logic && cargo build --release)
    echo "zk_logic compilation completed."; echo
else
    echo "Error: Cargo is not installed. Skipping compilation of zk_logic."
    echo "Install Rust and Cargo by following the instructions at https://www.rust-lang.org/tools/install."; echo
fi


# Compile smart contracts (src/Sapphire_Mock)
# ---------------------------------
echo "Compiling smart contracts in src/Sapphire_Mock..."

if command -v forge &> /dev/null; then
    (cd src/Sapphire_Mock && forge build)
    echo "Smart contract compilation in src/Sapphire_Mock completed."; echo
else
    echo "Error: Forge is not installed. Skipping compilation of smart contracts in src/Sapphire_Mock."
    echo "Install Foundry by following the instructions at https://book.getfoundry.sh/getting-started/installation."; echo
fi


# Create docker image
# ---------------------------------
echo "Building Docker image for ROFL_Mock..."
if docker build -t rofl_mock-app:latest src/ROFL_Mock; then
    echo "Docker image built successfully."; echo
else
    echo "Error: Failed to build Docker image for ROFL_Mock."
    echo "Create the ROFL Docker image manually by running 'docker build -t rofl_mock-app:latest src/ROFL_Mock'."; echo
fi

