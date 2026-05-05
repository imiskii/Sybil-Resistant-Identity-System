#!/bin/bash

echo "Setting up ZK-logic Environment..."

# 1. Check if rust is installed
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust is not installed."
    exit 1
fi

# 2. Install wasm-pack for browser compilation
echo "Installing wasm-pack..."
cargo install wasm-pack

# 3. Check for Circom and install if missing
if ! command -v circom &> /dev/null; then
    echo "Circom not found. Installing directly via Cargo..."
     
    # Downloads, builds, and installs the binary to the user's ~/.cargo/bin directory
    cargo install --git https://github.com/iden3/circom.git circom
    
    echo "Circom installed successfully!"
else
    echo "Circom is already installed."
fi

echo "Setup complete! You can now build the project."