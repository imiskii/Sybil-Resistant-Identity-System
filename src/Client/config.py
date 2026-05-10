from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# config.json lives in the same directory as this file (Client/)
CONFIG_FILE = Path(__file__).parent / "config.json"


@dataclass(frozen=True)
class ClientConfig:
    api_url: str
    rpc_url: str
    registry_address: str
    registry_abi_path: Path
    connection_manager_address: str
    connection_manager_abi_path: Path


def load_config() -> ClientConfig:
    """Load shared infrastructure config from Client/config.json.

    Raises FileNotFoundError with a helpful message if config.json is available.
    """
    base = CONFIG_FILE.parent

    if CONFIG_FILE.exists():
        raw: dict = json.loads(CONFIG_FILE.read_text())
        return ClientConfig(
            api_url=raw["api_url"],
            rpc_url=raw["rpc_url"],
            registry_address=raw["registry_address"],
            registry_abi_path=base / raw["registry_abi_path"],
            connection_manager_address=raw["connection_manager_address"],
            connection_manager_abi_path=base / raw["connection_manager_abi_path"],
        )

    raise FileNotFoundError(
        f"Client config not found at {CONFIG_FILE}.\n"
        "Copy Client/config.json.example to Client/config.json and fill in the deployed "
        "contract addresses and RPC URL.\n"
        "See the 'Shared Infrastructure Config' section in Client/README.md for instructions."
    )
