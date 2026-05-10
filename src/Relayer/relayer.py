from __future__ import annotations

import json
import time
import logging
from pathlib import Path
from typing import Any

from web3 import Web3
from web3.types import EventData
from eth_account import Account
from eth_account.signers.local import LocalAccount

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

CONFIG_FILE = Path(__file__).parent / "config.json"


def load_config() -> dict[str, Any]:
    return json.loads(CONFIG_FILE.read_text())


def connect(rpc_url: str) -> Web3:
    """Connect to Anvil. Raise RuntimeError if not reachable."""
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect to RPC at {rpc_url}")
    return w3


def load_contract(w3: Web3, address: str, abi_path: Path) -> Any:
    """Load a contract instance. Checksums the address."""
    checksum_addr = Web3.to_checksum_address(address)
    abi = json.loads(abi_path.read_text())
    return w3.eth.contract(address=checksum_addr, abi=abi)


def send_insert(
    w3: Web3,
    merkle_tree: Any,
    account: LocalAccount,
    cc_s: int,
) -> str:
    """
    Call merkleTree.insert(ccS).
    Returns tx hash. Raises RuntimeError with revert reason on failure.
    """
    tx = merkle_tree.functions.insert(cc_s).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 1_200_000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = Account.sign_transaction(tx, account.key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt.status == 0:
        try:
            w3.eth.call(tx, receipt.blockNumber)
        except Exception as e:
            raise RuntimeError(f"insert() reverted: {e}") from e
        raise RuntimeError("insert() reverted: unknown reason")
    return "0x" + tx_hash.hex()


def handle_connection_established(
    w3: Web3,
    merkle_tree: Any,
    account: LocalAccount,
    event: EventData,
) -> None:
    """
    Called for each ConnectionEstablished event.
    Extracts ccS, calls send_insert, logs result.
    """
    cc_s: int = event["args"]["ccS"]
    log.info(f"ConnectionEstablished event: ccS={hex(cc_s)}")
    try:
        tx_hash = send_insert(w3, merkle_tree, account, cc_s)
        log.info(f"Inserted ccS into Merkle tree. tx={tx_hash}")
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        watch_leaf_inserted(merkle_tree, receipt["blockNumber"])
    except RuntimeError as exc:
        log.error(str(exc))


def watch_leaf_inserted(merkle_tree: Any, from_block: int) -> None:
    """
    Poll for LeafInserted events since from_block.
    Log each: leaf, leafIndex, root.
    """
    events = merkle_tree.events.LeafInserted.get_logs(
        from_block=from_block,
        to_block=from_block,
    )
    for evt in events:
        leaf: int = evt["args"]["leaf"]
        leaf_index: int = evt["args"]["leafIndex"]
        root: int = evt["args"]["root"]
        log.info(f"LeafInserted: leaf={hex(leaf)}, index={leaf_index}, root={hex(root)}")


def main() -> None:
    """
    1. Load config.
    2. Connect to Anvil.
    3. Load ConnectionManager and IncrementalMerkleTree contracts.
    4. Load relayer account from private key.
    5. Enter poll loop:
       a. Fetch new ConnectionEstablished events since last processed block.
       b. For each event: call handle_connection_established.
       c. After each insert tx confirms: call watch_leaf_inserted to log the result.
       d. Sleep poll_interval_seconds.
    """
    config = load_config()

    w3 = connect(config["rpc_url"])
    log.info(f"Connected to {config['rpc_url']} (chain id {w3.eth.chain_id})")

    base_dir = Path(__file__).parent
    connection_manager = load_contract(
        w3,
        config["connection_manager_address"],
        base_dir / config["connection_manager_abi_path"],
    )
    merkle_tree = load_contract(
        w3,
        config["merkle_tree_address"],
        base_dir / config["merkle_tree_abi_path"],
    )

    account: LocalAccount = Account.from_key(config["relayer_private_key"])
    log.info(f"Relayer address: {account.address}")

    last_block: int = w3.eth.block_number
    log.info(f"Starting poll from block {last_block}")

    while True:
        current_block: int = w3.eth.block_number
        if current_block > last_block:
            events = connection_manager.events.ConnectionEstablished.get_logs(
                from_block=last_block + 1,
                to_block=current_block,
            )
            for event in events:
                handle_connection_established(w3, merkle_tree, account, event)
            last_block = current_block
        time.sleep(config["poll_interval_seconds"])


if __name__ == "__main__":
    main()
