from __future__ import annotations

import json
from pathlib import Path

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.contract import Contract


def connect(rpc_url: str) -> Web3:
    """Return a connected Web3 instance. Raise RuntimeError if not connected."""
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect to RPC endpoint: {rpc_url}")
    return w3


def load_contract(w3: Web3, address: str, abi_path: Path) -> Contract:
    """Load a contract instance from a checksummed address and ABI file."""
    abi = json.loads(abi_path.read_text())
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)


def send_transaction(
    w3: Web3,
    contract_fn,
    account: LocalAccount,
    gas: int = 300_000,
) -> str:
    """Build, sign, send, and wait for a transaction.

    Returns the transaction hash as a 0x hex string.
    Raises RuntimeError on revert, including the revert reason if available.
    """
    # Estimate gas with a 20 % safety buffer; fall back to the explicit limit
    # if estimation fails (e.g. the call would itself revert).
    try:
        estimated = contract_fn.estimate_gas({"from": account.address})
        gas = int(estimated * 1.2)
    except Exception:
        pass

    tx = contract_fn.build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": gas,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = Account.sign_transaction(tx, account.key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

    tx_hash_hex = "0x" + tx_hash.hex()
    if receipt.status == 0:
        # Replay without a gas cap so the node uses the block gas limit,
        # which lets it reach the revert opcode and return the reason string.
        revert_reason = "unknown revert reason"
        try:
            w3.eth.call(
                {
                    "from": account.address,
                    "to": receipt["to"],
                    "data": tx["data"],
                },
                receipt.blockNumber,
            )
        except Exception as exc:
            revert_reason = str(exc)
        raise RuntimeError(f"Transaction reverted ({tx_hash_hex}): {revert_reason}")

    print(f"Transaction confirmed: {tx_hash_hex} (block {receipt.blockNumber})")
    return tx_hash_hex
