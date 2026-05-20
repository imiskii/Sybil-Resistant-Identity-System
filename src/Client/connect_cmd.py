from __future__ import annotations

import base64
import json
from pathlib import Path

import click
import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

from chain import connect, load_contract, send_transaction
from config import load_config

EMBEDDINGS_DIR = Path(__file__).parent / "registered_embeddings"


def _load_embedding(id_b: str) -> list[float]:
    """Load localy stored embedding."""
    path = EMBEDDINGS_DIR / f"{id_b}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No stored embedding found for ID_B {id_b}. "
            f"Expected file: {path}\n"
        )
    return json.loads(path.read_text())["embedding"]


def run_connect(config_file: str) -> None:
    """Start connection establishment process."""
    with open(config_file) as f:
        user_config: dict = json.load(f)

    sk_a: str = user_config["SK_A"]
    pk_a: str = user_config["PK_A"]
    id_b: str = user_config["ID_B"]
    photo_b_path: str = user_config["photo_B_path"]

    cfg = load_config()
    received_embedding_b = _load_embedding(id_b)

    with open(photo_b_path, "rb") as img_f:
        photo_b64 = base64.b64encode(img_f.read()).decode()

    signable = encode_defunct(primitive=pk_a.encode())
    signed = Account.sign_message(signable, private_key=sk_a)
    signature_a = "0x" + signed.signature.hex()

    payload = {
        "PK_A": pk_a,
        "ID_B": id_b,
        "Photo_B": photo_b64,
        "received_embedding_B": received_embedding_b,
        "signature_A": signature_a,
    }

    response = httpx.post(f"{cfg.api_url}/establish_connection", json=payload, timeout=60.0)
    response.raise_for_status()
    rofl_response: dict = response.json()

    print(json.dumps(rofl_response, indent=2))

    if rofl_response.get("match_result"):
        w3 = connect(cfg.rpc_url)
        account = Account.from_key(sk_a)
        manager = load_contract(w3, cfg.connection_manager_address, cfg.connection_manager_abi_path)

        tx_hash = send_transaction(
            w3,
            manager.functions.establishConnection(
                int(rofl_response["CC_AB"], 16),
                bytes.fromhex(rofl_response["hash_received_B"].removeprefix("0x")),
                rofl_response["match_result"],
                bytes.fromhex(rofl_response["rofl_signature"].removeprefix("0x")),
                id_b,
            ),
            account,
        )
        click.echo(f"On-chain connection tx: {tx_hash}")
    else:
        click.echo(
            "Face mismatch - Photo_B does not match received_embedding_B."
            " No on-chain transaction sent."
        )
