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


def _save_embedding(identity: str, embedding: list[float]) -> Path:
    EMBEDDINGS_DIR.mkdir(exist_ok=True)
    path = EMBEDDINGS_DIR / f"{identity}.json"
    path.write_text(json.dumps({"ID": identity, "embedding": embedding}, indent=2))
    return path


def run_register(config_file: str) -> None:
    with open(config_file) as f:
        user_config: dict = json.load(f)

    sk: str = user_config["SK"]
    pk: str = user_config["PK"]
    photo_path: str = user_config["photo_path"]

    cfg = load_config()

    with open(photo_path, "rb") as img_f:
        image_b64 = base64.b64encode(img_f.read()).decode()

    signable = encode_defunct(primitive=pk.encode())
    signed = Account.sign_message(signable, private_key=sk)
    signature = "0x" + signed.signature.hex()

    payload = {"PK": pk, "image": image_b64, "signature": signature}

    response = httpx.post(f"{cfg.api_url}/register", json=payload, timeout=60.0)
    response.raise_for_status()
    rofl_response: dict = response.json()

    if rofl_response.get("match_result"):
        print("WARNING: Duplicate identity detected - registration rejected.")
        click.echo(
            "Duplicate face detected - limited registration recorded by ROFL only,"
            " no on-chain transaction sent."
        )
    else:
        saved_path = _save_embedding(rofl_response["ID"], rofl_response["facial_embedding"])
        print(f"Embedding saved to {saved_path}")

        w3 = connect(cfg.rpc_url)
        account = Account.from_key(sk)
        registry = load_contract(w3, cfg.registry_address, cfg.registry_abi_path)

        tx_hash = send_transaction(
            w3,
            registry.functions.registerProfile(
                rofl_response["ID"],
                bytes.fromhex(rofl_response["embedding_hash"].removeprefix("0x")),
                rofl_response["match_result"],
                bytes.fromhex(rofl_response["rofl_signature"].removeprefix("0x")),
            ),
            account,
        )
        click.echo(f"On-chain registration tx: {tx_hash}")

    print(json.dumps({k: v for k, v in rofl_response.items() if k != "facial_embedding"}, indent=2))
