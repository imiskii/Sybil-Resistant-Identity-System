from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

EMBEDDINGS_DIR = Path(__file__).parent / "registered_embeddings"


def _save_embedding(identity: str, embedding: list[float]) -> Path:
    EMBEDDINGS_DIR.mkdir(exist_ok=True)
    path = EMBEDDINGS_DIR / f"{identity}.json"
    path.write_text(json.dumps({"ID": identity, "embedding": embedding}, indent=2))
    return path


def run_register(config_file: str) -> None:
    with open(config_file) as f:
        config: dict = json.load(f)

    api_url: str = config["api_url"]
    sk: str = config["SK"]
    pk: str = config["PK"]
    photo_path: str = config["photo_path"]

    with open(photo_path, "rb") as img_f:
        image_b64 = base64.b64encode(img_f.read()).decode()

    signable = encode_defunct(primitive=pk.encode())
    signed = Account.sign_message(signable, private_key=sk)
    signature = "0x" + signed.signature.hex()

    payload = {"PK": pk, "image": image_b64, "signature": signature}

    response = httpx.post(f"{api_url}/register", json=payload, timeout=60.0)
    response.raise_for_status()
    data: dict = response.json()

    if data.get("match_result"):
        print("WARNING: Duplicate identity detected — registration rejected.")
    else:
        saved_path = _save_embedding(data["ID"], data["facial_embedding"])
        print(f"Embedding saved → {saved_path}")

    print(json.dumps({k: v for k, v in data.items() if k != "facial_embedding"}, indent=2))
