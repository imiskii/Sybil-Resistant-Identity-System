from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

EMBEDDINGS_DIR = Path(__file__).parent / "registered_embeddings"


def _load_embedding(id_b: str) -> list[float]:
    path = EMBEDDINGS_DIR / f"{id_b}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No stored embedding found for ID_B {id_b}. "
            f"Expected file: {path}\n"
        )
    return json.loads(path.read_text())["embedding"]


def run_connect(config_file: str) -> None:
    with open(config_file) as f:
        config: dict = json.load(f)

    api_url: str = config["api_url"]
    sk_a: str = config["SK_A"]
    pk_a: str = config["PK_A"]
    id_b: str = config["ID_B"]
    photo_b_path: str = config["photo_B_path"]

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

    response = httpx.post(f"{api_url}/establish_connection", json=payload, timeout=60.0)
    response.raise_for_status()
    data: dict = response.json()

    print(json.dumps(data, indent=2))
