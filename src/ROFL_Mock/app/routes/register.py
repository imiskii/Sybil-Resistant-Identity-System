from __future__ import annotations

import torch
import torch.nn.functional as F
from fastapi import APIRouter, HTTPException, Request

from app.crypto import (
    compute_db_key,
    derive_eth_address,
    encrypt_embedding,
    decrypt_embedding,
    normalize_and_hash_embedding,
    sign_payload,
    verify_signature,
)
from app.database import fetch_all_embeddings, insert_embedding
from app.embedding import extract_embedding
from app.models import RegisterRequest, RegisterResponse

router = APIRouter()


@router.post("/register", response_model=RegisterResponse)
async def register(body: RegisterRequest, req: Request) -> RegisterResponse:
    settings = req.app.state.settings

    if not verify_signature(body.PK, body.PK.encode(), body.signature):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    embedding: list[float] = extract_embedding(body.image, req.app.state.model)

    all_rows: list[tuple[str, bytes]] = await fetch_all_embeddings(req.app.state.pool)

    match_result = False
    if all_rows:
        new_tensor = torch.tensor(embedding).unsqueeze(0)  # (1, 512)
        stored_tensors = torch.tensor(
            [decrypt_embedding(payload, settings.SYM_KEY) for _, payload in all_rows]
        )  # (N, 512)
        similarities = F.cosine_similarity(new_tensor, stored_tensors)
        match_result = bool(similarities.max().item() > settings.SIMILARITY_THRESHOLD)

    identity = derive_eth_address(body.PK)
    embedding_hash = normalize_and_hash_embedding(embedding)

    if not match_result:
        db_key = compute_db_key(identity, settings.SK_ROFL)
        encrypted = encrypt_embedding(embedding, settings.SYM_KEY)
        await insert_embedding(req.app.state.pool, db_key, encrypted)

    signed_payload = {"ID": identity, "embedding_hash": embedding_hash, "match_result": match_result}
    rofl_signature = sign_payload(signed_payload, settings.SK_ROFL)

    return RegisterResponse(
        **signed_payload,
        rofl_signature=rofl_signature,
        facial_embedding=embedding,
    )
