from __future__ import annotations

import torch
import torch.nn.functional as F
from fastapi import APIRouter, HTTPException, Request

from app.crypto import (
    compute_connection_commitment,
    derive_eth_address,
    normalize_and_hash_embedding,
    sign_payload,
    verify_signature,
)
from app.embedding import extract_embedding
from app.models import EstablishConnectionRequest, EstablishConnectionResponse

router = APIRouter()


@router.post("/establish_connection", response_model=EstablishConnectionResponse)
async def establish_connection(body: EstablishConnectionRequest, req: Request) -> EstablishConnectionResponse:
    settings = req.app.state.settings

    if not verify_signature(body.PK_A, body.PK_A.encode(), body.signature_A):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    id_a = derive_eth_address(body.PK_A)
    hash_received_b = normalize_and_hash_embedding(body.received_embedding_B)

    computed_embedding_b: list[float] = extract_embedding(body.Photo_B, req.app.state.model)

    computed_tensor = torch.tensor(computed_embedding_b).unsqueeze(0)
    received_tensor = torch.tensor(body.received_embedding_B).unsqueeze(0)
    similarity = F.cosine_similarity(computed_tensor, received_tensor).item()
    match_result = bool(similarity > settings.SIMILARITY_THRESHOLD)

    cc_ab: str | None = compute_connection_commitment(id_a, body.ID_B) if match_result else None

    signed_payload = {"match_result": match_result, "CC_AB": cc_ab, "hash_received_B": hash_received_b}
    rofl_signature = sign_payload(signed_payload, settings.SK_ROFL)

    return EstablishConnectionResponse(**signed_payload, rofl_signature=rofl_signature)
