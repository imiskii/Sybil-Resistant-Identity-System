from __future__ import annotations

from pydantic import BaseModel


class RegisterRequest(BaseModel):
    PK: str         # hex uncompressed public key (with or without 0x/04 prefix)
    image: str      # base64-encoded face image
    signature: str  # ECDSA signature of the PK bytes produced by the user's SK


class RegisterResponse(BaseModel):
    ID: str                          # Ethereum address derived from PK
    embedding_hash: str              # Keccak256 of the normalised embedding
    match_result: bool               # True = duplicate detected, registration rejected
    rofl_signature: str              # ROFL TEE signature over {ID, embedding_hash, match_result}
    facial_embedding: list[float]    # Raw embedding — appended after signing, not part of signed payload


class EstablishConnectionRequest(BaseModel):
    PK_A: str                        # hex uncompressed public key of party A
    ID_B: str                        # Ethereum address of party B
    Photo_B: str                     # base64-encoded face image of party B
    received_embedding_B: list[float]  # embedding of B as claimed by A (from B's /register response)
    signature_A: str                 # ECDSA signature of PK_A bytes produced by SK_A


class EstablishConnectionResponse(BaseModel):
    match_result: bool       # True = live photo of B matches the claimed embedding
    CC_AB: str | None        # Connection commitment Keccak256(id_a || id_b); None if match_result is False
    hash_received_B: str     # Keccak256 of the normalised received_embedding_B
    rofl_signature: str      # ROFL TEE signature over {match_result, CC_AB, hash_received_B}
