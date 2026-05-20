from __future__ import annotations

import json
import os
import struct
from typing import Union

import torch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address


def _strip_hex_prefix(hex_str: str) -> str:
    return hex_str[2:] if hex_str.startswith(("0x", "0X")) else hex_str


def derive_eth_address(pk_hex: str) -> str:
    """Derive a Ethereum address from an uncompressed ECDSA public key."""
    raw = _strip_hex_prefix(pk_hex)
    if len(raw) == 130 and raw.startswith("04"):
        raw = raw[2:]
    key_bytes = bytes.fromhex(raw)
    key_hash = keccak(key_bytes)
    return to_checksum_address("0x" + key_hash[-20:].hex())


def verify_signature(pk_hex: str, message: bytes, signature_hex: str) -> bool:
    """Return True if signature_hex is a valid Ethereum ECDSA signature of message by pk_hex."""
    signable = encode_defunct(primitive=message)
    recovered: str = Account.recover_message(signable, signature=signature_hex)
    expected: str = derive_eth_address(pk_hex)
    return recovered.lower() == expected.lower()


def normalize_and_hash_embedding(embedding: Union[list[float], torch.Tensor]) -> str:
    """Scale each element by 1 000 000, pack as little-endian int64s, return Keccak256."""
    values: list[float] = embedding.tolist() if isinstance(embedding, torch.Tensor) else list(embedding)
    scaled = [round(v * 1_000_000) for v in values]
    packed = struct.pack(f"<{len(scaled)}q", *scaled)
    return "0x" + keccak(packed).hex()


def sign_payload(payload: dict, sk_hex: str) -> str:
    """Sign a canonical JSON serialisation of payload with an ECDSA private key."""
    canonical: bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    msg_hash: bytes = keccak(canonical)
    signable = encode_defunct(primitive=msg_hash)
    signed = Account.sign_message(signable, private_key=_strip_hex_prefix(sk_hex))
    return "0x" + signed.signature.hex()


def encrypt_embedding(embedding: list[float], sym_key_hex: str) -> bytes:
    """Encrypt an embedding list with AES-256-GCM using a random 12-byte nonce."""
    key = bytes.fromhex(_strip_hex_prefix(sym_key_hex))
    nonce = os.urandom(12)
    plaintext = json.dumps(embedding).encode()
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return nonce + tag + ciphertext


def decrypt_embedding(blob: bytes, sym_key_hex: str) -> list[float]:
    """Decrypt an AES-256-GCM blob produced by encrypt_embedding."""
    key = bytes.fromhex(_strip_hex_prefix(sym_key_hex))
    nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


def compute_db_key(eth_address: str, sk_rofl_hex: str) -> str:
    """K_DB = Keccak256(address_bytes || sk_rofl_bytes)."""
    addr_bytes = bytes.fromhex(_strip_hex_prefix(eth_address))
    sk_bytes = bytes.fromhex(_strip_hex_prefix(sk_rofl_hex))
    return "0x" + keccak(addr_bytes + sk_bytes).hex()


def compute_connection_commitment(id_a: str, id_b: str) -> str:
    """CC_AB = Keccak256(min(id_a, id_b) || max(id_a, id_b)) in sorted canonical order."""
    a = _strip_hex_prefix(id_a).lower()
    b = _strip_hex_prefix(id_b).lower()
    lo, hi = (a, b) if a <= b else (b, a)
    return "0x" + keccak(bytes.fromhex(lo) + bytes.fromhex(hi)).hex()