# ROFL Mock TEE

A containerised mock of an Oasis ROFL Trusted Execution Environment for the Sybil-Resistant Identity PoC. Exposes a FastAPI HTTP server that performs facial deduplication and connection commitment generation.

---

## Key generation

Generate a fresh ECDSA key pair and a 32-byte AES symmetric key for local development:

```python
python3 -c "
from eth_account import Account
from eth_keys import keys
import secrets, json

sk = Account.create()
pk_bytes = keys.PrivateKey(bytes.fromhex(sk.key.hex()[2:])).public_key.to_bytes()
sym_key = secrets.token_hex(32)

print(json.dumps({
    'SK_ROFL': sk.key.hex(),
    'PK_ROFL': '04' + pk_bytes.hex(),
    'SYM_KEY': sym_key,
}, indent=2))
"
```

Copy the printed values into a `.env` file next to `docker-compose.yml`:

```env
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_DB=rofldb
POSTGRES_USER=rofl
POSTGRES_PASSWORD=roflpass

SK_ROFL=0x72ad0c21afd2c74612ea9df2f0b12b8964b0988484aaff73c9fba8e8ec12c163
PK_ROFL=0x04be09c3f7d81114651b1474ed0de4fbcb720765d4c94842a15ebc1187d4ad3dc956c189ef55f89e209799e041223d956f9486460de3c809f35f95ff2c73c9b3bc
ADDRESS_ROFL=0x06f7fcd662714b099a6b1c14958fd6d826745616
SYM_KEY=3c1d02eeb369aa3b5310d7602fd5282b80f2ca358b605afc6f91dd9baa8ef70e
DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
SIMILARITY_THRESHOLD=0.85
```

---

## Running the server

```bash
docker compose up --build
```

The API is available at `http://localhost:8000`. The database is ephemeral — all data is lost when the containers stop.

---

## Endpoints

### `POST /register`

**Trust model:** The client proves ownership of an ECDSA key pair by signing their public key. The TEE extracts a facial embedding from the submitted photo inside the enclave, compares it against all previously stored embeddings, and rejects duplicates. The response is signed by the ROFL key so downstream verifiers can confirm the attestation came from the TEE without trusting the transport layer.

**Request:**
```json
{
  "PK": "0x04<uncompressed public key hex>",
  "image": "<base64-encoded face photo>",
  "signature": "<ECDSA signature of PK bytes by SK>"
}
```

**Response:**
```json
{
  "ID": "0x<checksummed Ethereum address>",
  "embedding_hash": "0x<keccak256 of normalised embedding>",
  "match_result": false,
  "rofl_signature": "0x<TEE signature over {ID, embedding_hash, match_result}>",
  "facial_embedding": [0.123, -0.456, "..."]
}
```

`match_result: true` means a duplicate was detected and the identity was **not** stored.

---

### `POST /establish_connection`

**Trust model:** Party A proves key ownership and submits party B's photo alongside the embedding it received from B's prior `/register` response. The TEE re-extracts an embedding from the live photo and checks whether it matches the claimed embedding. If so, a deterministic connection commitment `CC_AB = Keccak256(min(id_a, id_b) || max(id_a, id_b))` is produced. Both parties can independently verify the commitment is canonical (order-independent) and signed by the TEE.

**Request:**
```json
{
  "PK_A": "0x04<A's uncompressed public key>",
  "ID_B": "0x<B's Ethereum address>",
  "Photo_B": "<base64-encoded live photo of B>",
  "received_embedding_B": [0.123, -0.456, "..."],
  "signature_A": "<ECDSA signature of PK_A bytes by SK_A>"
}
```

**Response:**
```json
{
  "match_result": true,
  "CC_AB": "0x<connection commitment>",
  "hash_received_B": "0x<keccak256 of normalised received_embedding_B>",
  "rofl_signature": "0x<TEE signature over {match_result, CC_AB, hash_received_B}>"
}
```

`match_result: false` means the live photo did not match the claimed embedding; `CC_AB` will be `null`.
