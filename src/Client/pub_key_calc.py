# Simple calculator for public key from the private key for ECDSA secp256k1

from eth_keys import keys
from eth_utils import decode_hex

# Private key
private_key_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Decode hex and derive the public key
priv_key_bytes = decode_hex(private_key_hex)
priv_key = keys.PrivateKey(priv_key_bytes)
pub_key = priv_key.public_key

print("Raw/Uncompressed Public Key (no prefix):", pub_key)
print("Standard Uncompressed Public Key (0x04 prefix):", "0x04" + str(pub_key)[2:])
print("Compressed Public Key (0x02/0x03 prefix):", "0x" + pub_key.to_compressed_bytes().hex())