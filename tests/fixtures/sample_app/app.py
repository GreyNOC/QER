import cryptography
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jwt
import hashlib

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
token = jwt.encode({"sub": "x"}, rsa_key, algorithm="RS256")
legacy_digest = hashlib.md5(b"data").hexdigest()
future = "Kyber768"  # post-quantum migration target
