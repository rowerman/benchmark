#!/usr/bin/env python3
"""Generate RSA key pair for SAML signing."""
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="/app/keys")
    args = parser.parse_args()
    out = Path(args.output); out.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    (out / "private.pem").write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    (out / "public.pem").write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Keys: {out}/private.pem, {out}/public.pem")

if __name__ == "__main__": main()
