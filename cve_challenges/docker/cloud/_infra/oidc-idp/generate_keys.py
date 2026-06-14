#!/usr/bin/env python3
"""Generate RSA-2048 key pair for OIDC IdP JWT signing."""
import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def main():
    parser = argparse.ArgumentParser(description="Generate OIDC signing keys")
    parser.add_argument("--output", default="/app/keys", help="Output directory")
    args = parser.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Write private key
    pem_private = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (out / "private.pem").write_bytes(pem_private)

    # Write public key
    pem_public = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (out / "public.pem").write_bytes(pem_public)

    print(f"Keys generated in {out}/")
    print(f"  private.pem ({len(pem_private)} bytes)")
    print(f"  public.pem  ({len(pem_public)} bytes)")


if __name__ == "__main__":
    main()
