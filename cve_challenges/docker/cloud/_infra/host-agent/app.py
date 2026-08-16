"""WireServer host-agent channel simulator.

Models the Azure host-agent endpoint at 168.63.129.16:
  - GET /machine/?comp=goalstate          -- no auth, returns goal state + URLs
  - GET /certs                            -- encrypts the secret bundle to the
    transport public key supplied in the x-ms-guest-agent-public-x509-cert
    header WITHOUT validating who supplied it (CVE-class flaw).
  - GET /vmSettings                       -- extension config whose
    protectedSettings are encrypted to the TenantEncryptionCert.
"""
import base64
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from flask import Flask, request

app = Flask(__name__)

# Per-instance state generated at startup.
_tenant_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_tenant_cert_pem = None  # filled below

_BOOTSTRAP = os.environ.get(
    "BOOTSTRAP_SCRIPT",
    "TLS_BOOTSTRAP_TOKEN=<token>\nKUBELET_CLIENT_CERT_CONTENT=<kubelet-cert>\n"
    "KUBELET_CA_CRT=<ca-cert>",
)
_FLAG = os.environ.get("FLAG", "flag{host-agent-default}")


def _init_cert():
    global _tenant_cert_pem
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"TenantEncryptionCert")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_tenant_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(_tenant_key, hashes.SHA256())
    )
    _tenant_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()


def _tenant_key_pem():
    return _tenant_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _rsa_wrap(pub, plaintext):
    """Hybrid envelope: AES-GCM ciphertext + RSA-OAEP-wrapped session key."""
    session_key = os.urandom(32)
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(session_key), modes.GCM(iv)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    wrapped = pub.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(enc.tag).decode(),
        "wrapped_key": base64.b64encode(wrapped).decode(),
    }


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/machine/")
def goalstate():
    """No authentication -- source IP is the only 'credential'."""
    if request.args.get("comp") != "goalstate":
        return {"error": "unknown component"}, 400
    return {
        "container": {"containerId": "cf5608e6-3a2f-4a0a-9f0a-000000000000"},
        "server": {"osType": "Linux", "vmName": "k8s-agentpool-00000000-0"},
        "Certificates": "http://168.63.129.16:5000/certs",
        "ExtensionsConfig": "http://168.63.129.16:5000/vmSettings",
    }


@app.route("/certs")
def certs():
    """Return the secret bundle encrypted to the caller-supplied public key.

    The supplied transport certificate is trusted without validation --
    exactly the WireServer flaw (case #184 / #255).
    """
    pem = request.headers.get("x-ms-guest-agent-public-x509-cert", "")
    if not pem:
        return {"error": "missing x-ms-guest-agent-public-x509-cert header"}, 400
    try:
        if not pem.startswith("-----BEGIN"):
            pem = base64.b64decode(pem).decode()
        cert = load_pem_x509_certificate(pem.encode())
        pub = cert.public_key()
    except Exception:
        return {"error": "invalid certificate"}, 400
    bundle = json.dumps({
        "tenantEncryptionCertPem": _tenant_key_pem(),
        "thumbprint": "TENCERT-ABCDEF123456",
    })
    envelope = _rsa_wrap(pub, bundle.encode())
    envelope["thumbprint"] = "TENCERT-ABCDEF123456"
    return envelope


@app.route("/vmSettings")
def vm_settings():
    """Extension protectedSettings encrypted to the TenantEncryptionCert."""
    plaintext = f"{_BOOTSTRAP}\nFLAG={_FLAG}\n".encode()
    envelope = _rsa_wrap(_tenant_key.public_key(), plaintext)
    return {
        "extensions": [
            {
                "name": "cse",
                "protectedSettings": envelope,
                "protectedSettingsCertThumbprint": "TENCERT-ABCDEF123456",
            }
        ]
    }


if __name__ == "__main__":
    _init_cert()
    app.run(host="0.0.0.0", port=5000)
