"""Managed-K8s control plane: bootstrap-token CSR signing + node secrets."""
import base64
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, request

app = Flask(__name__)
TOKEN = os.environ.get("BOOTSTRAP_TOKEN", "token-abcdef")
FLAG = os.environ.get("FLAG", "flag{cloud-28-node-secrets}")

_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"control-plane-ca")])
_ca_cert = (
    x509.CertificateBuilder()
    .subject_name(_ca_name).issuer_name(_ca_name)
    .public_key(_ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(_ca_key, hashes.SHA256())
)


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/sign", methods=["POST"])
def sign():
    """Auto-sign CSRs presented with a bootstrap token (AKS behaviour)."""
    body = request.get_json(silent=True) or {}
    if body.get("token") != TOKEN:
        return {"error": "invalid bootstrap token"}, 403
    csr_pem = base64.b64decode(body.get("csr", ""))
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception as e:
        return {"error": f"bad csr: {e}"}, 400
    if not cn.startswith("system:node:"):
        return {"error": "CSR CN must be system:node:*"}, 403
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject).issuer_name(_ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(_ca_key, hashes.SHA256())
    )
    return {"cert": base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode(),
            "cn": cn}


@app.route("/node-secrets")
def node_secrets():
    """Node Authorizer: system:node identity may read secrets on its node."""
    raw = request.headers.get("X-Node-Cert", "")
    try:
        cert = x509.load_pem_x509_certificate(base64.b64decode(raw))
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return {"error": "not authenticated as a node"}, 403
    if not cn.startswith("system:node:"):
        return {"error": "not authenticated as a node"}, 403
    return {"node": "k8s-agentpool-00000000-0", "secrets": [{"name": "flag", "data": FLAG}]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
