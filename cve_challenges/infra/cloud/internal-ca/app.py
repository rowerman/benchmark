"""Internal certificate authority with a configurable CN validation rule.

Used to model certificate-issuance flaws such as ExtraReplica's mis-anchored
CN regex: the CA validates the CN with a regex whose tail is not anchored, so
an attacker-controlled suffix passes the check.
"""
import base64
import datetime
import os
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, request

app = Flask(__name__)

CN_REGEX = os.environ.get("CN_REGEX", "^.*$")
_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Provider Internal CA")])
_ca_cert = (
    x509.CertificateBuilder()
    .subject_name(_ca_name)
    .issuer_name(_ca_name)
    .public_key(_ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(_ca_key, hashes.SHA256())
)


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/ca")
def ca():
    return {
        "ca": base64.b64encode(_ca_cert.public_bytes(serialization.Encoding.PEM)).decode(),
        "cn_rule": CN_REGEX,
    }


@app.route("/sign", methods=["POST"])
def sign():
    body = request.get_json(silent=True) or {}
    cn = body.get("cn", "")
    if not cn:
        return {"error": "missing cn"}, 400
    if not re.match(CN_REGEX, cn):
        return {"error": f"CN '{cn}' rejected by rule {CN_REGEX}"}, 403
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(_ca_key, hashes.SHA256())
    )
    return {
        "cert": base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode(),
        "key": base64.b64encode(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ).decode(),
        "cn": cn,
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
