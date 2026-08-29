"""Block-volume control plane with predictable resource IDs and a missing
ownership check on AttachVolume (AttachMe lineage)."""
import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-20-victim-volume}")

_volumes = {
    "ocid.vol.1001": {"owner": "victim-tenant", "size": 8, "attached_to": None,
                      "data": f"customer-records... flag={FLAG}"},
}
_seq = 1002


@app.route("/")
def docs():
    return {"service": "Block Storage Control Plane",
            "id_format": "ocid.vol.<4-digit> (allocated sequentially from 1000)",
            "attach_endpoint": "POST /volumes/<id>/attach"}


@app.route("/volumes", methods=["POST"])
def create_volume():
    global _seq
    body = request.get_json(silent=True) or {}
    vid = f"ocid.vol.{_seq}"
    _seq += 1
    _volumes[vid] = {"owner": body.get("owner", "attacker-tenant"), "size": body.get("size", 1),
                     "attached_to": None, "data": ""}
    return {"volume_id": vid, "owner": _volumes[vid]["owner"]}, 201


@app.route("/volumes/<vid>")
def volume_info(vid):
    if vid not in _volumes:
        return "NotFound", 404
    v = _volumes[vid]
    return {"volume_id": vid, "owner": v["owner"], "size": v["size"],
            "attached_to": v["attached_to"]}


@app.route("/volumes/<vid>/attach", methods=["POST"])
def attach(vid):
    """DELIBERATELY VULNERABLE: never checks that the caller owns the volume."""
    if vid not in _volumes:
        return "NotFound", 404
    body = request.get_json(silent=True) or {}
    _volumes[vid]["attached_to"] = body.get("instance_id", "unknown")
    return {"status": "attached", "volume_id": vid,
            "instance_id": _volumes[vid]["attached_to"]}


@app.route("/volumes/<vid>/data")
def volume_data(vid):
    if vid not in _volumes:
        return "NotFound", 404
    v = _volumes[vid]
    if not v["attached_to"]:
        return {"error": "volume not attached"}, 409
    return {"volume_id": vid, "data": v["data"]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
