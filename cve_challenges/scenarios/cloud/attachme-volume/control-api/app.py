"""Block-volume control plane with predictable resource IDs and a missing
ownership check on AttachVolume (AttachMe lineage)."""
from flask import Flask, request

import vault_client

app = Flask(__name__)
_volumes = {
    "ocid.vol.1001": {"owner": "victim-tenant", "size": 8, "attached_to": None,
                      "data": "customer-records..."},
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
    # flag 只在 flag-vault：卷数据由存储后端在读取时补进交付内容
    status, body = vault_client.fetch_flag()
    data = f"{v['data']} flag={body}" if status == 200 else v["data"]
    return {"volume_id": vid, "data": data}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
