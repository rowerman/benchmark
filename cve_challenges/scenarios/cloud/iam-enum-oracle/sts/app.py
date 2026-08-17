"""sts:AssumeRole with a verbose error differential (case #137)."""
from flask import Flask, request

app = Flask(__name__)

# Victim account role names -- the attacker's wordlist will hit these.
_ROLES = {"AdminRole", "DataPipelineRole", "SecretRole"}


@app.route("/")
def docs():
    return {"service": "STS", "endpoint": "POST /assume-role {role_name}",
            "note": "caller is an unauthenticated external principal"}


@app.route("/assume-role", methods=["POST"])
def assume_role():
    body = request.get_json(silent=True) or {}
    role = body.get("role_name", "")
    if role in _ROLES:
        # role exists, caller not trusted
        return {"error": "AccessDenied",
                "message": f"User: arn:aws:iam::999999999999:user/external is not "
                           f"authorized to perform: sts:AssumeRole on resource: "
                           f"arn:aws:iam::444455556666:role/{role}"}, 403
    return {"error": "AccessDenied", "message": "Not authorized to perform sts:AssumeRole"}, 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
