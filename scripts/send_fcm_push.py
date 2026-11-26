#!/usr/bin/env python3
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def get_oauth2_token(sa: dict) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": sa.get("token_uri", "https://oauth2.googleapis.com/token"),
        "iat": now,
        "exp": now + 3600,
    }
    signing_input = f"{b64u(json.dumps(header, separators=(',', ':')).encode())}.{b64u(json.dumps(claims, separators=(',', ':')).encode())}"

    with tempfile.NamedTemporaryFile("w", delete=False) as kf:
        kf.write(sa["private_key"])
        key_path = kf.name
    try:
        os.chmod(key_path, 0o600)
        sig = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input.encode("ascii"),
        )
    finally:
        try:
            os.remove(key_path)
        except OSError:
            pass

    assertion = f"{signing_input}.{b64u(sig)}"
    form = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
    ).encode("ascii")

    req = urllib.request.Request(
        sa.get("token_uri", "https://oauth2.googleapis.com/token"),
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        tok_data = json.loads(resp.read().decode("utf-8"))
    return tok_data["access_token"]


def main() -> int:
    sa_raw = os.environ.get("FCM_SERVICE_ACCOUNT_JSON", "").strip()
    if not sa_raw:
        print("[ERROR] Secret FCM_SERVICE_ACCOUNT_JSON is missing!")
        return 1

    sa = json.loads(sa_raw)
    project_id = sa["project_id"]
    commit_sha = os.environ.get("GITHUB_SHA", "").strip().lower()

    seq = "0"
    if os.path.isfile("update.json"):
        try:
            man = json.load(open("update.json", encoding="utf-8"))
            seq = str(man.get("seq", 0))
        except Exception:
            pass

    access_token = get_oauth2_token(sa)
    payload = {
        "message": {
            "topic": "mw_all",
            "android": {
                "priority": "HIGH",
                "ttl": "86400s",
            },
            "data": {
                "mw_wake": "1",
                "mw_sha": commit_sha,
                "mw_seq": seq,
                "mw_ts": str(int(time.time())),
            },
        }
    }

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; charset=UTF-8",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read().decode("utf-8", errors="ignore")
            print(f"[OK] High-Priority FCM sent to /topics/mw_all (seq={seq}, sha={commit_sha[:8]}): {body}")
            return 0
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        print(f"[ERROR] FCM HTTP {e.code}: {err_body}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
