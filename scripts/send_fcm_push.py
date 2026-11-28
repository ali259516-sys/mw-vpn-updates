#!/usr/bin/env python3
import base64
import gzip
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


def http_post_retry(url: str, data: bytes, headers: dict, label: str, attempts: int = 3) -> str:
    last_err = None
    for idx in range(1, attempts + 1):
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            last_err = RuntimeError(f"{label} HTTP {e.code}: {err_body}")
            if e.code in (429, 500, 502, 503, 504) and idx < attempts:
                time.sleep(idx * 2)
                continue
            raise last_err
        except Exception as ex:
            last_err = ex
            if idx < attempts:
                time.sleep(idx * 2)
                continue
            raise last_err
    raise last_err


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

    raw_tok = http_post_retry(
        sa.get("token_uri", "https://oauth2.googleapis.com/token"),
        form,
        {"Content-Type": "application/x-www-form-urlencoded"},
        "OAuth2",
        attempts=3,
    )
    return json.loads(raw_tok)["access_token"]


def main() -> int:
    sa_raw = os.environ.get("FCM_SERVICE_ACCOUNT_JSON", "").strip()
    if not sa_raw:
        print("[ERROR] Secret FCM_SERVICE_ACCOUNT_JSON is missing!")
        return 1

    sa = json.loads(sa_raw)
    project_id = sa["project_id"]
    commit_sha = os.environ.get("GITHUB_SHA", "").strip().lower()

    seq = "0"
    gz_b64 = ""
    raw_gz_len = 0
    if os.path.isfile("update.json"):
        try:
            raw_bytes = open("update.json", "rb").read()
            man = json.loads(raw_bytes.decode("utf-8"))
            seq = str(man.get("seq", 0))
            compressed = base64.b64encode(gzip.compress(raw_bytes, compresslevel=9)).decode("ascii")
            raw_gz_len = len(compressed)
            if raw_gz_len <= 3200:
                gz_b64 = compressed
            else:
                print(f"[WARN] Compressed update.json is {raw_gz_len}B (>3200B); sending SHA wakeup only.")
        except Exception as ex:
            print(f"[WARN] Failed to inspect update.json: {ex}")

    access_token = get_oauth2_token(sa)
    data_payload = {
        "mw_wake": "1",
        "mw_sha": commit_sha,
        "mw_seq": seq,
        "mw_ts": str(int(time.time())),
    }
    if gz_b64:
        data_payload["mw_gz"] = gz_b64

    payload = {
        "message": {
            "topic": "mw_all",
            "android": {
                "priority": "HIGH",
                "ttl": "86400s",
            },
            "data": data_payload,
        }
    }

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    try:
        body = http_post_retry(
            url,
            json.dumps(payload).encode("utf-8"),
            {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json; charset=UTF-8",
            },
            "FCM",
            attempts=3,
        )
        print(f"[OK] High-Priority FCM sent (seq={seq}, sha={commit_sha[:8]}, gz={len(gz_b64)}/{raw_gz_len}B): {body}")
        return 0
    except Exception as ex:
        print(f"[ERROR] {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
