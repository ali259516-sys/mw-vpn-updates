#!/usr/bin/env python3
"""
MaintenanceWorld VPN — Cloud Auto Feeder v2.0
Fetches top verified dynamic feeds, filters strictly for MW_VPN v1.0.0 compatibility
(AEAD Shadowsocks, Trojan TLS, VLESS TLS non-vision, VMess AEAD aid=0),
performs real TCP + Strict CA TLS + WS/HTTPUpgrade 101 verification,
and outputs clean vip_clean.txt & stats.txt for the isolated `feeds` branch.
"""

import base64
import concurrent.futures
import datetime
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

FEEDS = [
    # Tier 1: Real Xray/HTTP-verified multi-country & protocol pools
    ("v2go-US",      "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/US.txt", 140),
    ("v2go-AE",      "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/AE.txt", 100),
    ("v2go-SG",      "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/SG.txt", 80),
    ("v2go-DE",      "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/DE.txt", 80),
    ("v2go-SS",      "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Protocol/ss.txt", 160),
    ("v2go-VMess",   "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Protocol/vmess.txt", 140),
    ("v2go-Trojan",  "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Protocol/trojan.txt", 120),
    # Tier 2: 3-Round HTTP-verified pools
    ("Radikal-Top",  "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/top100.txt", 120),
    ("Radikal-Ver",  "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/verified/configs_base64.txt", 180),
    ("Au1rxx-Ver",   "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/all-verified/v2ray-base64-0001.txt", 180),
    ("Au1rxx-AE",    "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/by-country/v2ray-base64-AE.txt", 100),
    # Tier 3: Fast high-frequency protocol splits & RadarHub
    ("Matin-SS",     "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/ss.txt", 140),
    ("Matin-Troj",   "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/trojan.txt", 120),
    ("Matin-VMess",  "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/vmess.txt", 120),
    ("CFY-SS",       "https://cdn.jsdelivr.net/gh/mohammadaz2/v2rayConfigsForYou@main/sub/ss.txt", 120),
    ("CFY-Troj",     "https://cdn.jsdelivr.net/gh/mohammadaz2/v2rayConfigsForYou@main/sub/trojan.txt", 100),
    ("CFY-VMess",    "https://cdn.jsdelivr.net/gh/mohammadaz2/v2rayConfigsForYou@main/sub/vmess.txt", 100),
    ("Fast-US",      "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/US.txt", 120),
    ("Fast-AE",      "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/AE.txt", 100),
    ("Fast-Ver",     "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/verified.txt", 140),
    ("Radar-SS",     "https://radarhub.top/by-protocol/shadowsocks.txt", 120),
    ("Radar-Troj",   "https://radarhub.top/by-protocol/trojan.txt", 120),
    ("Radar-VMess",  "https://radarhub.top/by-protocol/vmess.txt", 120),
    ("Radar-VLESS",  "https://radarhub.top/by-protocol/vless.txt", 100),
]

ALLOWED_SS_CIPHERS = {
    "aes-256-gcm", "aead_aes_256_gcm",
    "aes-128-gcm", "aead_aes_128_gcm",
    "chacha20-ietf-poly1305", "aead_chacha20_poly1305",
}

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
UUID_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")
MAX_FINAL_NODES = 280
MAX_PER_HOST = 2


def b64_decode_flex(raw: str) -> str:
    compact = re.sub(r"\s+", "", raw or "")
    if len(compact) < 8:
        return ""
    mod = len(compact) % 4
    if mod == 1:
        return ""
    if mod:
        compact += "=" * (4 - mod)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(compact).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return ""


def is_public_host(host: str) -> bool:
    if not host or len(host) > 253 or " " in host or "[" in host or ":" in host:
        return False
    h = host.lower().strip()
    if h in ("localhost", "0.0.0.0") or h.endswith(
        (".localhost", ".local", ".lan", ".home", ".internal", ".nip.io", ".sslip.io", ".xip.io")
    ):
        return False
    if IPV4_RE.match(h):
        try:
            p = [int(x) for x in h.split(".")]
            if any(x < 0 or x > 255 for x in p):
                return False
            b0, b1 = p[0], p[1]
            if b0 in (0, 10, 127) or b0 >= 224:
                return False
            if b0 == 192 and b1 == 168:
                return False
            if b0 == 172 and 16 <= b1 <= 31:
                return False
            if b0 == 169 and b1 == 254:
                return False
            if b0 == 100 and 64 <= b1 <= 127:
                return False
            if b0 == 198 and b1 in (18, 19):
                return False
        except Exception:
            return False
    return True


def sanitize_token(val: str) -> str:
    return (val or "").replace("\r", "").replace("\n", "").replace("\0", "").strip()


def parse_compatible_node(line: str):
    """Returns dict matching EncryptedTransportAdapter.java rules, or None."""
    line = sanitize_token(line)
    if not line or line.startswith("#") or "://" not in line:
        return None
    lo = line.lower()

    try:
        if lo.startswith("ss://"):
            body = line[5:].split("#", 1)[0].strip()
            if "?" in body:
                body, q = body.split("?", 1)
                if "plugin=" in q.lower():
                    return None
                body = body.strip()
            if not body:
                return None
            if "@" in body:
                ui, hp = body.rsplit("@", 1)
                ui = urllib.parse.unquote(ui.strip())
                if ":" not in ui:
                    ui = b64_decode_flex(ui)
            else:
                full = b64_decode_flex(body).strip()
                if "@" not in full:
                    return None
                ui, hp = full.rsplit("@", 1)
            if ":" not in ui:
                return None
            method, pwd = ui.split(":", 1)
            if method.lower().strip() not in ALLOWED_SS_CIPHERS or not pwd or len(pwd) > 160:
                return None
            hp = hp.strip().rstrip("/")
            if hp.startswith("[") or ":" not in hp:
                return None
            host, port_s = hp.rsplit(":", 1)
            host = host.strip()
            port = int(port_s.strip())
            if not is_public_host(host) or not (1 <= port <= 65535):
                return None
            return {
                "proto": "SS-AEAD",
                "host": host,
                "port": port,
                "outer_tls": False,
                "transport": "tcp",
                "sni": "",
                "ws_host": "",
                "ws_path": "",
                "uri": line,
            }

        if lo.startswith("trojan://"):
            body = line[9:].split("#", 1)[0]
            q = ""
            if "?" in body:
                body, q = body.split("?", 1)
            if "@" not in body:
                return None
            pwd, hp = body.rsplit("@", 1)
            pwd = urllib.parse.unquote(pwd)
            if not pwd or len(pwd) > 160:
                return None
            hp = hp.strip().rstrip("/")
            if hp.startswith("[") or ":" not in hp:
                return None
            host, port_s = hp.rsplit(":", 1)
            host = host.strip()
            port = int(port_s.strip())
            if not is_public_host(host) or not (1 <= port <= 65535):
                return None
            qs = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(q).items()}
            sec = qs.get("security", "tls").lower().strip()
            if sec not in ("", "tls"):
                return None
            typ = qs.get("type", "tcp").lower().strip() or "tcp"
            if typ not in ("tcp", "ws", "httpupgrade"):
                return None
            sni = sanitize_token(qs.get("sni") or qs.get("peer") or qs.get("host") or host)
            ws_host = sanitize_token(qs.get("host") or sni or host)
            ws_path = sanitize_token(qs.get("path") or "/") if typ in ("ws", "httpupgrade") else ""
            if IPV4_RE.match(sni) or not sni:
                return None
            return {
                "proto": "TROJAN-TLS",
                "host": host,
                "port": port,
                "outer_tls": True,
                "transport": typ,
                "sni": sni,
                "ws_host": ws_host,
                "ws_path": ws_path or "/",
                "uri": line,
            }

        if lo.startswith("vless://"):
            body = line[8:].split("#", 1)[0]
            q = ""
            if "?" in body:
                body, q = body.split("?", 1)
            if "@" not in body:
                return None
            uuid, hp = body.rsplit("@", 1)
            if not UUID_HEX_RE.match(uuid.replace("-", "").strip()):
                return None
            hp = hp.strip().rstrip("/")
            if hp.startswith("[") or ":" not in hp:
                return None
            host, port_s = hp.rsplit(":", 1)
            host = host.strip()
            port = int(port_s.strip())
            if not is_public_host(host) or not (1 <= port <= 65535):
                return None
            qs = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(q).items()}
            if qs.get("security", "").lower().strip() != "tls":
                return None
            if "vision" in qs.get("flow", "").lower():
                return None
            typ = qs.get("type", "tcp").lower().strip() or "tcp"
            if typ not in ("tcp", "ws", "httpupgrade"):
                return None
            sni = sanitize_token(qs.get("sni") or qs.get("host") or host)
            ws_host = sanitize_token(qs.get("host") or sni or host)
            ws_path = sanitize_token(qs.get("path") or "/") if typ in ("ws", "httpupgrade") else ""
            if IPV4_RE.match(sni) or not sni:
                return None
            return {
                "proto": "VLESS-TLS",
                "host": host,
                "port": port,
                "outer_tls": True,
                "transport": typ,
                "sni": sni,
                "ws_host": ws_host,
                "ws_path": ws_path or "/",
                "uri": line,
            }

        if lo.startswith("vmess://"):
            b64 = line[8:].split("#", 1)[0].strip()
            if len(b64) < 16 or len(b64) > 4096:
                return None
            decoded = b64_decode_flex(b64)
            if not decoded:
                return None
            obj = json.loads(decoded)
            aid_val = obj.get("aid", 0)
            if aid_val is not None:
                aid_str = str(aid_val).strip()
                if aid_str and aid_str.lower() != "null":
                    if int(aid_str) != 0:
                        return None
            tls_val = str(obj.get("tls", "")).lower().strip()
            use_tls = tls_val == "tls"
            if not use_tls and tls_val not in ("", "none"):
                return None
            host = sanitize_token(str(obj.get("add", "")))
            port = int(str(obj.get("port", "0")).strip())
            uuid = str(obj.get("id", "")).strip()
            if not UUID_HEX_RE.match(uuid.replace("-", "")) or not is_public_host(host) or not (1 <= port <= 65535):
                return None
            net = str(obj.get("net", "tcp")).lower().strip() or "tcp"
            if net in ("ws", "httpupgrade"):
                if not use_tls:
                    return None
                ws_path = sanitize_token(str(obj.get("path", "/") or "/")) or "/"
            elif net == "tcp":
                hdr_type = str(obj.get("type", "none")).lower().strip()
                if hdr_type not in ("", "none"):
                    return None
                ws_path = ""
            else:
                return None
            sni = sanitize_token(str(obj.get("sni", "") or obj.get("host", "") or host)) if use_tls else ""
            ws_host = sanitize_token(str(obj.get("host", "") or sni or host))
            if use_tls and (not sni or IPV4_RE.match(sni)):
                return None
            return {
                "proto": "VMESS-TLS" if use_tls else "VMESS-AEAD",
                "host": host,
                "port": port,
                "outer_tls": use_tls,
                "transport": net,
                "sni": sni,
                "ws_host": ws_host,
                "ws_path": ws_path or "/",
                "uri": line,
            }
    except Exception:
        return None
    return None


def fetch_feed(feed_tuple):
    name, url, limit = feed_tuple
    out = []
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) MaintenanceWorldVPN-Feeder/2.0",
                "Accept-Encoding": "identity",
            },
        )
        with urllib.request.urlopen(req, timeout=16) as resp:
            raw = resp.read(2 * 1024 * 1024).decode("utf-8", errors="ignore").strip()
        if "://" not in raw:
            raw = b64_decode_flex(raw)
        if not raw or "://" not in raw:
            return name, []
        for ln in raw.splitlines():
            if len(out) >= limit:
                break
            parsed = parse_compatible_node(ln)
            if parsed:
                parsed["src"] = name
                out.append(parsed)
    except Exception:
        return name, []
    return name, out


def verify_node_strict(node: dict):
    """Verifies real TCP + Strict CA TLS 1.2/1.3 + WS/HTTPUpgrade 101 handshake."""
    host = node["host"]
    port = node["port"]
    raw_sock = None
    sock = None
    try:
        t0 = time.monotonic()
        raw_sock = socket.create_connection((host, port), timeout=2.5)
        rtt_ms = max(1, int((time.monotonic() - t0) * 1000))
        raw_sock.settimeout(3.2)

        if node["outer_tls"]:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            sock = ctx.wrap_socket(raw_sock, server_hostname=node["sni"])
            sock.settimeout(3.2)

            if node["transport"] in ("ws", "httpupgrade"):
                path = node["ws_path"] if node["ws_path"].startswith("/") else ("/" + node["ws_path"])
                ws_host = node["ws_host"] or node["sni"] or host
                if node["transport"] == "ws":
                    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {ws_host}\r\n"
                        f"Upgrade: websocket\r\n"
                        f"Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {ws_key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n"
                        f"User-Agent: Mozilla/5.0 (Linux; Android 14)\r\n\r\n"
                    )
                else:
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {ws_host}\r\n"
                        f"Connection: Upgrade\r\n"
                        f"Upgrade: websocket\r\n"
                        f"User-Agent: Mozilla/5.0 (Linux; Android 14)\r\n\r\n"
                    )
                sock.sendall(req.encode("ascii", errors="ignore"))
                head = sock.recv(1024).decode("ascii", errors="ignore")
                first_line = head.split("\r\n", 1)[0].upper()
                if not first_line.startswith("HTTP/1.1 101"):
                    return None
        node["rtt"] = rtt_ms
        return node
    except Exception:
        return None
    finally:
        for s in (sock, raw_sock):
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass


def main() -> int:
    t_start = time.monotonic()
    feed_stats = []
    candidates = []
    seen_keys = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for name, items in ex.map(fetch_feed, FEEDS):
            added = 0
            for item in items:
                key = (item["proto"], item["host"].lower(), item["port"], item["sni"].lower(), item["ws_path"])
                if key not in seen_keys:
                    seen_keys.add(key)
                    candidates.append(item)
                    added += 1
            feed_stats.append((name, len(items), added))

    print(f"[INFO] Fetched {len(candidates)} unique MW_VPN-compatible candidates from {len(FEEDS)} feeds.")
    if not candidates:
        print("[WARN] No compatible candidates fetched.")
        return 0

    # Cap total verify load so Actions finishes quickly (<2 min)
    if len(candidates) > 1200:
        candidates = candidates[:1200]

    verified = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for res in ex.map(verify_node_strict, candidates):
            if res is not None:
                verified.append(res)

    # Sort: prefer direct-VPS/SS/Trojan & lowest RTT
    proto_priority = {
        "SS-AEAD": 0,
        "TROJAN-TLS": 1,
        "VMESS-TLS": 2,
        "VLESS-TLS": 2,
        "VMESS-AEAD": 3,
    }
    verified.sort(key=lambda x: (x["rtt"] + proto_priority.get(x["proto"], 4) * 25, x["rtt"]))

    # Enforce per-host cap so final pool stays diverse
    final_nodes = []
    host_counts = {}
    proto_counts = {}
    for n in verified:
        hk = n["host"].lower()
        if host_counts.get(hk, 0) >= MAX_PER_HOST:
            continue
        host_counts[hk] = host_counts.get(hk, 0) + 1
        final_nodes.append(n)
        proto_counts[n["proto"]] = proto_counts.get(n["proto"], 0) + 1
        if len(final_nodes) >= MAX_FINAL_NODES:
            break

    if not final_nodes:
        print("[WARN] Zero nodes passed strict verification.")
        return 0

    with open("vip_clean.txt", "w", encoding="utf-8") as f:
        for n in final_nodes:
            f.write(n["uri"] + "\n")

    elapsed = round(time.monotonic() - t_start, 1)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rtts = [n["rtt"] for n in final_nodes]
    avg_rtt = int(sum(rtts) / max(1, len(rtts)))

    lines = [
        "==========================================================",
        "MaintenanceWorld VPN — Verified Cloud Feed Stats (v2.0)",
        f"Updated: {now_utc} | Scan Duration: {elapsed}s",
        f"Total Candidates: {len(candidates)} | Strict Verified: {len(verified)} | Published: {len(final_nodes)}",
        f"RTT (Runner): min={min(rtts)}ms | avg={avg_rtt}ms | max={max(rtts)}ms",
        "Protocols: " + ", ".join(f"{k}={v}" for k, v in sorted(proto_counts.items())),
        "==========================================================",
        "Source Breakdown (parsed / unique):",
    ]
    for name, parsed_c, uniq_c in feed_stats:
        lines.append(f"  - {name:<14}: {parsed_c:>3} parsed / {uniq_c:>3} unique")

    stats_text = "\n".join(lines) + "\n"
    with open("stats.txt", "w", encoding="utf-8") as f:
        f.write(stats_text)

    print(stats_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
