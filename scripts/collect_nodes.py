#!/usr/bin/env python3
import asyncio
import base64
import datetime
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

OUT_FILE = "/tmp/vip_clean.txt"
TARGET_TOTAL = 360
MIN_REQUIRED = 25
MAX_CONCURRENCY = 110

FEEDS = [
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/verified.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/top.txt",
    "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/US.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/AE.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/SA.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/TR.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/DE.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/NL.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/GB.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/FR.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/SG.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/JP.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/CA.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/CH.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/SE.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/FI.txt",
    "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/v2ray-base64.txt",
    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/all_valid_proxies.txt",
    "https://radarhub.top/by-protocol/shadowsocks.txt",
    "https://radarhub.top/by-protocol/trojan.txt",
    "https://radarhub.top/by-protocol/vless.txt",
    "https://radarhub.top/by-protocol/vmess.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/ss.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/trojan.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/vless.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/vmess.txt",
    "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/Splitted-By-Protocol/ss.txt",
    "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/Splitted-By-Protocol/trojan.txt",
]

IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
SS_AEAD_METHODS = {
    "aes-256-gcm", "aead_aes_256_gcm",
    "aes-128-gcm", "aead_aes_128_gcm",
    "chacha20-ietf-poly1305", "aead_chacha20_poly1305",
}
RESTRICTED_SUFFIXES = (
    ".localhost", ".local", ".lan", ".home", ".internal",
    ".nip.io", ".sslip.io", ".xip.io",
)

def is_public_ipv4(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return ip.is_global and not (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        )
    except Exception:
        return False

def is_valid_host(host, port):
    if not host or not isinstance(port, int) or port < 1 or port > 65535:
        return False
    h = host.strip().lower()
    if len(h) > 253 or " " in h or "[" in h or ":" in h or h == "localhost":
        return False
    if any(h.endswith(suf) for suf in RESTRICTED_SUFFIXES):
        return False
    if IPV4_RE.match(h):
        return is_public_ipv4(h)
    return "." in h

def decode_b64_flex(raw):
    try:
        s = re.sub(r"\s+", "", raw or "")
        if len(s) < 4:
            return None
        rem = len(s) % 4
        if rem == 1:
            return None
        if rem:
            s += "=" * (4 - rem)
        try:
            return base64.b64decode(s)
        except Exception:
            return base64.urlsafe_b64decode(s)
    except Exception:
        return None

def parse_query(q):
    out = {}
    if not q:
        return out
    for pair in q.split("&"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        out[k.strip().lower()] = urllib.parse.unquote(v.strip())
    return out

def parse_ss(uri):
    try:
        body = uri[5:].strip()
        if "#" in body:
            body = body.split("#", 1)[0].strip()
        if "?" in body:
            body, q = body.split("?", 1)
            if "plugin=" in q.lower():
                return None
            body = body.strip()
        if not body:
            return None
        if "@" in body:
            uinfo, hp = body.rsplit("@", 1)
            uinfo = urllib.parse.unquote(uinfo.strip())
            if ":" not in uinfo:
                dec = decode_b64_flex(uinfo)
                if not dec:
                    return None
                uinfo = dec.decode("utf-8", errors="ignore")
        else:
            dec = decode_b64_flex(body)
            if not dec:
                return None
            full = dec.decode("utf-8", errors="ignore").strip()
            if "@" not in full:
                return None
            uinfo, hp = full.rsplit("@", 1)
        if ":" not in uinfo:
            return None
        method, pwd = uinfo.split(":", 1)
        if method.strip().lower() not in SS_AEAD_METHODS or not pwd or len(pwd) > 160:
            return None
        hp = hp.strip().rstrip("/")
        if hp.startswith("[") or ":" not in hp:
            return None
        host, pstr = hp.rsplit(":", 1)
        port = int(pstr.strip())
        if not is_valid_host(host, port):
            return None
        return {"uri": uri, "proto": "ss", "host": host.strip(), "port": port, "tls": False, "net": "tcp", "sni": "", "ws_host": "", "ws_path": ""}
    except Exception:
        return None

def parse_trojan(uri):
    try:
        body = uri[9:]
        if "#" in body:
            body = body.split("#", 1)[0]
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
        host, pstr = hp.rsplit(":", 1)
        host = host.strip()
        port = int(pstr.strip())
        if not is_valid_host(host, port):
            return None
        params = parse_query(q)
        sec = params.get("security", "tls").lower()
        if sec and sec != "tls":
            return None
        net = params.get("type", "tcp").lower() or "tcp"
        if net not in ("tcp", "ws", "httpupgrade"):
            return None
        sni = params.get("sni", "") or params.get("peer", "") or params.get("host", "") or host
        if IPV4_RE.match(sni):
            return None
        ws_host = params.get("host", "") or sni
        ws_path = params.get("path", "/") or "/"
        return {"uri": uri, "proto": "trojan", "host": host, "port": port, "tls": True, "net": net, "sni": sni, "ws_host": ws_host, "ws_path": ws_path}
    except Exception:
        return None

def parse_vless(uri):
    try:
        body = uri[8:]
        if "#" in body:
            body = body.split("#", 1)[0]
        q = ""
        if "?" in body:
            body, q = body.split("?", 1)
        if "@" not in body:
            return None
        uuid, hp = body.rsplit("@", 1)
        if not UUID_RE.match(uuid.replace("-", "").strip()):
            return None
        hp = hp.strip().rstrip("/")
        if hp.startswith("[") or ":" not in hp:
            return None
        host, pstr = hp.rsplit(":", 1)
        host = host.strip()
        port = int(pstr.strip())
        if not is_valid_host(host, port):
            return None
        params = parse_query(q)
        if params.get("security", "").lower() != "tls":
            return None
        if "vision" in params.get("flow", "").lower():
            return None
        net = params.get("type", "tcp").lower() or "tcp"
        if net not in ("tcp", "ws", "httpupgrade"):
            return None
        sni = params.get("sni", "") or params.get("host", "") or host
        if IPV4_RE.match(sni):
            return None
        ws_host = params.get("host", "") or sni
        ws_path = params.get("path", "/") or "/"
        return {"uri": uri, "proto": "vless", "host": host, "port": port, "tls": True, "net": net, "sni": sni, "ws_host": ws_host, "ws_path": ws_path}
    except Exception:
        return None

def parse_vmess(uri):
    try:
        b64 = uri[8:].strip()
        if "#" in b64:
            b64 = b64.split("#", 1)[0].strip()
        if len(b64) < 16 or len(b64) > 4096:
            return None
        dec = decode_b64_flex(b64)
        if not dec:
            return None
        obj = json.loads(dec.decode("utf-8", errors="ignore"))
        aid = str(obj.get("aid", "0")).strip()
        if aid and aid.lower() != "null" and int(aid) != 0:
            return None
        tls_val = str(obj.get("tls", "")).strip().lower()
        use_tls = (tls_val == "tls")
        if not use_tls and tls_val not in ("", "none"):
            return None
        host = str(obj.get("add", "")).strip()
        port = int(str(obj.get("port", "0")).strip())
        uuid = str(obj.get("id", "")).strip()
        if not UUID_RE.match(uuid.replace("-", "")) or not is_valid_host(host, port):
            return None
        net = str(obj.get("net", "tcp")).strip().lower() or "tcp"
        if net in ("ws", "httpupgrade"):
            if not use_tls:
                return None
        elif net == "tcp":
            ht = str(obj.get("type", "none")).strip().lower()
            if ht and ht != "none":
                return None
        else:
            return None
        sni = str(obj.get("sni", "")).strip() or str(obj.get("host", "")).strip() or host
        if use_tls and IPV4_RE.match(sni):
            return None
        ws_host = str(obj.get("host", "")).strip() or sni
        ws_path = str(obj.get("path", "/")).strip() or "/"
        return {"uri": uri, "proto": "vmess", "host": host, "port": port, "tls": use_tls, "net": net, "sni": sni if use_tls else "", "ws_host": ws_host, "ws_path": ws_path}
    except Exception:
        return None

def parse_line(line):
    s = line.strip()
    if not s or s.startswith("#") or len(s) > 2500:
        return None
    low = s.lower()
    if low.startswith("ss://"):
        return parse_ss(s)
    if low.startswith("trojan://"):
        return parse_trojan(s)
    if low.startswith("vless://"):
        return parse_vless(s)
    if low.startswith("vmess://"):
        return parse_vmess(s)
    return None

def fetch_feed(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14)"})
        with urllib.request.urlopen(req, timeout=14) as r:
            raw = r.read(1600000).decode("utf-8", errors="ignore").strip()
            if "://" not in raw:
                dec = decode_b64_flex(raw)
                if dec:
                    raw = dec.decode("utf-8", errors="ignore")
            return raw.splitlines()
    except Exception:
        return []

SSL_CTX = ssl.create_default_context()
SSL_CTX.minimum_version = ssl.TLSVersion.TLSv1_2

async def probe_node(sem, node):
    async with sem:
        writer = None
        try:
            loop = asyncio.get_running_loop()
            if IPV4_RE.match(node["host"]):
                connect_ip = node["host"]
            else:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(node["host"], node["port"], family=socket.AF_INET, type=socket.SOCK_STREAM),
                    timeout=2.0,
                )
                connect_ip = infos[0][4][0]
                if not is_public_ipv4(connect_ip):
                    return None

            t0 = time.monotonic()
            if node["tls"]:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, node["port"], ssl=SSL_CTX, server_hostname=node["sni"]),
                    timeout=3.2,
                )
                rtt_ms = int((time.monotonic() - t0) * 1000)
                if node["net"] in ("ws", "httpupgrade"):
                    path = node["ws_path"] if node["ws_path"].startswith("/") else ("/" + node["ws_path"])
                    path = path.replace("\r", "").replace("\n", "")
                    ws_host = node["ws_host"].replace("\r", "").replace("\n", "")
                    if node["net"] == "ws":
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
                    writer.write(req.encode("ascii", errors="ignore"))
                    await writer.drain()
                    first = await asyncio.wait_for(reader.readline(), timeout=2.5)
                    if not first.upper().startswith(b"HTTP/1.1 101"):
                        return None
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, node["port"]),
                    timeout=1.9,
                )
                rtt_ms = int((time.monotonic() - t0) * 1000)
            return (max(1, rtt_ms), node)
        except Exception:
            return None
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except Exception:
                    pass

async def main():
    print(f"[1/3] Fetching {len(FEEDS)} global feeds...")
    seen_backends = set()
    candidates = []
    for url in FEEDS:
        lines = fetch_feed(url)
        random.shuffle(lines)
        added_feed = 0
        for ln in lines:
            if added_feed >= 110:
                break
            parsed = parse_line(ln)
            if not parsed:
                continue
            bkey = (parsed["proto"], parsed["host"].lower(), parsed["port"], parsed["sni"].lower(), parsed["ws_path"])
            if bkey in seen_backends:
                continue
            seen_backends.add(bkey)
            candidates.append(parsed)
            added_feed += 1

    random.shuffle(candidates)
    candidates = candidates[:1400]
    print(f"[2/3] Probing {len(candidates)} MW-compatible encrypted candidates...")

    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    tasks = [asyncio.create_task(probe_node(sem, c)) for c in candidates]
    verified = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res is not None:
            verified.append(res)

    verified.sort(key=lambda x: x[0])

    # Balance across protocols so users always have direct SS/Trojan/VMess + TLS WS diversity
    buckets = {"ss": [], "trojan": [], "vless": [], "vmess": []}
    for rtt, node in verified:
        buckets[node["proto"]].append((rtt, node))

    selected = []
    seen_host_port = set()
    caps = {"ss": 110, "trojan": 110, "vless": 90, "vmess": 90}
    for proto in ("trojan", "ss", "vless", "vmess"):
        for rtt, node in buckets[proto]:
            if len([x for x in selected if x[1]["proto"] == proto]) >= caps[proto]:
                break
            hp = (node["host"].lower(), node["port"])
            if hp in seen_host_port:
                continue
            seen_host_port.add(hp)
            selected.append((rtt, node))

    for rtt, node in verified:
        if len(selected) >= TARGET_TOTAL:
            break
        hp = (node["host"].lower(), node["port"])
        if hp in seen_host_port:
            continue
        seen_host_port.add(hp)
        selected.append((rtt, node))

    selected.sort(key=lambda x: x[0])
    selected = selected[:TARGET_TOTAL]
    print(f"[3/3] Verified={len(verified)} | Selected={len(selected)}")

    if len(selected) < MIN_REQUIRED:
        print(f"[WARN] Too few nodes ({len(selected)} < {MIN_REQUIRED}); keeping previous feed intact.")
        sys.exit(0)

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out_lines = [f"# MW VPN Cloud Feed | Updated: {now_utc} | Nodes: {len(selected)}"]
    out_lines.extend(node["uri"] for _, node in selected)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines) + "\n")
    print(f"[OK] Wrote {len(selected)} clean nodes to {OUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
