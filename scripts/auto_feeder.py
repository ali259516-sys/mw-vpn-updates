#!/usr/bin/env python3
import base64
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

FEEDS = [
    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/site_access/aistudio.txt",
    "https://cdn.jsdelivr.net/gh/Alirewa/V2ray-Configs@main/sub1.txt",
    "https://cdn.jsdelivr.net/gh/Alirewa/V2ray-Configs@main/sub2.txt",
    "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/trojan.txt",
    "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/ss.txt",
    "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/v2ray/super-sub.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/verified.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/US.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/AE.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/TR.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/SG.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/DE.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/NL.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/GB.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/CA.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/trojan.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/ss.txt",
]

UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$')
IP_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
SS_ALLOWED = {
    "aes-256-gcm", "aead_aes_256_gcm",
    "aes-128-gcm", "aead_aes_128_gcm",
    "chacha20-ietf-poly1305", "aead_chacha20_poly1305",
}

def b64_flex(s):
    s = re.sub(r'\s+', '', s)
    rem = len(s) % 4
    if rem == 1:
        return None
    if rem:
        s += "=" * (4 - rem)
    try:
        return base64.b64decode(s)
    except Exception:
        try:
            return base64.urlsafe_b64decode(s)
        except Exception:
            return None

def valid_host(h):
    if not h or h.startswith("[") or ":" in h or " " in h or len(h) > 253:
        return False
    low = h.lower()
    if low in ("localhost", "127.0.0.1", "0.0.0.0") or low.endswith((".localhost", ".local", ".lan", ".home", ".internal")):
        return False
    if IP_RE.match(low):
        parts = [int(x) for x in low.split(".")]
        if any(p > 255 for p in parts):
            return False
        b0, b1 = parts[0], parts[1]
        if b0 in (0, 10, 127) or b0 >= 224:
            return False
        if (b0 == 192 and b1 == 168) or (b0 == 172 and 16 <= b1 <= 31) or (b0 == 169 and b1 == 254):
            return False
        if (b0 == 100 and 64 <= b1 <= 127) or (b0 == 198 and b1 in (18, 19)):
            return False
    return True

def parse_node(uri):
    uri = uri.strip()
    if not uri or len(uri) > 2048:
        return None
    low = uri.lower()
    try:
        if low.startswith("trojan://"):
            body = uri[9:].split("#", 1)[0]
            q = body.split("?", 1)[1] if "?" in body else ""
            body = body.split("?", 1)[0]
            pwd, hp = body.rsplit("@", 1)
            if not pwd or len(pwd) > 160 or hp.startswith("["):
                return None
            host, port = hp.rsplit(":", 1)[0].strip(), int(hp.rsplit(":", 1)[1].strip())
            p = dict(urllib.parse.parse_qsl(q))
            sec = p.get("security", "tls").lower()
            typ = p.get("type", "tcp").lower()
            sni = (p.get("sni") or p.get("peer") or p.get("host") or host).strip()
            if sec in ("", "tls") and typ in ("tcp", "ws", "httpupgrade") and valid_host(host) and 1 <= port <= 65535 and not IP_RE.match(sni):
                return ("trojan", host, port, sni, True, 0, uri)

        elif low.startswith("vless://"):
            body = uri[8:].split("#", 1)[0]
            q = body.split("?", 1)[1] if "?" in body else ""
            body = body.split("?", 1)[0]
            uid, hp = body.rsplit("@", 1)
            if not UUID_RE.match(uid.strip()) or hp.startswith("["):
                return None
            host, port = hp.rsplit(":", 1)[0].strip(), int(hp.rsplit(":", 1)[1].strip())
            p = dict(urllib.parse.parse_qsl(q))
            sec = p.get("security", "").lower()
            typ = p.get("type", "tcp").lower()
            flow = p.get("flow", "").lower()
            sni = (p.get("sni") or p.get("host") or host).strip()
            if sec == "tls" and typ in ("tcp", "ws", "httpupgrade") and "vision" not in flow and valid_host(host) and 1 <= port <= 65535 and not IP_RE.match(sni):
                return ("vless", host, port, sni, True, 0, uri)

        elif low.startswith("vmess://"):
            raw = b64_flex(uri[8:].split("#", 1)[0])
            if not raw:
                return None
            obj = json.loads(raw.decode("utf-8", errors="ignore"))
            if int(obj.get("aid", 0) or 0) != 0:
                return None
            host = str(obj.get("add", "")).strip()
            port = int(str(obj.get("port", 0)).strip())
            uid = str(obj.get("id", "")).strip()
            tls = str(obj.get("tls", "")).lower().strip()
            net = str(obj.get("net", "tcp")).lower().strip()
            use_tls = (tls == "tls")
            if not UUID_RE.match(uid) or not valid_host(host) or not (1 <= port <= 65535):
                return None
            if net in ("ws", "httpupgrade") and not use_tls:
                return None
            if net == "tcp" and str(obj.get("type", "none")).lower() not in ("", "none"):
                return None
            sni = (str(obj.get("sni", "")).strip() or str(obj.get("host", "")).strip() or host)
            if use_tls and IP_RE.match(sni):
                return None
            return ("vmess", host, port, sni if use_tls else "", use_tls, 10, uri)

        elif low.startswith("ss://"):
            body = uri[5:].split("#", 1)[0]
            if "?" in body:
                body, q = body.split("?", 1)
                if "plugin=" in q.lower():
                    return None
            if "@" not in body:
                dec = b64_flex(body)
                if not dec:
                    return None
                body = dec.decode("utf-8", errors="ignore")
            ui, hp = body.rsplit("@", 1)
            if ":" not in ui:
                dec = b64_flex(ui)
                if not dec:
                    return None
                ui = dec.decode("utf-8", errors="ignore")
            method, pwd = ui.split(":", 1)
            if method.lower().strip() not in SS_ALLOWED or not pwd or len(pwd) > 160:
                return None
            hp = hp.rstrip("/")
            if hp.startswith("["):
                return None
            host, port = hp.rsplit(":", 1)[0].strip(), int(hp.rsplit(":", 1)[1].strip())
            if valid_host(host) and 1 <= port <= 65535:
                return ("ss", host, port, "", False, 25, uri)
    except Exception:
        return None
    return None

def fetch_feed(url):
    out = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        raw = urllib.request.urlopen(req, timeout=12).read().decode("utf-8", errors="ignore").strip()
        if "://" not in raw:
            dec = b64_flex(raw)
            raw = dec.decode("utf-8", errors="ignore") if dec else ""
        for line in raw.splitlines():
            p = parse_node(line)
            if p:
                out.append(p)
                if len(out) >= 120:
                    break
    except Exception:
        pass
    return out

def probe(item):
    proto, host, port, sni, use_tls, penalty, uri = item
    raw = None
    try:
        t0 = time.time()
        raw = socket.create_connection((host, port), timeout=1.6)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                s.settimeout(2.2)
                s.do_handshake()
            raw = None
        else:
            raw.close()
            raw = None
        rtt = int((time.time() - t0) * 1000)
        if rtt <= 0 or rtt > 900:
            return None
        return (rtt + penalty, rtt, proto, host, uri)
    except Exception:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass
        return None

def main():
    candidates = []
    seen_ep = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for batch in ex.map(fetch_feed, FEEDS):
            for item in batch:
                ep_key = (item[1].lower(), item[2])
                if ep_key not in seen_ep:
                    seen_ep.add(ep_key)
                    candidates.append(item)

    print(f"Collected {len(candidates)} compatible encrypted candidates")
    if not candidates:
        sys.exit(0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=45) as ex:
        alive = [r for r in ex.map(probe, candidates[:750]) if r is not None]

    alive.sort(key=lambda x: x[0])

    # Keep diverse mix (max 2 per host, cap at 160 fastest nodes)
    selected = []
    host_counts = {}
    proto_counts = {}
    for score, rtt, proto, host, uri in alive:
        h = host.lower()
        if host_counts.get(h, 0) >= 2:
            continue
        if proto == "ss" and proto_counts.get("ss", 0) >= 70:
            continue
        host_counts[h] = host_counts.get(h, 0) + 1
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
        selected.append(uri)
        if len(selected) >= 160:
            break

    print(f"Verified alive: {len(alive)} | Selected clean nodes: {len(selected)} | Breakdown: {proto_counts}")
    if len(selected) < 10:
        print("Too few verified nodes; skipping update to preserve previous live feed.")
        sys.exit(0)

    with open("vip_clean.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(selected) + "\n")

    with open("stats.txt", "w", encoding="utf-8") as f:
        f.write(f"updated_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        f.write(f"total_nodes={len(selected)}\n")
        f.write(f"protocols={json.dumps(proto_counts)}\n")

if __name__ == "__main__":
    main()
