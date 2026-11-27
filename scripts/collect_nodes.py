#!/usr/bin/env python3
import asyncio
import base64
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request

OUT_FILE = "/tmp/vip_clean.txt"
TARGET_TOTAL = 360
MIN_REQUIRED = 25
MAX_CONCURRENCY = 120
MAX_PER_COUNTRY = 10
MAX_MENA_US_COUNTRY = 14

BLOCKED_COUNTRIES = {
    "IR", "SY", "CU", "KP", "RU", "BY", "CN", "HK", "MO",
    "AF", "MM", "SD", "SS", "VE", "YE", "IQ", "LY", "SO",
    "CF", "CD", "ER", "ZW", "XX", "T1", "A1", "A2", "EU",
}
MENA_COUNTRIES = {
    "AE", "SA", "QA", "KW", "BH", "OM", "JO", "EG", "TR",
    "CY", "GE", "AM", "LB", "AZ", "MA", "TN", "DZ",
}
FASTNODES_CCS = [
    "AE", "SA", "TR", "QA", "KW", "BH", "OM", "JO", "EG", "CY", "GE", "AM",
    "SG", "JP", "KR", "IN", "AU", "NZ", "TW", "VN", "ID", "MY", "TH", "KZ",
    "US", "CA", "BR", "MX", "CL", "AR", "ZA",
    "GB", "DE", "NL", "FR", "CH", "SE", "FI", "NO", "PL", "IT", "ES",
    "AT", "CZ", "RO", "HU", "BE", "DK", "IE", "PT", "GR", "BG", "UA", "LT", "LV", "EE", "RS",
]
V2GO_CCS = [
    "AE", "TR", "SG", "JP", "KR", "IN", "AU", "BR", "CA", "US",
    "GB", "DE", "NL", "FR", "CH", "SE", "FI", "PL", "IT", "ES", "AT", "CZ", "RO", "NO", "IE",
]
AU1RXX_CCS = [
    "AE", "TR", "SG", "JP", "KR", "IN", "AU", "BR", "CA", "US",
    "GB", "DE", "NL", "FR", "CH", "SE", "FI", "PL",
]
GLOBAL_FEEDS = [
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/verified.txt",
    "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/top.txt",
    "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/verified/configs_base64.txt",
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
ISO2_TAG_RE = re.compile(r"(?:^|[^A-Z])([A-Z]{2})(?:$|[^A-Z])")
SS_AEAD_METHODS = {
    "aes-256-gcm", "aead_aes_256_gcm",
    "aes-128-gcm", "aead_aes_128_gcm",
    "chacha20-ietf-poly1305", "aead_chacha20_poly1305",
}
RESTRICTED_SUFFIXES = (".localhost", ".local", ".lan", ".home", ".internal", ".nip.io", ".sslip.io", ".xip.io")
VALID_CCS = set(FASTNODES_CCS) | MENA_COUNTRIES | {
    "SK", "SI", "HR", "LU", "IS", "MD", "AL", "BA", "MK", "ME", "MT",
    "CO", "PE", "PH", "PK", "NG", "KE", "AZ", "LB", "MA", "TN", "DZ",
}

def flag_emoji(cc):
    if not cc or len(cc) != 2: return ""
    u = cc.upper()
    return chr(0x1F1E6 + ord(u[0]) - 65) + chr(0x1F1E6 + ord(u[1]) - 65)

def extract_flag_cc(text):
    if not text: return ""
    for i in range(len(text) - 1):
        c1, c2 = ord(text[i]), ord(text[i + 1])
        if 0x1F1E6 <= c1 <= 0x1F1FF and 0x1F1E6 <= c2 <= 0x1F1FF:
            return chr(65 + (c1 - 0x1F1E6)) + chr(65 + (c2 - 0x1F1E6))
    return ""

def hint_cc_from_uri(uri, feed_cc):
    if feed_cc and len(feed_cc) == 2 and feed_cc not in BLOCKED_COUNTRIES:
        return feed_cc
    hidx = uri.rfind("#")
    if hidx > 0 and hidx + 1 < len(uri):
        tag = urllib.parse.unquote(uri[hidx + 1:])
        fc = extract_flag_cc(tag)
        if fc and fc not in BLOCKED_COUNTRIES: return fc
        m = ISO2_TAG_RE.search(tag.upper())
        if m and m.group(1) in VALID_CCS and m.group(1) not in BLOCKED_COUNTRIES:
            return m.group(1)
    return "ZZ"

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
    if not host or not isinstance(port, int) or port < 1 or port > 65535: return False
    h = host.strip().lower()
    if len(h) > 253 or " " in h or "[" in h or ":" in h or h == "localhost": return False
    if any(h.endswith(suf) for suf in RESTRICTED_SUFFIXES): return False
    if IPV4_RE.match(h): return is_public_ipv4(h)
    return "." in h

def decode_b64_flex(raw):
    try:
        s = re.sub(r"\s+", "", raw or "")
        if len(s) < 4: return None
        rem = len(s) % 4
        if rem == 1: return None
        if rem: s += "=" * (4 - rem)
        try: return base64.b64decode(s)
        except Exception: return base64.urlsafe_b64decode(s)
    except Exception:
        return None

def parse_query(q):
    out = {}
    if not q: return out
    for pair in q.split("&"):
        if "=" not in pair: continue
        k, v = pair.split("=", 1)
        out[k.strip().lower()] = urllib.parse.unquote(v.strip())
    return out

def parse_ss(uri):
    try:
        body = uri[5:].strip()
        if "#" in body: body = body.split("#", 1)[0].strip()
        if "?" in body:
            body, q = body.split("?", 1)
            if "plugin=" in q.lower(): return None
            body = body.strip()
        if not body: return None
        if "@" in body:
            uinfo, hp = body.rsplit("@", 1)
            uinfo = urllib.parse.unquote(uinfo.strip())
            if ":" not in uinfo:
                dec = decode_b64_flex(uinfo)
                if not dec: return None
                uinfo = dec.decode("utf-8", errors="ignore")
        else:
            dec = decode_b64_flex(body)
            if not dec: return None
            full = dec.decode("utf-8", errors="ignore").strip()
            if "@" not in full: return None
            uinfo, hp = full.rsplit("@", 1)
        if ":" not in uinfo: return None
        method, pwd = uinfo.split(":", 1)
        if method.strip().lower() not in SS_AEAD_METHODS or not pwd or len(pwd) > 160: return None
        hp = hp.strip().rstrip("/")
        if hp.startswith("[") or ":" not in hp: return None
        host, pstr = hp.rsplit(":", 1)
        port = int(pstr.strip())
        if not is_valid_host(host, port): return None
        return {"uri": uri, "proto": "ss", "host": host.strip(), "port": port, "auth": pwd, "tls": False, "net": "tcp", "sni": "", "ws_host": "", "ws_path": ""}
    except Exception:
        return None

def parse_trojan(uri):
    try:
        body = uri[9:]
        if "#" in body: body = body.split("#", 1)[0]
        q = ""
        if "?" in body: body, q = body.split("?", 1)
        if "@" not in body: return None
        pwd, hp = body.rsplit("@", 1)
        pwd = urllib.parse.unquote(pwd)
        if not pwd or len(pwd) > 160: return None
        hp = hp.strip().rstrip("/")
        if hp.startswith("[") or ":" not in hp: return None
        host, pstr = hp.rsplit(":", 1)
        host = host.strip()
        port = int(pstr.strip())
        if not is_valid_host(host, port): return None
        params = parse_query(q)
        sec = params.get("security", "tls").lower()
        if sec and sec != "tls": return None
        net = params.get("type", "tcp").lower() or "tcp"
        if net not in ("tcp", "ws", "httpupgrade"): return None
        sni = params.get("sni", "") or params.get("peer", "") or params.get("host", "") or host
        if IPV4_RE.match(sni): return None
        ws_host = params.get("host", "") or sni
        ws_path = params.get("path", "/") or "/"
        return {"uri": uri, "proto": "trojan", "host": host, "port": port, "auth": pwd, "tls": True, "net": net, "sni": sni, "ws_host": ws_host, "ws_path": ws_path}
    except Exception:
        return None

def parse_vless(uri):
    try:
        body = uri[8:]
        if "#" in body: body = body.split("#", 1)[0]
        q = ""
        if "?" in body: body, q = body.split("?", 1)
        if "@" not in body: return None
        uuid, hp = body.rsplit("@", 1)
        uuid_hex = uuid.replace("-", "").strip()
        if not UUID_RE.match(uuid_hex): return None
        hp = hp.strip().rstrip("/")
        if hp.startswith("[") or ":" not in hp: return None
        host, pstr = hp.rsplit(":", 1)
        host = host.strip()
        port = int(pstr.strip())
        if not is_valid_host(host, port): return None
        params = parse_query(q)
        if params.get("security", "").lower() != "tls": return None
        if "vision" in params.get("flow", "").lower(): return None
        net = params.get("type", "tcp").lower() or "tcp"
        if net not in ("tcp", "ws", "httpupgrade"): return None
        sni = params.get("sni", "") or params.get("host", "") or host
        if IPV4_RE.match(sni): return None
        ws_host = params.get("host", "") or sni
        ws_path = params.get("path", "/") or "/"
        return {"uri": uri, "proto": "vless", "host": host, "port": port, "auth": uuid_hex, "tls": True, "net": net, "sni": sni, "ws_host": ws_host, "ws_path": ws_path}
    except Exception:
        return None

def parse_vmess(uri):
    try:
        b64 = uri[8:].strip()
        if "#" in b64: b64 = b64.split("#", 1)[0].strip()
        if len(b64) < 16 or len(b64) > 4096: return None
        dec = decode_b64_flex(b64)
        if not dec: return None
        obj = json.loads(dec.decode("utf-8", errors="ignore"))
        aid = str(obj.get("aid", "0")).strip()
        if aid and aid.lower() != "null" and int(aid) != 0: return None
        tls_val = str(obj.get("tls", "")).strip().lower()
        use_tls = (tls_val == "tls")
        if not use_tls and tls_val not in ("", "none"): return None
        host = str(obj.get("add", "")).strip()
        port = int(str(obj.get("port", "0")).strip())
        uuid = str(obj.get("id", "")).strip()
        if not UUID_RE.match(uuid.replace("-", "")) or not is_valid_host(host, port): return None
        net = str(obj.get("net", "tcp")).strip().lower() or "tcp"
        if net in ("ws", "httpupgrade"):
            if not use_tls: return None
        elif net == "tcp":
            ht = str(obj.get("type", "none")).strip().lower()
            if ht and ht != "none": return None
        else:
            return None
        sni = str(obj.get("sni", "")).strip() or str(obj.get("host", "")).strip() or host
        if use_tls and IPV4_RE.match(sni): return None
        ws_host = str(obj.get("host", "")).strip() or sni
        ws_path = str(obj.get("path", "/")).strip() or "/"
        return {"uri": uri, "proto": "vmess", "host": host, "port": port, "auth": uuid, "tls": use_tls, "net": net, "sni": sni if use_tls else "", "ws_host": ws_host, "ws_path": ws_path}
    except Exception:
        return None

def parse_line(line, feed_cc):
    s = line.strip()
    if not s or s.startswith("#") or len(s) > 2500: return None
    low = s.lower()
    if low.startswith("ss://"): res = parse_ss(s)
    elif low.startswith("trojan://"): res = parse_trojan(s)
    elif low.startswith("vless://"): res = parse_vless(s)
    elif low.startswith("vmess://"): res = parse_vmess(s)
    else: return None
    if res is not None:
        res["hint_cc"] = hint_cc_from_uri(s, feed_cc)
    return res

def build_feed_jobs():
    jobs = []
    for cc in FASTNODES_CCS:
        jobs.append((f"https://cdn.jsdelivr.net/gh/rtwo2/FastNodes@main/sub/countries/{cc}.txt", cc))
    for cc in V2GO_CCS:
        jobs.append((f"https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/{cc}.txt", cc))
    for cc in AU1RXX_CCS:
        jobs.append((f"https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/by-country/v2ray-base64-{cc}.txt", cc))
    for url in GLOBAL_FEEDS:
        jobs.append((url, ""))
    return jobs

def fetch_one_feed(job):
    url, feed_cc = job
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14)"})
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = r.read(1400000).decode("utf-8", errors="ignore").strip()
            if "://" not in raw:
                dec = decode_b64_flex(raw)
                if dec: raw = dec.decode("utf-8", errors="ignore")
            return (feed_cc, raw.splitlines())
    except Exception:
        return (feed_cc, [])

def batch_geoip_lookup(ips):
    mapping = {}
    uniq = sorted({ip for ip in ips if is_public_ipv4(ip)})
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        try:
            data = json.dumps(chunk).encode("utf-8")
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,query,countryCode",
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "MW-GeoIP/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                arr = json.loads(r.read().decode("utf-8", errors="ignore"))
                if isinstance(arr, list):
                    for item in arr:
                        if isinstance(item, dict) and item.get("status") == "success":
                            q = item.get("query", "")
                            cc = str(item.get("countryCode", "")).upper().strip()
                            if q and len(cc) == 2:
                                mapping[q] = cc
        except Exception:
            pass
    return mapping

def tag_uri_with_cc(uri, cc, ai_ok):
    base = uri.split("#", 1)[0].strip()
    if cc and len(cc) == 2 and cc != "ZZ":
        suffix = f"{flag_emoji(cc)} {cc}" + (" AI" if ai_ok else "")
        return f"{base}#{urllib.parse.quote(suffix)}"
    return base

SSL_CTX = ssl.create_default_context()
SSL_CTX.minimum_version = ssl.TLSVersion.TLSv1_2

# Real End-to-End Tunnel + Gemini GeoIP Gate Probe using Python stdlib ssl.MemoryBIO
async def probe_trojan_or_vless_gemini_e2e(reader, writer, node):
    target_host = "generativelanguage.googleapis.com"
    hb = target_host.encode("ascii")
    if node["proto"] == "trojan":
        pw_hex = hashlib.sha224(node["auth"].encode("utf-8")).hexdigest().encode("ascii")
        proto_hdr = pw_hex + b"\r\n\x01\x03" + bytes([len(hb)]) + hb + struct.pack("!H", 443) + b"\r\n"
        strip_vless = False
    elif node["proto"] == "vless":
        uuid_b = bytes.fromhex(node["auth"])
        proto_hdr = b"\x00" + uuid_b + b"\x00\x01" + struct.pack("!H", 443) + b"\x02" + bytes([len(hb)]) + hb
        strip_vless = True
    else:
        return (False, False)

    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()
    ssl_obj = SSL_CTX.wrap_bio(in_bio, out_bio, server_hostname=target_host)
    hdr_sent = False
    vless_stripped = not strip_vless
    rx_pending = bytearray()

    async def flush_out():
        nonlocal hdr_sent
        data = out_bio.read()
        if data:
            if not hdr_sent:
                writer.write(proto_hdr + data)
                hdr_sent = True
            else:
                writer.write(data)
            await writer.drain()

    async def feed_in(timeout_s=2.6):
        nonlocal vless_stripped
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout_s)
        if not chunk:
            raise EOFError("Tunnel EOF")
        if not vless_stripped:
            rx_pending.extend(chunk)
            if len(rx_pending) < 2:
                return
            if rx_pending[0] != 0:
                raise ValueError("Bad VLESS resp")
            need = 2 + rx_pending[1]
            if len(rx_pending) < need:
                return
            rem = bytes(rx_pending[need:])
            rx_pending.clear()
            vless_stripped = True
            if rem:
                in_bio.write(rem)
        else:
            in_bio.write(chunk)

    for _ in range(12):
        try:
            ssl_obj.do_handshake()
            await flush_out()
            break
        except ssl.SSLWantReadError:
            await flush_out()
            await feed_in(2.4)
        except ssl.SSLWantWriteError:
            await flush_out()

    req = (
        "GET /v1beta/models?key=MW_CLOUD_PROBE HTTP/1.1\r\n"
        "Host: generativelanguage.googleapis.com\r\n"
        "User-Agent: Mozilla/5.0 (Linux; Android 14)\r\n"
        "Accept: application/json\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    ssl_obj.write(req)
    await flush_out()

    resp_chunks = bytearray()
    for _ in range(10):
        try:
            d = ssl_obj.read(4096)
            if not d:
                break
            resp_chunks.extend(d)
            if len(resp_chunks) >= 2048 or b"}" in resp_chunks:
                break
        except ssl.SSLWantReadError:
            await feed_in(2.4)
        except EOFError:
            break

    low = resp_chunks.decode("utf-8", errors="ignore").lower()
    if not low or "http/1." not in low:
        return (False, False)
    if ("api key not valid" in low or "api_key_invalid" in low or "invalid_argument" in low) \
            and "location" not in low and "failed_precondition" not in low:
        return (True, True)
    return (True, False)

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
                    timeout=1.8,
                )
                connect_ip = infos[0][4][0]
                if not is_public_ipv4(connect_ip):
                    return None

            t0 = time.monotonic()
            e2e_ok = False
            ai_ok = False
            if node["tls"]:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, node["port"], ssl=SSL_CTX, server_hostname=node["sni"]),
                    timeout=3.0,
                )
                rtt_ms = int((time.monotonic() - t0) * 1000)
                if node["net"] in ("ws", "httpupgrade"):
                    path = node["ws_path"] if node["ws_path"].startswith("/") else ("/" + node["ws_path"])
                    path = path.replace("\r", "").replace("\n", "")
                    ws_host = node["ws_host"].replace("\r", "").replace("\n", "")
                    if node["net"] == "ws":
                        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
                        req = (
                            f"GET {path} HTTP/1.1\r\nHost: {ws_host}\r\nUpgrade: websocket\r\n"
                            f"Connection: Upgrade\r\nSec-WebSocket-Key: {ws_key}\r\n"
                            f"Sec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        )
                    else:
                        req = (
                            f"GET {path} HTTP/1.1\r\nHost: {ws_host}\r\nConnection: Upgrade\r\n"
                            f"Upgrade: websocket\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        )
                    writer.write(req.encode("ascii", errors="ignore"))
                    await writer.drain()
                    first = await asyncio.wait_for(reader.readline(), timeout=2.3)
                    if not first.upper().startswith(b"HTTP/1.1 101"):
                        return None
                elif node["proto"] in ("trojan", "vless") and node["net"] == "tcp":
                    try:
                        e2e_ok, ai_ok = await asyncio.wait_for(
                            probe_trojan_or_vless_gemini_e2e(reader, writer, node),
                            timeout=4.8,
                        )
                    except Exception:
                        e2e_ok, ai_ok = (False, False)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, node["port"]),
                    timeout=1.8,
                )
                rtt_ms = int((time.monotonic() - t0) * 1000)
            node["ip"] = connect_ip
            node["e2e_ok"] = e2e_ok
            node["ai_ok"] = ai_ok
            return (max(1, rtt_ms), node)
        except Exception:
            return None
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.4)
                except Exception:
                    pass

async def main():
    jobs = build_feed_jobs()
    print(f"[1/4] Fetching {len(jobs)} country & global feeds in parallel...")
    seen_backends = set()
    by_hint_cc = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=18) as ex:
        for feed_cc, lines in ex.map(fetch_one_feed, jobs):
            random.shuffle(lines)
            limit = 45 if feed_cc else 140
            added = 0
            for ln in lines:
                if added >= limit: break
                p = parse_line(ln, feed_cc)
                if not p: continue
                bkey = (p["proto"], p["host"].lower(), p["port"], p["sni"].lower(), p["ws_path"])
                if bkey in seen_backends: continue
                seen_backends.add(bkey)
                by_hint_cc.setdefault(p["hint_cc"], []).append(p)
                added += 1

    candidates = []
    for cc, lst in by_hint_cc.items():
        random.shuffle(lst)
    cc_order = list(by_hint_cc.keys())
    random.shuffle(cc_order)
    for rnd in range(42):
        for cc in cc_order:
            lst = by_hint_cc[cc]
            if rnd < len(lst):
                candidates.append(lst[rnd])
                if len(candidates) >= 1750: break
        if len(candidates) >= 1750: break

    print(f"[2/4] Probing {len(candidates)} candidates (TCP + TLS + WS101 + Real E2E Gemini)...")
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    tasks = [asyncio.create_task(probe_node(sem, c)) for c in candidates]
    verified = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res is not None:
            verified.append(res)

    print(f"[3/4] Verified {len(verified)} live nodes — resolving real GeoIP countries...")
    geo_map = batch_geoip_lookup([n["ip"] for _, n in verified])

    by_real_cc = {}
    for rtt, node in verified:
        real_cc = geo_map.get(node["ip"], "")
        if not real_cc or len(real_cc) != 2:
            real_cc = node["hint_cc"] if node["hint_cc"] != "ZZ" else "US"
        if real_cc in BLOCKED_COUNTRIES:
            continue
        node["real_cc"] = real_cc
        by_real_cc.setdefault(real_cc, []).append((rtt, node))

    for cc in by_real_cc:
        # Rank inside each country: E2E Gemini AI verified -> E2E verified -> direct TCP -> lowest RTT
        by_real_cc[cc].sort(key=lambda x: (
            0 if x[1].get("ai_ok") else 1,
            0 if x[1].get("e2e_ok") else 1,
            0 if x[1]["net"] == "tcp" else 1,
            x[0],
        ))

    def cc_priority(cc):
        if cc in MENA_COUNTRIES: return (0, cc)
        if cc in ("SG", "JP", "KR", "AU", "IN", "CA", "BR", "US", "TW", "VN", "MY", "ID", "TH", "MX", "CL", "ZA", "NZ"):
            return (1, cc)
        return (2, cc)

    ordered_ccs = sorted(by_real_cc.keys(), key=cc_priority)
    selected = []
    seen_hp = set()
    cc_counts = {}
    for rnd in range(MAX_MENA_US_COUNTRY):
        for cc in ordered_ccs:
            if len(selected) >= TARGET_TOTAL: break
            cap = MAX_MENA_US_COUNTRY if (cc in MENA_COUNTRIES or cc == "US") else MAX_PER_COUNTRY
            if cc_counts.get(cc, 0) >= cap: continue
            lst = by_real_cc[cc]
            while lst:
                rtt, node = lst.pop(0)
                hp = (node["host"].lower(), node["port"])
                if hp in seen_hp: continue
                seen_hp.add(hp)
                selected.append((cc, rtt, node))
                cc_counts[cc] = cc_counts.get(cc, 0) + 1
                break
        if len(selected) >= TARGET_TOTAL: break

    uniq_ccs = sorted(cc_counts.keys())
    ai_total = sum(1 for _, _, n in selected if n.get("ai_ok"))
    print(f"[4/4] Selected={len(selected)} | Countries={len(uniq_ccs)} | Gemini_AI_Verified={ai_total}")
    if len(selected) < MIN_REQUIRED:
        sys.exit(0)

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out_lines = [
        f"# MW VPN Cloud Feed | Updated: {now_utc} | Nodes: {len(selected)} | Countries: {len(uniq_ccs)} | AI: {ai_total} ({','.join(uniq_ccs)})"
    ]
    for cc, _, node in selected:
        out_lines.append(tag_uri_with_cc(node["uri"], cc, bool(node.get("ai_ok"))))

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines) + "\n")

if __name__ == "__main__":
    asyncio.run(main())
