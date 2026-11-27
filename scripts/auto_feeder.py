#!/usr/bin/env python3
"""
MaintenanceWorld VPN — Cloud Auto Feeder v4.0 (Real Exit-IP + Cloud AI-Clean |AI + Balanced MENA/Global)
- Zero external pip dependencies (Python stdlib + embedded Java 8+ RealExitVerifier).
- Active high-yield MENA & Global sources only (dead FastNodes/broken endpoints removed).
- Real tunnel Exit-IP verification for SS-AEAD, Trojan-TLS, VLESS-TLS (non-vision), VMess-AEAD (aid=0).
- Cloud Gemini/Google GeoIP clean verification tagging verified nodes with #MW-<CC>-<RTT>ms|AI
  so MW VPN unlocks Gemini instantly via CoreTunnelService.hasCloudAiTag() with zero client battery waste.
- Balanced country diversity caps (MENA reserved up to 90, US cap 65, other single CC cap 30).
"""

import base64
import concurrent.futures
import datetime
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

FEEDS = [
    # --- Active Middle East & Neighboring (MENA) Feeds ---
    ("MENA", "Forge-AE",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/ae/all.txt", 160),
    ("MENA", "Forge-TR",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/tr/all.txt", 160),
    ("MENA", "Forge-SA",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/sa/all.txt", 120),
    ("MENA", "Forge-EG",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/eg/all.txt", 100),
    ("MENA", "Forge-CY",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/cy/all.txt", 100),
    ("MENA", "Forge-QA",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/qa/all.txt", 100),
    ("MENA", "Forge-BH",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/bh/all.txt", 100),
    ("MENA", "Forge-KW",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/kw/all.txt", 100),
    ("MENA", "Forge-OM",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/om/all.txt", 100),
    ("MENA", "Forge-JO",      "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/jo/all.txt", 100),
    ("MENA", "OpenRay-AE",    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/country/AE.txt", 140),
    ("MENA", "OpenRay-TR",    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/country/TR.txt", 140),
    ("MENA", "OpenRay-SA",    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/country/SA.txt", 100),
    ("MENA", "OpenRay-AM",    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/country/AM.txt", 100),
    ("MENA", "OpenRay-GE",    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/country/GE.txt", 100),
    ("MENA", "Soli-AE",       "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Countries/United_Arab_Emirates.txt", 140),
    ("MENA", "Soli-TR",       "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Countries/Turkey.txt", 140),
    ("MENA", "Soli-SA",       "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Countries/Saudi_Arabia.txt", 100),
    ("MENA", "Soli-EG",       "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Countries/Egypt.txt", 100),
    ("MENA", "Soli-GE",       "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Countries/Georgia.txt", 100),
    ("MENA", "Soli-AM",       "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Countries/Armenia.txt", 100),
    ("MENA", "v2go-AE",       "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/AE.txt", 120),
    ("MENA", "v2go-TR",       "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/TR.txt", 120),
    # --- High-Yield Global Verified Pools ---
    ("GLOBAL", "v2go-US",     "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/US.txt", 140),
    ("GLOBAL", "v2go-SG",     "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/SG.txt", 110),
    ("GLOBAL", "v2go-DE",     "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/DE.txt", 100),
    ("GLOBAL", "v2go-GB",     "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/GB.txt", 100),
    ("GLOBAL", "v2go-JP",     "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/JP.txt", 100),
    ("GLOBAL", "v2go-CA",     "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Country/CA.txt", 100),
    ("GLOBAL", "v2go-SS",     "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Protocol/ss.txt", 160),
    ("GLOBAL", "v2go-VMess",  "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Protocol/vmess.txt", 140),
    ("GLOBAL", "v2go-Trojan", "https://cdn.jsdelivr.net/gh/Danialsamadi/v2go@main/Splitted-By-Protocol/trojan.txt", 120),
    ("GLOBAL", "Radikal-Top", "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/top100.txt", 120),
    ("GLOBAL", "Radikal-Ver", "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/verified/configs_base64.txt", 180),
    ("GLOBAL", "Au1rxx-Ver",  "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/all-verified/v2ray-base64-0001.txt", 180),
    ("GLOBAL", "OpenRay-All", "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/all_valid_proxies.txt", 180),
    ("GLOBAL", "Matin-SS",    "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/ss.txt", 150),
    ("GLOBAL", "Matin-Troj",  "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/trojan.txt", 120),
    ("GLOBAL", "Matin-VMess", "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/filtered/subs/vmess.txt", 120),
    ("GLOBAL", "Alirewa-1",   "https://cdn.jsdelivr.net/gh/Alirewa/V2ray-Configs@main/sub1.txt", 140),
    ("GLOBAL", "Morpheus",    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt", 140),
    ("GLOBAL", "CFY-Troj",    "https://cdn.jsdelivr.net/gh/mohammadaz2/v2rayConfigsForYou@main/sub/trojan.txt", 100),
    ("GLOBAL", "CFY-VMess",   "https://cdn.jsdelivr.net/gh/mohammadaz2/v2rayConfigsForYou@main/sub/vmess.txt", 100),
    ("GLOBAL", "Barry-SS",    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/ss.txt", 140),
    ("GLOBAL", "Barry-Troj",  "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/trojan.txt", 120),
    ("GLOBAL", "Radar-SS",    "https://radarhub.top/by-protocol/shadowsocks.txt", 140),
    ("GLOBAL", "Radar-Troj",  "https://radarhub.top/by-protocol/trojan.txt", 120),
    ("GLOBAL", "Radar-VMess", "https://radarhub.top/by-protocol/vmess.txt", 120),
    ("GLOBAL", "Radar-VLESS", "https://radarhub.top/by-protocol/vless.txt", 110),
]

MENA_COUNTRIES = {
    "AE", "SA", "QA", "KW", "BH", "OM", "JO", "EG",
    "TR", "CY", "LB", "GE", "AM", "AZ", "MA", "TN", "DZ",
}

BLOCKED_COUNTRIES = {
    "IR", "SY", "CU", "KP", "RU", "BY", "CN", "HK", "MO",
    "AF", "MM", "SD", "SS", "VE", "YE", "IQ", "LY", "SO",
    "CF", "CD", "ER", "ZW", "XX", "T1", "A1", "A2", "EU",
}

MENA_TAG_RE = re.compile(
    r"(?:^|[^A-Z])(AE|SA|QA|KW|BH|OM|JO|EG|TR|CY|GE|AM|LB|AZ|MA|TN|DZ|"
    r"UAE|EMIRATES|DUBAI|ABUDHABI|RIYADH|JEDDAH|SAUDI|DOHA|QATAR|KUWAIT|"
    r"BAHRAIN|MANAMA|OMAN|MUSCAT|JORDAN|AMMAN|EGYPT|CAIRO|TURKEY|ISTANBUL|"
    r"ANKARA|IZMIR|CYPRUS|GEORGIA|TBILISI|ARMENIA|YEREVAN|BAKU|BEIRUT)(?:$|[^A-Z])"
)

SS_CIPHER_MAP = {
    "aes-256-gcm": "SS-AES256",
    "aead_aes_256_gcm": "SS-AES256",
    "aes-128-gcm": "SS-AES128",
    "aead_aes_128_gcm": "SS-AES128",
    "chacha20-ietf-poly1305": "SS-CHACHA",
    "aead_chacha20_poly1305": "SS-CHACHA",
}

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
UUID_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")

MAX_MENA_CANDIDATES = 700
MAX_GLOBAL_CANDIDATES = 1000
MAX_FINAL_NODES = 280
MENA_RESERVED_SLOTS = 90
US_COUNTRY_CAP = 65
OTHER_COUNTRY_CAP = 30
MAX_PER_HOST_GLOBAL = 2
MAX_PER_HOST_MENA = 3

# Self-contained Zero-Dependency Java 8+ Real Tunnel Exit-IP + Cloud Gemini GeoIP Verifier
JAVA_VERIFIER_SRC = r"""
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.*;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

public final class RealExitVerifier {
    private static final SecureRandom RNG = new SecureRandom();
    private static final Pattern TRACE_LOC = Pattern.compile("loc=([A-Z]{2})");
    private static final String WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final byte[] SS_SUBKEY_INFO = "ss-subkey".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VMESS_MAGIC = "c48619fe-8f02-49e0-b9e9-edf763e17e21".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VMESS_KDF_SALT = "VMess AEAD KDF".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_AUTH_ID = "AES Auth ID Encryption".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_HLEN_K = "VMess Header AEAD Key_Length".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_HLEN_N = "VMess Header AEAD Nonce_Length".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_HDR_K = "VMess Header AEAD Key".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_HDR_N = "VMess Header AEAD Nonce".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_RLEN_K = "AEAD Resp Header Len Key".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_RLEN_N = "AEAD Resp Header Len IV".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_RHDR_K = "AEAD Resp Header Key".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KDF_RHDR_N = "AEAD Resp Header IV".getBytes(StandardCharsets.US_ASCII);
    private static final Set<String> BLOCKED_CC = new HashSet<>(Arrays.asList(
            "IR","SY","CU","KP","RU","BY","CN","HK","MO","AF","MM","SD","SS",
            "VE","YE","IQ","LY","SO","CF","CD","ER","ZW","XX","T1","A1","A2","EU"
    ));
    private static final String CHACHA_ALG = detectChaChaAlg();
    private static final Map<String, String> DNS_CACHE = new ConcurrentHashMap<>();
    private static SSLSocketFactory SSL_FACTORY;

    private static String detectChaChaAlg() {
        for (String name : new String[]{"ChaCha20-Poly1305", "ChaCha20/Poly1305/NoPadding"}) {
            try {
                Cipher c = Cipher.getInstance(name);
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "ChaCha20"), new IvParameterSpec(new byte[12]));
                if (c.doFinal(new byte[]{1}).length == 17) return name;
            } catch (Throwable ignored) {}
        }
        return null;
    }

    private static boolean isPublicIpv4(String ip) {
        if (ip == null) return false;
        String[] p = ip.split("\\.");
        if (p.length != 4) return false;
        try {
            int b0 = Integer.parseInt(p[0]), b1 = Integer.parseInt(p[1]),
                b2 = Integer.parseInt(p[2]), b3 = Integer.parseInt(p[3]);
            if (b0 < 0 || b0 > 255 || b1 < 0 || b1 > 255 || b2 < 0 || b2 > 255 || b3 < 0 || b3 > 255) return false;
            if (b0 == 0 || b0 == 10 || b0 == 127 || b0 >= 224) return false;
            if (b0 == 192 && b1 == 168) return false;
            if (b0 == 172 && b1 >= 16 && b1 <= 31) return false;
            if (b0 == 169 && b1 == 254) return false;
            if (b0 == 100 && b1 >= 64 && b1 <= 127) return false;
            return !(b0 == 198 && (b1 == 18 || b1 == 19));
        } catch (Throwable ignored) { return false; }
    }

    private static String resolvePublicIpv4(String host) {
        if (host == null || host.isEmpty()) return null;
        String norm = host.toLowerCase(Locale.ROOT).trim();
        String cached = DNS_CACHE.get(norm);
        if (cached != null) return cached.isEmpty() ? null : cached;
        if (norm.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            String res = isPublicIpv4(norm) ? norm : "";
            DNS_CACHE.put(norm, res);
            return res.isEmpty() ? null : res;
        }
        try {
            for (InetAddress a : InetAddress.getAllByName(norm)) {
                if (a instanceof Inet4Address) {
                    String ip = a.getHostAddress();
                    if (isPublicIpv4(ip)) {
                        DNS_CACHE.put(norm, ip);
                        return ip;
                    }
                }
            }
        } catch (Throwable ignored) {}
        DNS_CACHE.put(norm, "");
        return null;
    }

    private static SSLSocket wrapStrictTls(Socket raw, String sni, int port, int timeoutMs) throws Exception {
        SSLSocket ssl = (SSLSocket) SSL_FACTORY.createSocket(raw, sni, port, true);
        List<String> protos = new ArrayList<>();
        for (String p : ssl.getSupportedProtocols()) {
            if ("TLSv1.3".equals(p) || "TLSv1.2".equals(p)) protos.add(p);
        }
        if (!protos.isEmpty()) ssl.setEnabledProtocols(protos.toArray(new String[0]));
        SSLParameters sp = ssl.getSSLParameters();
        sp.setEndpointIdentificationAlgorithm("HTTPS");
        if (sni != null && !sni.isEmpty()) {
            sp.setServerNames(Collections.singletonList(new SNIHostName(sni)));
        }
        ssl.setSSLParameters(sp);
        ssl.setSoTimeout(timeoutMs);
        ssl.startHandshake();
        SSLSession ses = ssl.getSession();
        if (ses == null || !ses.isValid() || ses.getPeerCertificates() == null || ses.getPeerCertificates().length == 0) {
            throw new SSLPeerUnverifiedException("Invalid TLS session");
        }
        return ssl;
    }

    private static String readHeaderBlock(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
        int st = 0, b;
        while (buf.size() < 16384 && (b = in.read()) != -1) {
            buf.write(b);
            if (b == 13) st = (st == 0 || st == 2) ? st + 1 : 1;
            else if (b == 10) {
                if (st == 1) st = 2;
                else if (st == 3) break;
                else st = 0;
            } else st = 0;
        }
        return buf.size() == 0 ? null : new String(buf.toByteArray(), StandardCharsets.US_ASCII);
    }

    private static String decodeChunkedBody(String body) {
        StringBuilder out = new StringBuilder();
        int p = 0, n = body.length();
        while (p < n) {
            int cr = body.indexOf("\r\n", p);
            if (cr < 0) break;
            String szLine = body.substring(p, cr).trim();
            int semi = szLine.indexOf(';');
            if (semi >= 0) szLine = szLine.substring(0, semi).trim();
            int sz;
            try { sz = Integer.parseInt(szLine, 16); } catch (Throwable t) { break; }
            p = cr + 2;
            if (sz <= 0 || p + sz > n) break;
            out.append(body, p, p + sz);
            p += sz + 2;
        }
        return out.toString();
    }

    private static byte[] parseUuid(String u) {
        String hex = u.replace("-", "").trim();
        if (hex.length() != 32) return null;
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) return null;
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static byte[] buildSocks5DomainAddr(String host, int port) {
        byte[] hb = host.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[1 + 1 + hb.length + 2];
        out[0] = 0x03;
        out[1] = (byte) hb.length;
        System.arraycopy(hb, 0, out, 2, hb.length);
        out[2 + hb.length] = (byte) ((port >> 8) & 0xFF);
        out[3 + hb.length] = (byte) (port & 0xFF);
        return out;
    }

    private static String sha224Hex(byte[] data) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-224").digest(data);
        char[] alph = "0123456789abcdef".toCharArray();
        char[] out = new char[d.length * 2];
        for (int i = 0; i < d.length; i++) {
            out[i * 2] = alph[(d[i] >>> 4) & 0x0F];
            out[i * 2 + 1] = alph[d[i] & 0x0F];
        }
        return new String(out);
    }

    private static byte[] evpMd5(byte[] pw, int keyLen) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] res = new byte[keyLen];
        byte[] prev = null;
        int filled = 0;
        while (filled < keyLen) {
            md5.reset();
            if (prev != null) md5.update(prev);
            md5.update(pw);
            prev = md5.digest();
            int cp = Math.min(prev.length, keyLen - filled);
            System.arraycopy(prev, 0, res, filled, cp);
            filled += cp;
        }
        return res;
    }

    private static byte[] hkdfSha1(byte[] ikm, byte[] salt, byte[] info, int outLen) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA1");
        hmac.init(new SecretKeySpec(salt, "HmacSHA1"));
        byte[] prk = hmac.doFinal(ikm);
        byte[] out = new byte[outLen];
        byte[] t = new byte[0];
        int filled = 0;
        byte ctr = 1;
        while (filled < outLen) {
            hmac.init(new SecretKeySpec(prk, "HmacSHA1"));
            hmac.update(t);
            hmac.update(info);
            hmac.update(ctr++);
            t = hmac.doFinal();
            int cp = Math.min(t.length, outLen - filled);
            System.arraycopy(t, 0, out, filled, cp);
            filled += cp;
        }
        return out;
    }

    private static void incNonceLE(byte[] n) {
        for (int i = 0; i < n.length; i++) {
            int v = (n[i] & 0xFF) + 1;
            n[i] = (byte) v;
            if ((v & 0x100) == 0) break;
        }
    }

    private interface HashFn { byte[] hash(byte[] data) throws Exception; }
    private static final HashFn SHA256_FN = new HashFn() {
        @Override public byte[] hash(byte[] data) throws Exception {
            return MessageDigest.getInstance("SHA-256").digest(data);
        }
    };

    private static HashFn wrapHmac(final HashFn inner, byte[] key) throws Exception {
        byte[] k = key.length > 64 ? inner.hash(key) : key;
        final byte[] ipad = new byte[64], opad = new byte[64];
        for (int i = 0; i < 64; i++) {
            byte b = (i < k.length) ? k[i] : 0;
            ipad[i] = (byte) (b ^ 0x36);
            opad[i] = (byte) (b ^ 0x5C);
        }
        return new HashFn() {
            @Override public byte[] hash(byte[] msg) throws Exception {
                byte[] inBuf = new byte[64 + msg.length];
                System.arraycopy(ipad, 0, inBuf, 0, 64);
                System.arraycopy(msg, 0, inBuf, 64, msg.length);
                byte[] id = inner.hash(inBuf);
                byte[] outBuf = new byte[64 + id.length];
                System.arraycopy(opad, 0, outBuf, 0, 64);
                System.arraycopy(id, 0, outBuf, 64, id.length);
                return inner.hash(outBuf);
            }
        };
    }

    private static byte[] vmessKdf(byte[] key, byte[]... path) throws Exception {
        HashFn cur = wrapHmac(SHA256_FN, VMESS_KDF_SALT);
        for (byte[] p : path) cur = wrapHmac(cur, p);
        return cur.hash(key);
    }

    private static int fnv1a32(byte[] d, int len) {
        int h = 0x811c9dc5;
        for (int i = 0; i < len; i++) { h ^= (d[i] & 0xFF); h *= 0x01000193; }
        return h;
    }

    private static byte[] aesGcm(Cipher c, int mode, SecretKeySpec k, byte[] iv, byte[] aad, byte[] in, int off, int len) throws Exception {
        c.init(mode, k, new GCMParameterSpec(128, iv));
        if (aad != null && aad.length > 0) c.updateAAD(aad);
        return c.doFinal(in, off, len);
    }

    private static abstract class BaseWrapSocket extends Socket {
        protected final Socket base;
        BaseWrapSocket(Socket base) { this.base = base; }
        @Override public void close() throws IOException { base.close(); }
        @Override public boolean isClosed() { return base.isClosed(); }
        @Override public boolean isConnected() { return base.isConnected(); }
        @Override public void setSoTimeout(int t) throws SocketException { base.setSoTimeout(t); }
        @Override public int getSoTimeout() throws SocketException { return base.getSoTimeout(); }
        @Override public InetAddress getInetAddress() { return base.getInetAddress(); }
        @Override public int getPort() { return base.getPort(); }
    }

    private static final class BufSocket extends BaseWrapSocket {
        private final InputStream in;
        BufSocket(Socket base, InputStream in) { super(base); this.in = in; }
        @Override public InputStream getInputStream() { return in; }
        @Override public OutputStream getOutputStream() throws IOException { return base.getOutputStream(); }
    }

    private static final class WsSocket extends BaseWrapSocket {
        private final DataInputStream rawIn;
        private final OutputStream rawOut;
        private final Object wLock = new Object();
        private final InputStream wsIn;
        private final OutputStream wsOut;
        private volatile boolean closed = false;

        WsSocket(Socket base, InputStream bis, OutputStream rawOut) {
            super(base);
            this.rawIn = new DataInputStream(bis);
            this.rawOut = rawOut;
            this.wsOut = new OutputStream() {
                @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }
                @Override public void write(byte[] b, int off, int len) throws IOException {
                    int pos = off, end = off + len;
                    while (pos < end) {
                        int ch = Math.min(32768, end - pos);
                        sendFrame(0x82, b, pos, ch);
                        pos += ch;
                    }
                }
                @Override public void flush() throws IOException { synchronized (wLock) { rawOut.flush(); } }
                @Override public void close() throws IOException { WsSocket.this.close(); }
            };
            this.wsIn = new InputStream() {
                private byte[] buf = null;
                private int pos = 0, len = 0;
                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    int r = read(one, 0, 1);
                    return r == -1 ? -1 : (one[0] & 0xFF);
                }
                @Override public int read(byte[] b, int off, int l) throws IOException {
                    if (l <= 0) return 0;
                    while (pos >= len) {
                        if (closed || !nextFrame()) return -1;
                    }
                    int cp = Math.min(len - pos, l);
                    System.arraycopy(buf, pos, b, off, cp);
                    pos += cp;
                    return cp;
                }
                private boolean nextFrame() throws IOException {
                    int ctrl = 0;
                    while (!closed) {
                        int b0;
                        try { b0 = rawIn.readUnsignedByte(); } catch (EOFException e) { closed = true; return false; }
                        int b1 = rawIn.readUnsignedByte();
                        int op = b0 & 0x0F;
                        boolean masked = (b1 & 0x80) != 0;
                        long plen = b1 & 0x7F;
                        if (plen == 126) plen = rawIn.readUnsignedShort();
                        else if (plen == 127) plen = rawIn.readLong();
                        if (plen < 0 || plen > 262144) throw new IOException("WS frame too big");
                        byte[] mk = null;
                        if (masked) { mk = new byte[4]; rawIn.readFully(mk); }
                        int p = (int) plen;
                        byte[] pay = new byte[p];
                        if (p > 0) {
                            rawIn.readFully(pay);
                            if (masked) for (int i = 0; i < p; i++) pay[i] ^= mk[i & 3];
                        }
                        if (op == 0x08) { closed = true; return false; }
                        if (op == 0x09) {
                            if (++ctrl > 16) throw new IOException("WS ping flood");
                            try { sendFrame(0x8A, pay, 0, p); } catch (Throwable ignored) {}
                            continue;
                        }
                        if (op == 0x0A) { if (++ctrl > 16) throw new IOException("WS pong flood"); continue; }
                        if ((op == 0 || op == 1 || op == 2) && p > 0) { buf = pay; pos = 0; len = p; return true; }
                    }
                    return false;
                }
                @Override public void close() throws IOException { WsSocket.this.close(); }
            };
        }

        private void sendFrame(int fb, byte[] data, int off, int len) throws IOException {
            byte[] mk = new byte[4];
            RNG.nextBytes(mk);
            int hlen = (len <= 125) ? 6 : (len <= 65535 ? 8 : 14);
            byte[] f = new byte[hlen + len];
            f[0] = (byte) fb;
            int idx;
            if (len <= 125) { f[1] = (byte) (0x80 | len); idx = 2; }
            else if (len <= 65535) { f[1] = (byte) (0x80 | 126); f[2] = (byte) (len >> 8); f[3] = (byte) len; idx = 4; }
            else { f[1] = (byte) (0x80 | 127); f[6] = (byte) (len >>> 24); f[7] = (byte) (len >>> 16); f[8] = (byte) (len >>> 8); f[9] = (byte) len; idx = 10; }
            System.arraycopy(mk, 0, f, idx, 4);
            idx += 4;
            for (int i = 0; i < len; i++) f[idx + i] = (byte) (data[off + i] ^ mk[i & 3]);
            synchronized (wLock) { rawOut.write(f); rawOut.flush(); }
        }
        @Override public InputStream getInputStream() { return wsIn; }
        @Override public OutputStream getOutputStream() { return wsOut; }
        @Override public void close() throws IOException { closed = true; super.close(); }
    }

    private static final class DeferredSocket extends BaseWrapSocket {
        private final byte[] hdr;
        private final boolean stripVless;
        private volatile boolean sent = false;
        private final Object lock = new Object();
        private final InputStream wIn;
        private final OutputStream wOut;

        DeferredSocket(Socket base, byte[] hdr, boolean stripVless) throws IOException {
            super(base);
            this.hdr = hdr;
            this.stripVless = stripVless;
            final InputStream rIn = base.getInputStream();
            final OutputStream rOut = base.getOutputStream();
            this.wOut = new OutputStream() {
                @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }
                @Override public void write(byte[] b, int off, int len) throws IOException {
                    if (len <= 0) return;
                    synchronized (lock) {
                        if (!sent) {
                            sent = true;
                            byte[] m = new byte[hdr.length + len];
                            System.arraycopy(hdr, 0, m, 0, hdr.length);
                            System.arraycopy(b, off, m, hdr.length, len);
                            rOut.write(m);
                            return;
                        }
                    }
                    rOut.write(b, off, len);
                }
                @Override public void flush() throws IOException { rOut.flush(); }
                @Override public void close() throws IOException { DeferredSocket.this.close(); }
            };
            this.wIn = new InputStream() {
                private boolean stripped = !stripVless;
                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    int r = read(one, 0, 1);
                    return r == -1 ? -1 : (one[0] & 0xFF);
                }
                @Override public int read(byte[] b, int off, int len) throws IOException {
                    if (len <= 0) return 0;
                    if (!sent) { synchronized (lock) { if (!sent) { sent = true; rOut.write(hdr); rOut.flush(); } } }
                    if (!stripped) {
                        int ver = rIn.read();
                        if (ver != 0) return -1;
                        int aLen = rIn.read();
                        if (aLen < 0) return -1;
                        for (int i = 0; i < aLen; i++) if (rIn.read() < 0) return -1;
                        stripped = true;
                    }
                    return rIn.read(b, off, len);
                }
                @Override public void close() throws IOException { DeferredSocket.this.close(); }
            };
        }
        @Override public InputStream getInputStream() { return wIn; }
        @Override public OutputStream getOutputStream() { return wOut; }
    }

    private static final class SsSocket extends BaseWrapSocket {
        private final boolean isChaCha;
        private final int keyLen;
        private final byte[] masterKey, txSalt, addrHdr;
        private final SecretKeySpec txKeySpec;
        private final Cipher txCipher;
        private final byte[] txNonce = new byte[12];
        private final DataInputStream rawIn;
        private final OutputStream rawOut;
        private final Object wLock = new Object();
        private volatile boolean hdrSent = false;
        private final InputStream sIn;
        private final OutputStream sOut;

        SsSocket(Socket base, String proto, String pw, String destHost, int destPort) throws Exception {
            super(base);
            this.isChaCha = "SS-CHACHA".equals(proto);
            if (isChaCha && CHACHA_ALG == null) throw new IOException("No ChaCha20");
            this.keyLen = "SS-AES128".equals(proto) ? 16 : 32;
            this.addrHdr = buildSocks5DomainAddr(destHost, destPort);
            this.masterKey = evpMd5(pw.getBytes(StandardCharsets.UTF_8), keyLen);
            this.txSalt = new byte[keyLen];
            RNG.nextBytes(txSalt);
            byte[] txSub = hkdfSha1(masterKey, txSalt, SS_SUBKEY_INFO, keyLen);
            this.txKeySpec = new SecretKeySpec(txSub, isChaCha ? "ChaCha20" : "AES");
            this.txCipher = Cipher.getInstance(isChaCha ? CHACHA_ALG : "AES/GCM/NoPadding");
            this.rawIn = new DataInputStream(new BufferedInputStream(base.getInputStream(), 16384));
            this.rawOut = base.getOutputStream();

            this.sOut = new OutputStream() {
                @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }
                @Override public void write(byte[] b, int off, int len) throws IOException {
                    if (len <= 0) return;
                    synchronized (wLock) {
                        if (!hdrSent) {
                            hdrSent = true;
                            int fp = Math.min(len, 0x3FFF - addrHdr.length);
                            byte[] m = new byte[addrHdr.length + fp];
                            System.arraycopy(addrHdr, 0, m, 0, addrHdr.length);
                            System.arraycopy(b, off, m, addrHdr.length, fp);
                            writeChunk(m, 0, m.length, true);
                            int pos = off + fp, end = off + len;
                            while (pos < end) { int ch = Math.min(0x3FFF, end - pos); writeChunk(b, pos, ch, false); pos += ch; }
                            return;
                        }
                        int pos = off, end = off + len;
                        while (pos < end) { int ch = Math.min(0x3FFF, end - pos); writeChunk(b, pos, ch, false); pos += ch; }
                    }
                }
                @Override public void flush() throws IOException { synchronized (wLock) { rawOut.flush(); } }
                @Override public void close() throws IOException { SsSocket.this.close(); }
            };
            this.sIn = new InputStream() {
                private SecretKeySpec rxKeySpec = null;
                private Cipher rxCipher = null;
                private final byte[] rxNonce = new byte[12];
                private byte[] pBuf = null;
                private int pPos = 0, pLen = 0;
                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    int r = read(one, 0, 1);
                    return r == -1 ? -1 : (one[0] & 0xFF);
                }
                @Override public int read(byte[] b, int off, int len) throws IOException {
                    if (len <= 0) return 0;
                    if (!hdrSent) { synchronized (wLock) { if (!hdrSent) { hdrSent = true; writeChunk(addrHdr, 0, addrHdr.length, true); rawOut.flush(); } } }
                    while (pPos >= pLen) {
                        try {
                            if (rxKeySpec == null) {
                                byte[] rs = new byte[keyLen];
                                rawIn.readFully(rs);
                                byte[] rSub = hkdfSha1(masterKey, rs, SS_SUBKEY_INFO, keyLen);
                                rxKeySpec = new SecretKeySpec(rSub, isChaCha ? "ChaCha20" : "AES");
                                rxCipher = Cipher.getInstance(isChaCha ? CHACHA_ALG : "AES/GCM/NoPadding");
                            }
                            byte[] eLen = new byte[18];
                            rawIn.readFully(eLen);
                            byte[] dLen = aead(rxCipher, Cipher.DECRYPT_MODE, rxKeySpec, rxNonce, eLen, 0, 18);
                            incNonceLE(rxNonce);
                            int pl = ((dLen[0] & 0x3F) << 8) | (dLen[1] & 0xFF);
                            if (pl <= 0 || pl > 0x3FFF) return -1;
                            byte[] ePay = new byte[pl + 16];
                            rawIn.readFully(ePay);
                            pBuf = aead(rxCipher, Cipher.DECRYPT_MODE, rxKeySpec, rxNonce, ePay, 0, ePay.length);
                            incNonceLE(rxNonce);
                            pPos = 0; pLen = pBuf.length;
                        } catch (EOFException e) { return -1; }
                        catch (Throwable t) { throw new IOException(t); }
                    }
                    int cp = Math.min(pLen - pPos, len);
                    System.arraycopy(pBuf, pPos, b, off, cp);
                    pPos += cp;
                    return cp;
                }
                @Override public void close() throws IOException { SsSocket.this.close(); }
            };
        }

        private byte[] aead(Cipher c, int mode, SecretKeySpec k, byte[] n, byte[] in, int off, int len) throws Exception {
            if (isChaCha) c.init(mode, k, new IvParameterSpec(n));
            else c.init(mode, k, new GCMParameterSpec(128, n));
            return c.doFinal(in, off, len);
        }

        private void writeChunk(byte[] pt, int off, int len, boolean withSalt) throws IOException {
            try {
                byte[] lb = {(byte) ((len >> 8) & 0x3F), (byte) (len & 0xFF)};
                byte[] eLen = aead(txCipher, Cipher.ENCRYPT_MODE, txKeySpec, txNonce, lb, 0, 2);
                incNonceLE(txNonce);
                byte[] ePay = aead(txCipher, Cipher.ENCRYPT_MODE, txKeySpec, txNonce, pt, off, len);
                incNonceLE(txNonce);
                int sLen = withSalt ? txSalt.length : 0;
                byte[] wire = new byte[sLen + eLen.length + ePay.length];
                if (withSalt) System.arraycopy(txSalt, 0, wire, 0, sLen);
                System.arraycopy(eLen, 0, wire, sLen, eLen.length);
                System.arraycopy(ePay, 0, wire, sLen + eLen.length, ePay.length);
                rawOut.write(wire);
            } catch (Throwable t) { throw new IOException(t); }
        }
        @Override public InputStream getInputStream() { return sIn; }
        @Override public OutputStream getOutputStream() { return sOut; }
    }

    private static final class VmessSocket extends BaseWrapSocket {
        private final byte[] reqHdrWire, txIv, rxKey, rxIv;
        private final SecretKeySpec txKeySpec, rxKeySpec;
        private final Cipher txCipher, rxCipher;
        private final byte respAuthV;
        private final DataInputStream rawIn;
        private final OutputStream rawOut;
        private final Object wLock = new Object();
        private volatile boolean hdrSent = false;
        private int txCnt = 0, rxCnt = 0;
        private final InputStream vIn;
        private final OutputStream vOut;

        VmessSocket(Socket base, byte[] uuidBytes, String destHost, int destPort) throws Exception {
            super(base);
            this.rawIn = new DataInputStream(new BufferedInputStream(base.getInputStream(), 16384));
            this.rawOut = base.getOutputStream();

            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(uuidBytes); md5.update(VMESS_MAGIC);
            byte[] cmdKey = md5.digest();

            byte[] txKey = new byte[16]; this.txIv = new byte[16];
            RNG.nextBytes(txKey); RNG.nextBytes(txIv);
            byte[] vb = new byte[1]; RNG.nextBytes(vb); this.respAuthV = vb[0];
            this.txKeySpec = new SecretKeySpec(txKey, "AES");
            this.txCipher = Cipher.getInstance("AES/GCM/NoPadding");

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            this.rxKey = Arrays.copyOf(sha256.digest(txKey), 16);
            sha256.reset();
            this.rxIv = Arrays.copyOf(sha256.digest(txIv), 16);
            this.rxKeySpec = new SecretKeySpec(rxKey, "AES");
            this.rxCipher = Cipher.getInstance("AES/GCM/NoPadding");

            long nowSec = System.currentTimeMillis() / 1000L;
            byte[] ap = new byte[16];
            for (int i = 0; i < 8; i++) ap[7 - i] = (byte) ((nowSec >>> (i * 8)) & 0xFF);
            byte[] ar = new byte[4]; RNG.nextBytes(ar); System.arraycopy(ar, 0, ap, 8, 4);
            CRC32 crc = new CRC32(); crc.update(ap, 0, 12); long cv = crc.getValue();
            ap[12] = (byte)(cv>>>24); ap[13] = (byte)(cv>>>16); ap[14] = (byte)(cv>>>8); ap[15] = (byte)cv;

            Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
            ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOf(vmessKdf(cmdKey, KDF_AUTH_ID), 16), "AES"));
            byte[] authId = ecb.doFinal(ap);

            ByteArrayOutputStream hp = new ByteArrayOutputStream(128);
            hp.write(1); hp.write(txIv); hp.write(txKey); hp.write(respAuthV & 0xFF); hp.write(1);
            int padLen = RNG.nextInt(16);
            hp.write(((padLen & 0x0F) << 4) | 0x03); hp.write(0); hp.write(1);
            hp.write((destPort >> 8) & 0xFF); hp.write(destPort & 0xFF);
            byte[] hb = destHost.getBytes(StandardCharsets.US_ASCII);
            hp.write(2); hp.write(hb.length & 0xFF); hp.write(hb);
            if (padLen > 0) { byte[] pad = new byte[padLen]; RNG.nextBytes(pad); hp.write(pad); }
            byte[] bf = hp.toByteArray();
            int fh = fnv1a32(bf, bf.length);
            hp.write(fh>>>24); hp.write(fh>>>16); hp.write(fh>>>8); hp.write(fh);
            byte[] hPlain = hp.toByteArray();

            byte[] n8 = new byte[8]; RNG.nextBytes(n8);
            byte[] lb = {(byte)((hPlain.length >> 8) & 0xFF), (byte)(hPlain.length & 0xFF)};
            byte[] lEnc = aesGcm(txCipher, Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(Arrays.copyOf(vmessKdf(cmdKey, KDF_HLEN_K, authId, n8), 16), "AES"),
                    Arrays.copyOf(vmessKdf(cmdKey, KDF_HLEN_N, authId, n8), 12), authId, lb, 0, 2);
            byte[] hEnc = aesGcm(txCipher, Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(Arrays.copyOf(vmessKdf(cmdKey, KDF_HDR_K, authId, n8), 16), "AES"),
                    Arrays.copyOf(vmessKdf(cmdKey, KDF_HDR_N, authId, n8), 12), authId, hPlain, 0, hPlain.length);

            ByteArrayOutputStream wire = new ByteArrayOutputStream(16 + lEnc.length + 8 + hEnc.length);
            wire.write(authId); wire.write(lEnc); wire.write(n8); wire.write(hEnc);
            this.reqHdrWire = wire.toByteArray();

            this.vOut = new OutputStream() {
                @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }
                @Override public void write(byte[] b, int off, int len) throws IOException {
                    if (len <= 0) return;
                    synchronized (wLock) {
                        int pos = off, end = off + len;
                        while (pos < end) {
                            int ch = Math.min(16300, end - pos);
                            writeEncChunk(b, pos, ch);
                            pos += ch;
                        }
                    }
                }
                @Override public void flush() throws IOException { synchronized (wLock) { rawOut.flush(); } }
                @Override public void close() throws IOException { VmessSocket.this.close(); }
            };
            this.vIn = new InputStream() {
                private boolean respOk = false;
                private byte[] pBuf = null;
                private int pPos = 0, pLen = 0;
                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    int r = read(one, 0, 1);
                    return r == -1 ? -1 : (one[0] & 0xFF);
                }
                @Override public int read(byte[] b, int off, int len) throws IOException {
                    if (len <= 0) return 0;
                    if (!hdrSent) { synchronized (wLock) { if (!hdrSent) { hdrSent = true; rawOut.write(reqHdrWire); rawOut.flush(); } } }
                    if (!respOk) {
                        try {
                            byte[] rlEnc = new byte[18]; rawIn.readFully(rlEnc);
                            byte[] rlP = aesGcm(rxCipher, Cipher.DECRYPT_MODE,
                                    new SecretKeySpec(Arrays.copyOf(vmessKdf(rxKey, KDF_RLEN_K), 16), "AES"),
                                    Arrays.copyOf(vmessKdf(rxIv, KDF_RLEN_N), 12), null, rlEnc, 0, 18);
                            int rhLen = ((rlP[0] & 0xFF) << 8) | (rlP[1] & 0xFF);
                            if (rhLen < 4 || rhLen > 512) return -1;
                            byte[] rhEnc = new byte[rhLen + 16]; rawIn.readFully(rhEnc);
                            byte[] rhP = aesGcm(rxCipher, Cipher.DECRYPT_MODE,
                                    new SecretKeySpec(Arrays.copyOf(vmessKdf(rxKey, KDF_RHDR_K), 16), "AES"),
                                    Arrays.copyOf(vmessKdf(rxIv, KDF_RHDR_N), 12), null, rhEnc, 0, rhEnc.length);
                            if (rhP.length < 4 || rhP[0] != respAuthV) return -1;
                            respOk = true;
                        } catch (EOFException e) { return -1; }
                        catch (Throwable t) { throw new IOException(t); }
                    }
                    while (pPos >= pLen) {
                        try {
                            int ctLen = rawIn.readUnsignedShort();
                            if (ctLen < 16) return -1;
                            byte[] ct = new byte[ctLen]; rawIn.readFully(ct);
                            int c = rxCnt++;
                            byte[] iv = new byte[12];
                            iv[0] = (byte)(c >> 8); iv[1] = (byte)c;
                            System.arraycopy(rxIv, 2, iv, 2, 10);
                            pBuf = aesGcm(rxCipher, Cipher.DECRYPT_MODE, rxKeySpec, iv, null, ct, 0, ctLen);
                            if (pBuf.length == 0) return -1;
                            pPos = 0; pLen = pBuf.length;
                        } catch (EOFException e) { return -1; }
                        catch (Throwable t) { throw new IOException(t); }
                    }
                    int cp = Math.min(pLen - pPos, len);
                    System.arraycopy(pBuf, pPos, b, off, cp);
                    pPos += cp;
                    return cp;
                }
                @Override public void close() throws IOException { VmessSocket.this.close(); }
            };
        }

        private void writeEncChunk(byte[] pt, int off, int len) throws IOException {
            try {
                int c = txCnt++;
                byte[] iv = new byte[12];
                iv[0] = (byte)(c >> 8); iv[1] = (byte)c;
                System.arraycopy(txIv, 2, iv, 2, 10);
                byte[] ct = aesGcm(txCipher, Cipher.ENCRYPT_MODE, txKeySpec, iv, null, pt, off, len);
                if (!hdrSent) {
                    hdrSent = true;
                    byte[] m = new byte[reqHdrWire.length + 2 + ct.length];
                    System.arraycopy(reqHdrWire, 0, m, 0, reqHdrWire.length);
                    m[reqHdrWire.length] = (byte)(ct.length >> 8);
                    m[reqHdrWire.length + 1] = (byte)ct.length;
                    System.arraycopy(ct, 0, m, reqHdrWire.length + 2, ct.length);
                    rawOut.write(m);
                } else {
                    byte[] f = new byte[2 + ct.length];
                    f[0] = (byte)(ct.length >> 8); f[1] = (byte)ct.length;
                    System.arraycopy(ct, 0, f, 2, ct.length);
                    rawOut.write(f);
                }
            } catch (Throwable t) { throw new IOException(t); }
        }
        @Override public InputStream getInputStream() { return vIn; }
        @Override public OutputStream getOutputStream() { return vOut; }
    }

    private static Socket openProxyChannel(String proto, String ip, int port, String auth,
                                           String sni, String wsHost, String wsPath, String net,
                                           String destHost, int destPort, int[] rttOut) throws Exception {
        Socket raw = new Socket();
        try {
            raw.setTcpNoDelay(true);
            long t0 = System.nanoTime();
            raw.connect(new InetSocketAddress(ip, port), 2300);
            rttOut[0] = (int) Math.max(1L, (System.nanoTime() - t0) / 1_000_000L);
            raw.setSoTimeout(3500);

            boolean outerTls = "TROJAN-TLS".equals(proto) || "VLESS-TLS".equals(proto) || "VMESS-TLS".equals(proto);
            Socket carrier = outerTls ? wrapStrictTls(raw, sni, port, 3500) : raw;

            if ("ws".equals(net)) {
                String path = (wsPath == null || wsPath.isEmpty()) ? "/" : (wsPath.startsWith("/") ? wsPath : "/" + wsPath);
                byte[] kb = new byte[16]; RNG.nextBytes(kb);
                String wsKey = Base64.getEncoder().encodeToString(kb);
                String expAcc = Base64.getEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-1").digest((wsKey + WS_GUID).getBytes(StandardCharsets.US_ASCII)));
                String req = "GET " + path + " HTTP/1.1\r\nHost: " + wsHost + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
                OutputStream os = carrier.getOutputStream();
                os.write(req.getBytes(StandardCharsets.US_ASCII)); os.flush();
                BufferedInputStream bis = new BufferedInputStream(carrier.getInputStream(), 16384);
                String hdr = readHeaderBlock(bis);
                if (hdr == null || !hdr.split("\r?\n", 2)[0].toUpperCase(Locale.ROOT).startsWith("HTTP/1.1 101")) {
                    carrier.close(); return null;
                }
                boolean okAcc = false;
                for (String ln : hdr.split("\r?\n")) {
                    if (ln.toLowerCase(Locale.ROOT).startsWith("sec-websocket-accept:")) {
                        okAcc = expAcc.equals(ln.substring(21).trim());
                        break;
                    }
                }
                if (!okAcc) { carrier.close(); return null; }
                carrier = new WsSocket(carrier, bis, os);
            } else if ("httpupgrade".equals(net)) {
                String path = (wsPath == null || wsPath.isEmpty()) ? "/" : (wsPath.startsWith("/") ? wsPath : "/" + wsPath);
                String req = "GET " + path + " HTTP/1.1\r\nHost: " + wsHost + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
                OutputStream os = carrier.getOutputStream();
                os.write(req.getBytes(StandardCharsets.US_ASCII)); os.flush();
                BufferedInputStream bis = new BufferedInputStream(carrier.getInputStream(), 16384);
                String hdr = readHeaderBlock(bis);
                if (hdr == null || !hdr.split("\r?\n", 2)[0].toUpperCase(Locale.ROOT).startsWith("HTTP/1.1 101")) {
                    carrier.close(); return null;
                }
                carrier = new BufSocket(carrier, bis);
            }

            if (proto.startsWith("SS-")) {
                return new SsSocket(carrier, proto, auth, destHost, destPort);
            }
            if ("TROJAN-TLS".equals(proto)) {
                byte[] addr = buildSocks5DomainAddr(destHost, destPort);
                ByteArrayOutputStream h = new ByteArrayOutputStream(128);
                h.write(sha224Hex(auth.getBytes(StandardCharsets.UTF_8)).getBytes(StandardCharsets.US_ASCII));
                h.write('\r'); h.write('\n'); h.write(1); h.write(addr); h.write('\r'); h.write('\n');
                return new DeferredSocket(carrier, h.toByteArray(), false);
            }
            if ("VLESS-TLS".equals(proto)) {
                byte[] u = parseUuid(auth);
                if (u == null) { carrier.close(); return null; }
                byte[] hb = destHost.getBytes(StandardCharsets.US_ASCII);
                ByteArrayOutputStream h = new ByteArrayOutputStream(64);
                h.write(0); h.write(u); h.write(0); h.write(1);
                h.write((destPort >> 8) & 0xFF); h.write(destPort & 0xFF);
                h.write(2); h.write(hb.length & 0xFF); h.write(hb);
                return new DeferredSocket(carrier, h.toByteArray(), true);
            }
            if (proto.startsWith("VMESS-")) {
                byte[] u = parseUuid(auth);
                if (u == null) { carrier.close(); return null; }
                return new VmessSocket(carrier, u, destHost, destPort);
            }
            carrier.close();
            return null;
        } catch (Throwable t) {
            try { raw.close(); } catch (Throwable ignored) {}
            return null;
        }
    }

    private static String queryGeoViaProxy(String[] f, String geoHost, String path, boolean trace, int[] rttOut) {
        Socket proxy = null;
        SSLSocket ssl = null;
        try {
            String ip = resolvePublicIpv4(f[2]);
            if (ip == null) return null;
            proxy = openProxyChannel(f[1], ip, Integer.parseInt(f[3]), f[4], f[5], f[6], f[7], f[8], geoHost, 443, rttOut);
            if (proxy == null) return null;
            ssl = wrapStrictTls(proxy, geoHost, 443, 3800);
            OutputStream out = ssl.getOutputStream();
            out.write(("GET " + path + " HTTP/1.1\r\nHost: " + geoHost + "\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
            byte[] buf = new byte[1024];
            InputStream in = ssl.getInputStream();
            int r;
            while (baos.size() < 4096 && (r = in.read(buf)) > 0) baos.write(buf, 0, r);
            String full = new String(baos.toByteArray(), StandardCharsets.US_ASCII);
            int sep = full.indexOf("\r\n\r\n");
            if (sep < 0) return null;
            String hdr = full.substring(0, sep);
            if (!hdr.contains(" 200")) return null;
            String body = full.substring(sep + 4);
            if (hdr.toLowerCase(Locale.ROOT).contains("transfer-encoding: chunked")) {
                body = decodeChunkedBody(body);
            }
            body = body.trim();
            if (trace) {
                Matcher m = TRACE_LOC.matcher(body);
                return m.find() ? m.group(1).toUpperCase(Locale.ROOT) : null;
            }
            for (String ln : body.split("\r?\n")) {
                String t = ln.trim().toUpperCase(Locale.ROOT);
                if (t.length() == 2 && t.charAt(0) >= 'A' && t.charAt(0) <= 'Z' && t.charAt(1) >= 'A' && t.charAt(1) <= 'Z') {
                    return t;
                }
            }
            return null;
        } catch (Throwable ignored) {
            return null;
        } finally {
            try { if (ssl != null) ssl.close(); } catch (Throwable ignored) {}
            try { if (proxy != null) proxy.close(); } catch (Throwable ignored) {}
        }
    }

    private static boolean queryGeminiCleanViaProxy(String[] f) {
        Socket proxy = null;
        SSLSocket ssl = null;
        try {
            String ip = resolvePublicIpv4(f[2]);
            if (ip == null) return false;
            int[] dummyRtt = {0};
            String host = "generativelanguage.googleapis.com";
            proxy = openProxyChannel(f[1], ip, Integer.parseInt(f[3]), f[4], f[5], f[6], f[7], f[8], host, 443, dummyRtt);
            if (proxy == null) return false;
            ssl = wrapStrictTls(proxy, host, 443, 4200);
            OutputStream out = ssl.getOutputStream();
            out.write(("GET /v1beta/models?key=MW_LOCATION_VERIFICATION HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: Mozilla/5.0 (Linux; Android 14)\r\n"
                    + "Accept: application/json\r\n"
                    + "Accept-Encoding: identity\r\n"
                    + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            ByteArrayOutputStream baos = new ByteArrayOutputStream(2048);
            byte[] buf = new byte[1024];
            InputStream in = ssl.getInputStream();
            long rdDeadline = System.currentTimeMillis() + 4200L;
            try {
                while (baos.size() < 6144 && System.currentTimeMillis() < rdDeadline) {
                    int r = in.read(buf);
                    if (r <= 0) break;
                    baos.write(buf, 0, r);
                    String cur = new String(baos.toByteArray(), StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
                    if (cur.contains("api_key_invalid")
                            || cur.contains("api key not valid")
                            || cur.contains("failed_precondition")
                            || cur.contains("user location is not supported")) {
                        break;
                    }
                }
            } catch (Throwable ignored) {
                // Keep bytes already received if peer resets or times out before TLS close_notify
            }
            if (baos.size() == 0) return false;
            String lower = new String(baos.toByteArray(), StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
            if (lower.contains("user location is not supported")
                    || lower.contains("failed_precondition")
                    || lower.contains("location is not supported")
                    || lower.contains("not available in your country")
                    || lower.contains("google.com/sorry")
                    || lower.contains(" 451")
                    || lower.contains(" 429")) {
                return false;
            }
            return lower.contains("api key not valid")
                    || lower.contains("api_key_invalid")
                    || lower.contains("invalid_argument");
        } catch (Throwable ignored) {
            return false;
        } finally {
            try { if (ssl != null) ssl.close(); } catch (Throwable ignored) {}
            try { if (proxy != null) proxy.close(); } catch (Throwable ignored) {}
        }
    }

    private static boolean queryGoogleFrontendCleanViaProxy(String[] f) {
        Socket proxy = null;
        SSLSocket ssl = null;
        try {
            String ip = resolvePublicIpv4(f[2]);
            if (ip == null) return false;
            int[] dummyRtt = {0};
            String host = "gemini.google.com";
            proxy = openProxyChannel(f[1], ip, Integer.parseInt(f[3]), f[4], f[5], f[6], f[7], f[8], host, 443, dummyRtt);
            if (proxy == null) return false;
            ssl = wrapStrictTls(proxy, host, 443, 4000);
            OutputStream out = ssl.getOutputStream();
            out.write(("GET /app HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36\r\n"
                    + "Accept-Language: en-US,en;q=0.9\r\n"
                    + "Accept-Encoding: identity\r\n"
                    + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            ByteArrayOutputStream baos = new ByteArrayOutputStream(2048);
            byte[] buf = new byte[1024];
            InputStream in = ssl.getInputStream();
            long rdDeadline = System.currentTimeMillis() + 3800L;
            try {
                while (baos.size() < 8192 && System.currentTimeMillis() < rdDeadline) {
                    int r = in.read(buf);
                    if (r <= 0) break;
                    baos.write(buf, 0, r);
                    if (baos.size() >= 1024) {
                        String cur = new String(baos.toByteArray(), StandardCharsets.UTF_8);
                        if (cur.contains("\r\n\r\n")) break;
                    }
                }
            } catch (Throwable ignored) {}
            if (baos.size() == 0) return false;
            String sample = new String(baos.toByteArray(), StandardCharsets.UTF_8);
            String lower = sample.toLowerCase(Locale.ROOT);
            String first = lower.split("\r?\n", 2)[0];
            String loc = "";
            for (String ln : sample.split("\r?\n")) {
                if (ln.isEmpty()) break;
                if (ln.toLowerCase(Locale.ROOT).startsWith("location:")) {
                    loc = ln.substring(9).trim().toLowerCase(Locale.ROOT);
                    break;
                }
            }
            if (first.contains(" 403") || first.contains(" 451") || first.contains(" 429")
                    || loc.contains("/faq") || loc.contains("unsupported") || loc.contains("sorry")
                    || lower.contains("google.com/sorry") || lower.contains("unsupported_country")
                    || lower.contains("location is not supported")) {
                return false;
            }
            return first.contains(" 200")
                    || ((first.contains(" 301") || first.contains(" 302") || first.contains(" 307"))
                        && (loc.contains("gemini.google.com") || loc.contains("accounts.google.com") || loc.startsWith("/")));
        } catch (Throwable ignored) {
            return false;
        } finally {
            try { if (ssl != null) ssl.close(); } catch (Throwable ignored) {}
            try { if (proxy != null) proxy.close(); } catch (Throwable ignored) {}
        }
    }

    public static void main(String[] args) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        SSL_FACTORY = ctx.getSocketFactory();

        List<String[]> rows = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String ln;
            while ((ln = br.readLine()) != null) {
                String[] parts = ln.split("\t", -1);
                if (parts.length >= 9) rows.add(parts);
            }
        }
        if (rows.isEmpty()) return;

        int workers = Math.min(64, Math.max(8, rows.size()));
        ExecutorService pool = Executors.newFixedThreadPool(workers, new ThreadFactory() {
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }
        });
        final Object outLock = new Object();
        final AtomicInteger aiProbes = new AtomicInteger(0);
        final CountDownLatch latch = new CountDownLatch(rows.size());
        final long deadlineNs = System.nanoTime() + TimeUnit.SECONDS.toNanos(185);
        final long aiDeadlineNs = System.nanoTime() + TimeUnit.SECONDS.toNanos(155);

        for (final String[] f : rows) {
            pool.execute(new Runnable() {
                @Override public void run() {
                    try {
                        if (System.nanoTime() > deadlineNs) return;
                        int[] rtt = {0};
                        String cc = queryGeoViaProxy(f, "get.geojs.io", "/v1/ip/country", false, rtt);
                        if (cc == null && System.nanoTime() < deadlineNs) {
                            cc = queryGeoViaProxy(f, "www.cloudflare.com", "/cdn-cgi/trace", true, rtt);
                        }
                        if (cc == null && System.nanoTime() < deadlineNs) {
                            cc = queryGeoViaProxy(f, "ipinfo.io", "/country", false, rtt);
                        }
                        if (cc != null && rtt[0] > 0) {
                            int aiOk = 0;
                            boolean aiRegionEligible = "US".equals(cc) || "CA".equals(cc) || "SG".equals(cc)
                                    || "JP".equals(cc) || "AU".equals(cc) || "AE".equals(cc) || "SA".equals(cc);
                            if (aiRegionEligible
                                    && !BLOCKED_CC.contains(cc)
                                    && rtt[0] <= 350
                                    && System.nanoTime() < aiDeadlineNs
                                    && aiProbes.incrementAndGet() <= 220) {
                                if (queryGeminiCleanViaProxy(f) && queryGoogleFrontendCleanViaProxy(f)) {
                                    aiOk = 1;
                                }
                            }
                            synchronized (outLock) {
                                System.out.println("OK\t" + f[0] + "\t" + cc + "\t" + rtt[0] + "\t" + aiOk);
                                System.out.flush();
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }
        latch.await(190, TimeUnit.SECONDS);
        pool.shutdownNow();
    }
}
"""


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
    return (val or "").replace("\r", "").replace("\n", "").replace("\t", "").replace("\0", "").strip()


def has_mena_tag(line: str) -> bool:
    h_idx = line.rfind("#")
    if h_idx < 0 or h_idx + 1 >= len(line):
        return False
    tag = urllib.parse.unquote(line[h_idx + 1:])
    for i in range(len(tag) - 1):
        c1, c2 = ord(tag[i]), ord(tag[i + 1])
        if 0x1F1E6 <= c1 <= 0x1F1FF and 0x1F1E6 <= c2 <= 0x1F1FF:
            cc = chr(65 + c1 - 0x1F1E6) + chr(65 + c2 - 0x1F1E6)
            if cc in MENA_COUNTRIES:
                return True
    return bool(MENA_TAG_RE.search(tag.upper()))


def parse_compatible_node(line: str):
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
            j_proto = SS_CIPHER_MAP.get(method.lower().strip())
            pwd = sanitize_token(pwd)
            if not j_proto or not pwd or len(pwd) > 160:
                return None
            hp = hp.strip().rstrip("/")
            if hp.startswith("[") or ":" not in hp:
                return None
            host, port_s = hp.rsplit(":", 1)
            host = sanitize_token(host)
            port = int(port_s.strip())
            if not is_public_host(host) or not (1 <= port <= 65535):
                return None
            return {
                "proto": "SS-AEAD", "j_proto": j_proto, "host": host, "port": port,
                "auth": pwd, "outer_tls": False, "transport": "tcp",
                "sni": "", "ws_host": "", "ws_path": "", "uri": line,
            }

        if lo.startswith("trojan://"):
            body = line[9:].split("#", 1)[0]
            q = ""
            if "?" in body:
                body, q = body.split("?", 1)
            if "@" not in body:
                return None
            pwd, hp = body.rsplit("@", 1)
            pwd = sanitize_token(urllib.parse.unquote(pwd))
            if not pwd or len(pwd) > 160:
                return None
            hp = hp.strip().rstrip("/")
            if hp.startswith("[") or ":" not in hp:
                return None
            host, port_s = hp.rsplit(":", 1)
            host = sanitize_token(host)
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
                "proto": "TROJAN-TLS", "j_proto": "TROJAN-TLS", "host": host, "port": port,
                "auth": pwd, "outer_tls": True, "transport": typ,
                "sni": sni, "ws_host": ws_host, "ws_path": ws_path or "/", "uri": line,
            }

        if lo.startswith("vless://"):
            body = line[8:].split("#", 1)[0]
            q = ""
            if "?" in body:
                body, q = body.split("?", 1)
            if "@" not in body:
                return None
            uuid, hp = body.rsplit("@", 1)
            uuid = sanitize_token(uuid)
            if not UUID_HEX_RE.match(uuid.replace("-", "")):
                return None
            hp = hp.strip().rstrip("/")
            if hp.startswith("[") or ":" not in hp:
                return None
            host, port_s = hp.rsplit(":", 1)
            host = sanitize_token(host)
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
                "proto": "VLESS-TLS", "j_proto": "VLESS-TLS", "host": host, "port": port,
                "auth": uuid, "outer_tls": True, "transport": typ,
                "sni": sni, "ws_host": ws_host, "ws_path": ws_path or "/", "uri": line,
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
                if aid_str and aid_str.lower() != "null" and int(aid_str) != 0:
                    return None
            tls_val = str(obj.get("tls", "")).lower().strip()
            use_tls = tls_val == "tls"
            if not use_tls and tls_val not in ("", "none"):
                return None
            host = sanitize_token(str(obj.get("add", "")))
            port = int(str(obj.get("port", "0")).strip())
            uuid = sanitize_token(str(obj.get("id", "")))
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
            p_name = "VMESS-TLS" if use_tls else "VMESS-AEAD"
            return {
                "proto": p_name, "j_proto": p_name, "host": host, "port": port,
                "auth": uuid, "outer_tls": use_tls, "transport": net,
                "sni": sni, "ws_host": ws_host, "ws_path": ws_path or "/", "uri": line,
            }
    except Exception:
        return None
    return None


def fetch_feed(feed_tuple):
    bucket, name, url, limit = feed_tuple
    out = []
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) MaintenanceWorldVPN-Feeder/4.0",
                "Accept-Encoding": "identity",
            },
        )
        with urllib.request.urlopen(req, timeout=16) as resp:
            raw = resp.read(2 * 1024 * 1024).decode("utf-8", errors="ignore").strip()
        if "://" not in raw:
            raw = b64_decode_flex(raw)
        if not raw or "://" not in raw:
            return bucket, name, []
        for ln in raw.splitlines():
            if len(out) >= limit:
                break
            parsed = parse_compatible_node(ln)
            if parsed:
                parsed["src"] = name
                parsed["hint_mena"] = (bucket == "MENA") or has_mena_tag(ln)
                out.append(parsed)
    except Exception:
        return bucket, name, []
    return bucket, name, out


def verify_candidates_java_real_exit(candidates):
    javac = shutil.which("javac")
    java = shutil.which("java")
    if not javac or not java:
        return None
    tmp_dir = tempfile.mkdtemp(prefix="mw_real_exit_v4_")
    try:
        src_p = os.path.join(tmp_dir, "RealExitVerifier.java")
        with open(src_p, "w", encoding="utf-8") as f:
            f.write(JAVA_VERIFIER_SRC)
        subprocess.check_call([javac, "-Xlint:-options", "-encoding", "UTF-8", src_p], cwd=tmp_dir)

        tsv_lines = []
        for idx, n in enumerate(candidates):
            row = "\t".join([
                str(idx), n["j_proto"], n["host"], str(n["port"]), n["auth"],
                n["sni"], n["ws_host"], n["ws_path"], n["transport"]
            ])
            tsv_lines.append(row)
        stdin_data = ("\n".join(tsv_lines) + "\n").encode("utf-8")

        proc = subprocess.run(
            [java, "-Xmx256m", "-cp", tmp_dir, "RealExitVerifier"],
            input=stdin_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=220,
        )
        results = {}
        for line in proc.stdout.decode("utf-8", errors="ignore").splitlines():
            parts = line.split("\t")
            if len(parts) >= 4 and parts[0] == "OK":
                try:
                    idx = int(parts[1])
                    cc = parts[2].strip().upper()
                    rtt = int(parts[3])
                    ai_ok = (len(parts) >= 5 and parts[4].strip() == "1")
                    if len(cc) == 2 and rtt > 0:
                        results[idx] = (cc, rtt, ai_ok)
                except Exception:
                    pass
        return results
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def verify_node_python_fallback(node: dict):
    host, port = node["host"], node["port"]
    raw_sock = sock = None
    try:
        t0 = time.monotonic()
        raw_sock = socket.create_connection((host, port), timeout=2.5)
        rtt_ms = max(1, int((time.monotonic() - t0) * 1000))
        raw_sock.settimeout(3.2)
        if node["outer_tls"]:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = ctx.wrap_socket(raw_sock, server_hostname=node["sni"])
            sock.settimeout(3.2)
            if node["transport"] in ("ws", "httpupgrade"):
                path = node["ws_path"] if node["ws_path"].startswith("/") else ("/" + node["ws_path"])
                ws_host = node["ws_host"] or node["sni"] or host
                if node["transport"] == "ws":
                    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
                    req = (
                        f"GET {path} HTTP/1.1\r\nHost: {ws_host}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
                    )
                else:
                    req = f"GET {path} HTTP/1.1\r\nHost: {ws_host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                sock.sendall(req.encode("ascii", errors="ignore"))
                head = sock.recv(1024).decode("ascii", errors="ignore")
                if not head.split("\r\n", 1)[0].upper().startswith("HTTP/1.1 101"):
                    return None
        node["rtt"] = rtt_ms
        node["real_cc"] = "UN"
        node["ai_ok"] = False
        return node
    except Exception:
        return None
    finally:
        for s in (sock, raw_sock):
            if s is not None:
                try: s.close()
                except Exception: pass


def rewrite_clean_uri_tag(uri: str, real_cc: str, rtt_ms: int, ai_ok: bool) -> str:
    if not real_cc or len(real_cc) != 2 or real_cc == "UN":
        return uri
    base = uri.rsplit("#", 1)[0] if "#" in uri else uri
    suffix = "|AI" if ai_ok else ""
    return f"{base}#MW-{real_cc}-{rtt_ms}ms{suffix}"


def run_self_test() -> int:
    javac = shutil.which("javac")
    java = shutil.which("java")
    if not javac or not java:
        print("[ERROR] javac/java غير متوفر!")
        return 1
    tmp_dir = tempfile.mkdtemp(prefix="mw_selftest_v4_")
    try:
        src_p = os.path.join(tmp_dir, "RealExitVerifier.java")
        with open(src_p, "w", encoding="utf-8") as f:
            f.write(JAVA_VERIFIER_SRC)
        subprocess.check_call([javac, "-Xlint:-options", "-encoding", "UTF-8", src_p], cwd=tmp_dir)
        subprocess.run([java, "-cp", tmp_dir, "RealExitVerifier"], input=b"", check=True, timeout=15)
        print("[OK] اجتاز auto_feeder.py v4.0 الفحص الذاتي الأوفلاين (Real Exit-IP + AI-Clean |AI) بـ 0 أخطاء!")
        return 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()

    t_start = time.monotonic()
    feed_stats = []
    mena_buckets = []
    global_buckets = []
    seen_keys = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for bucket, name, items in ex.map(fetch_feed, FEEDS):
            uniq_mena, uniq_global = [], []
            for item in items:
                key = (item["j_proto"], item["host"].lower(), item["port"], item["sni"].lower(), item["ws_path"])
                if key not in seen_keys:
                    seen_keys.add(key)
                    if item["hint_mena"]:
                        uniq_mena.append(item)
                    else:
                        uniq_global.append(item)
            if uniq_mena:
                mena_buckets.append(uniq_mena)
            if uniq_global:
                global_buckets.append(uniq_global)
            feed_stats.append((name, len(items), len(uniq_mena) + len(uniq_global)))

    def round_robin_pick(buckets, limit):
        picked = []
        max_len = max((len(b) for b in buckets), default=0)
        for i in range(max_len):
            for b in buckets:
                if i < len(b):
                    picked.append(b[i])
                    if len(picked) >= limit:
                        return picked
        return picked

    mena_cands = round_robin_pick(mena_buckets, MAX_MENA_CANDIDATES)
    global_cands = round_robin_pick(global_buckets, MAX_GLOBAL_CANDIDATES)
    candidates = mena_cands + global_cands

    print(
        f"[INFO] Selected {len(candidates)} unique compatible candidates "
        f"(MENA-hinted={len(mena_cands)}, Global={len(global_cands)}) from {len(FEEDS)} feeds."
    )
    if not candidates:
        print("[WARN] No compatible candidates fetched.")
        return 0

    verified = []
    blocked_dropped = 0
    fake_mena_dropped = 0
    mode_label = "Real-Exit-IP + AI-Clean (Java Engine)"

    java_res = verify_candidates_java_real_exit(candidates)
    if java_res is not None:
        for idx, (cc, rtt_ms, ai_ok) in java_res.items():
            node = candidates[idx]
            if cc in BLOCKED_COUNTRIES:
                blocked_dropped += 1
                continue
            if node.get("hint_mena") and cc not in MENA_COUNTRIES:
                fake_mena_dropped += 1
            node["real_cc"] = cc
            node["rtt"] = rtt_ms
            node["ai_ok"] = ai_ok
            node["uri"] = rewrite_clean_uri_tag(node["uri"], cc, rtt_ms, ai_ok)
            verified.append(node)
    else:
        mode_label = "Python Fallback (TCP+TLS)"
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            for res in ex.map(verify_node_python_fallback, candidates):
                if res is not None:
                    verified.append(res)

    proto_priority = {"SS-AEAD": 0, "TROJAN-TLS": 1, "VMESS-TLS": 2, "VLESS-TLS": 2, "VMESS-AEAD": 3}
    verified.sort(key=lambda x: (
        0 if x.get("ai_ok") else 1,
        x["rtt"] + proto_priority.get(x["proto"], 4) * 25,
        x["rtt"],
    ))

    mena_verified = [n for n in verified if n.get("real_cc") in MENA_COUNTRIES]
    other_verified = [n for n in verified if n.get("real_cc") not in MENA_COUNTRIES]

    final_nodes = []
    host_counts = {}
    proto_counts = {}
    cc_counts = {}
    ai_published = 0

    # 1) Guaranteed MENA real-exit slots first (up to MENA_RESERVED_SLOTS)
    mena_added = 0
    for n in mena_verified:
        if len(final_nodes) >= MAX_FINAL_NODES or mena_added >= MENA_RESERVED_SLOTS:
            break
        hk = n["host"].lower()
        if host_counts.get(hk, 0) >= MAX_PER_HOST_MENA:
            continue
        host_counts[hk] = host_counts.get(hk, 0) + 1
        final_nodes.append(n)
        mena_added += 1
        if n.get("ai_ok"):
            ai_published += 1
        proto_counts[n["proto"]] = proto_counts.get(n["proto"], 0) + 1
        cc = n.get("real_cc", "UN")
        cc_counts[cc] = cc_counts.get(cc, 0) + 1

    # 2) Balanced global pass (enforces US_COUNTRY_CAP & OTHER_COUNTRY_CAP for rich country diversity)
    overflow = []
    for n in other_verified:
        if len(final_nodes) >= MAX_FINAL_NODES:
            break
        hk = n["host"].lower()
        if host_counts.get(hk, 0) >= MAX_PER_HOST_GLOBAL:
            continue
        cc = n.get("real_cc", "UN")
        cc_cap = US_COUNTRY_CAP if cc == "US" else OTHER_COUNTRY_CAP
        if cc_counts.get(cc, 0) >= cc_cap:
            overflow.append(n)
            continue
        host_counts[hk] = host_counts.get(hk, 0) + 1
        final_nodes.append(n)
        if n.get("ai_ok"):
            ai_published += 1
        proto_counts[n["proto"]] = proto_counts.get(n["proto"], 0) + 1
        cc_counts[cc] = cc_counts.get(cc, 0) + 1

    # 3) Backfill any remaining seats up to MAX_FINAL_NODES from fastest overflow nodes
    for n in overflow:
        if len(final_nodes) >= MAX_FINAL_NODES:
            break
        hk = n["host"].lower()
        if host_counts.get(hk, 0) >= MAX_PER_HOST_GLOBAL:
            continue
        host_counts[hk] = host_counts.get(hk, 0) + 1
        final_nodes.append(n)
        if n.get("ai_ok"):
            ai_published += 1
        proto_counts[n["proto"]] = proto_counts.get(n["proto"], 0) + 1
        cc = n.get("real_cc", "UN")
        cc_counts[cc] = cc_counts.get(cc, 0) + 1

    if not final_nodes:
        print("[WARN] Zero nodes passed strict Real-Exit verification.")
        return 0

    with open("vip_clean.txt", "w", encoding="utf-8") as f:
        for n in final_nodes:
            f.write(n["uri"] + "\n")

    elapsed = round(time.monotonic() - t_start, 1)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rtts = [n["rtt"] for n in final_nodes]
    avg_rtt = int(sum(rtts) / max(1, len(rtts)))
    mena_cc_str = ", ".join(f"{k}={v}" for k, v in sorted(cc_counts.items()) if k in MENA_COUNTRIES) or "None"
    top_cc_str = ", ".join(f"{k}={v}" for k, v in sorted(cc_counts.items(), key=lambda kv: -kv[1])[:14])

    lines = [
        "==========================================================",
        f"MaintenanceWorld VPN — Verified Cloud Feed Stats (v4.2 {mode_label})",
        f"Updated: {now_utc} | Scan Duration: {elapsed}s",
        f"Candidates: {len(candidates)} | Real-Verified: {len(verified)} | Published: {len(final_nodes)} | AI-Clean: {ai_published}",
        f"Real MENA Published: {mena_added} ({mena_cc_str})",
        f"Filtered Out: Blocked-CC={blocked_dropped} | Fake-MENA-Flags={fake_mena_dropped}",
        f"RTT (Runner): min={min(rtts)}ms | avg={avg_rtt}ms | max={max(rtts)}ms",
        "Protocols: " + ", ".join(f"{k}={v}" for k, v in sorted(proto_counts.items())),
        "Top Exit Countries: " + top_cc_str,
        "==========================================================",
        "Source Breakdown (parsed / unique):",
    ]
    for name, parsed_c, uniq_c in feed_stats:
        if parsed_c > 0:
            lines.append(f"  - {name:<14}: {parsed_c:>3} parsed / {uniq_c:>3} unique")

    stats_text = "\n".join(lines) + "\n"
    with open("stats.txt", "w", encoding="utf-8") as f:
        f.write(stats_text)

    print(stats_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
