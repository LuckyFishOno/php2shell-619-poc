# CVE-2026-109619 — PHP Session Upload Progress OOM → RCE

利用 PHP Session Upload Progress 的 OOM（記憶體耗盡）漏洞，
在 session 檔案中保留攻擊者控制的 PHP 程式碼，再搭配第二個漏洞（LFI 或 .htaccess 寫入）
將 session 檔案包含執行，達成遠端程式碼執行。

**已在兩個完全不同的環境上驗證成功：**

| | Target A | Target B |
|---|---|---|
| OS | Ubuntu 24.04 | CentOS 7 |
| PHP | 8.4.26 | 7.4.33 |
| Apache | 2.4.58 | 2.4.6 |
| 協定 | HTTP | HTTPS |
| Session 路徑 | `/var/lib/php/sessions/` | `/var/lib/php/session/` |
| 包含方式 | `.htaccess` auto_prepend_file | LFI (reader.php) |
| 結果 | `uid=33(www-data)` | `uid=48(apache)` |

> 同一個 OOM 原語，不需要任何記憶體位址、不需要 GDB、不需要 debug symbols，
> 跨 PHP 7.x / 8.x、跨作業系統皆可觸發。
>
> 單漏洞驗證路線（透過 GDB 直接劫持記憶體達成 RCE）請參考 [gdb-exploit.md](gdb-exploit.md)。

## 漏洞原理

```
攻擊者 ──POST──▶ PHP (multipart + session upload progress)
                  │
                  ├─ PHP 在 filename 中記錄 session upload progress
                  ├─ POST body 超過 memory_limit → OOM
                  ├─ OOM 阻止 session RSHUTDOWN 執行
                  └─ session 檔案保留在磁碟上，內含 filename 中的 PHP 程式碼
                  
攻擊者 ──GET───▶ 第二個漏洞 include session 檔案
                  │
                  └─ PHP parser 解析到 <?php 標籤 → 執行任意指令 → RCE
```

### 關鍵機制

1. **Session Upload Progress**：PHP 處理 multipart 上傳時，會將上傳進度（包含 filename）
   寫入 session 檔案。攻擊者將 PHP 程式碼放在 filename 中。

2. **OOM 阻止清理**：當 POST body 大小超過 `memory_limit`，PHP 觸發 Fatal Error。
   OOM 發生在 `sapi_activate()` 階段，`zend_activate_modules()`（RINIT）永不執行，
   因此 session 的 RSHUTDOWN 也不執行 — session 檔案不會被刪除。

3. **Session 檔案格式**：保留的 session 檔案是 PHP 序列化格式，
   PHP parser 在遇到 `<?php` 標籤時會直接執行其後的程式碼，
   無論前後有多少序列化資料。

## post_max_size 與 memory_limit 的關係

OOM 觸發的**必要條件**：

```
post_max_size ≥ memory_limit
```

| 設定 | 預設值 | OOM 可否觸發 |
|------|--------|:----------:|
| `post_max_size=8M`, `memory_limit=128M` | PHP 預設 | ✗ 不可能 |
| `post_max_size=256M`, `memory_limit=128M` | 調高 post_max_size | ✓ |
| `post_max_size=8M`, `memory_limit=8M` | .htaccess 降低 memory_limit | ✓ |

**原理**：PHP 在 `sapi_read_post_data()` 階段處理 POST body，但最多只處理
`post_max_size` 大小的資料。若 `post_max_size < memory_limit`，無論攻擊者
傳送多大的 body，PHP 分配的記憶體永遠不會超過 `memory_limit`，OOM 無法觸發。

> Apache 本身會接受任何大小的 request body（已測試 1.2GB 通過），
> 但 PHP 層只處理 `post_max_size` 以內的部分。

### 現實場景的攻擊條件

1. **管理員調高 post_max_size**（如 WordPress 允許大檔案上傳，設為 64M / 128M / 256M）
   → POST body 超過 memory_limit → OOM
2. **AllowOverride All + .htaccess 寫入** → `.htaccess` 設定
   `php_value memory_limit 8M` + `php_value post_max_size 256M` → OOM
3. **PHP 預設** (`post_max_size=8M`, `memory_limit=128M`) → **無法觸發**

### PHP 預設設定參考

```ini
; PHP 預設值（所有版本）
memory_limit = 128M          ; 單一腳本可用記憶體上限
post_max_size = 8M           ; PHP 處理的 POST 資料上限
upload_max_filesize = 2M     ; 單一上傳檔案大小上限
max_file_uploads = 20        ; 同時上傳檔案數上限

; Session Upload Progress（預設全部啟用）
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"

; Session Cookie
session.use_only_cookies = 1  ; 預設只接受 cookie 傳遞 PHPSESSID
session.use_strict_mode = 0   ; 預設接受任意 session ID
```

## 攻擊流程

### 方式一：OOM + LFI（純 HTTP，無需 SSH）

適用於目標存在 Local File Inclusion 漏洞的環境。

```
1. POST multipart → OOM → session 檔案保留（含 PHP code）
2. GET /vuln.php?file=/var/lib/php/session/sess_<SID> → include → RCE
```

**腳本**：`exploit_lfi.py`

```bash
TARGET_HOST=10.0.0.1 TARGET_PORT=443 python3 exploit_lfi.py
```

### 方式二：OOM + .htaccess auto_prepend_file（需 SSH）

適用於有 SSH 存取且 Apache 設定 AllowOverride All 的環境。

```
1. SSH 建立 .htaccess（設定 auto_prepend_file 指向 session 檔案）
2. POST multipart → OOM → session 檔案保留（含 PHP code）
3. GET /any.php → Apache 自動 prepend session 檔案 → RCE
```

**腳本**：
- `http_rce.py` — 目標已調整過 php.ini（post_max_size > memory_limit）
- `http_rce_default.py` — 目標為 stock php.ini，用 .htaccess 同時覆蓋
  memory_limit 和 post_max_size

```bash
TARGET_HOST=10.0.0.1 SSH_USER=admin SSH_PASS=secret python3 http_rce.py
TARGET_HOST=10.0.0.1 SSH_USER=admin SSH_PASS=secret python3 http_rce_default.py
```

### OOM 獨立測試

只測試 OOM 是否能觸發（不嘗試 RCE）：

```bash
TARGET_HOST=10.0.0.1 TARGET_PORT=443 python3 test_oom.py
```

## 環境變數

所有腳本使用環境變數取代硬編碼的主機資訊：

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `TARGET_HOST` | `127.0.0.1` | 目標 IP 或主機名稱 |
| `TARGET_PORT` | `80` 或 `443` | HTTP/HTTPS port |
| `SSH_USER` | `user` | SSH 使用者（需 sudo 權限） |
| `SSH_PASS` | `pass` | SSH 密碼 |

## Session 檔案路徑

不同發行版的 session 儲存路徑不同：

| 發行版 | 路徑 |
|--------|------|
| Debian / Ubuntu | `/var/lib/php/sessions/` |
| CentOS / RHEL | `/var/lib/php/session/` |
| 通用 fallback | `/tmp/` |
| 自訂 | `php.ini` 的 `session.save_path` |

> `phpinfo()` 顯示 `session.save_path` 為 "no value" 時，
> 實際路徑由編譯時預設決定，不一定是 `/tmp/`。

## 檔案結構

```
├── exploit_lfi.py           ← 純 HTTP RCE（OOM + LFI，無需 SSH）
├── http_rce.py              ← HTTP RCE + SSH（lab-tuned php.ini）
├── http_rce_default.py      ← HTTP RCE + SSH（stock php.ini，.htaccess override）
├── test_oom.py          ← 獨立 OOM 觸發測試
├── exploit.py               ← GDB 輔助單漏洞 RCE（詳見 gdb-exploit.md）
├── README.md                ← 本文件（HTTP 雙漏洞路線）
├── gdb-exploit.md           ← GDB 單漏洞路線：記憶體位址解析與 payload 佈局
├── RESULTS.md               ← 實機測試結果
```

## 限制

- **LFI 版本** (`exploit_lfi.py`)：需要目標存在 LFI 向量
- **.htaccess 版本** (`http_rce.py`, `http_rce_default.py`)：需要 SSH + Apache AllowOverride All
- **PHP 預設設定下無法單獨觸發 OOM**：需要 `post_max_size ≥ memory_limit`
- **GDB 版本** (`exploit.py`)：需要 SSH + sudo + debug symbols，詳見 [gdb-exploit.md](gdb-exploit.md)

## 相關 CVE

- **CVE-2026-109619**：PHP Session Upload Progress OOM → session file preservation
