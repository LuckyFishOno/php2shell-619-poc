# PHP2Shell RCE Chain 設計筆記

日期：2026-10-24。供下次 session 直接接續實作。

## 目標

在 172.16.158.133（Ubuntu 26.04 ARM64, Apache 2.4.66, source-compiled PHP 8.1.2）上執行 `cat /etc/os-release > /tmp/p`。

## 環境現況（已確認）

- MaxRequestWorkers=1, memory_limit=128M, ASLR=off
- session.upload_progress.cleanup=Off, save_path=/tmp
- `OnUpdateSaveDir` 已 patch：ACTIVATE/DEACTIVATE 階段跳過 SESSION_CHECK_ACTIVE_STATE
- SEED: 3×8MB filename → session file ~25MB
- ARM: 1×32MB filename → OOM 發生在 multipart parsing / session upload progress decode 階段（`php_request_startup` → `php_hash_environment` → session decode），尚未進入 `php_execute_script`。`zend_bailout()` 回到 `php_request_startup` 的 `zend_catch`，Apache request cleanup 隨後執行 `php_request_shutdown()` → `shutdown_memory_manager(..., 0)` → `zend_mm_shutdown(full=0)` 重設 request allocation state。Context 的 request-owned memory 在 ZendMM reset 時被回收，但 `BG(unserialize).data` 未清（level=1, 不滿足歸零條件）→ 指向 **0xfffff447a000** 的跨 request dangling pointer。`full=0` 保留部分 ZendMM chunk 供後續 request 重用，因此原 context bytes 可能仍留在映射的記憶體中，但不保證所有 chunk 或 pages 都不被 unmap。
- FIRE: `UNSERIALIZE_INIT` 發現 `BG(unserialize).data != NULL` → level 1→2 → reuse 已釋放的 context（**cross-request heap use-after-free**，與 CVE-2026-109619 官方描述一致）。本實驗觀察到原 context bytes 尚未遭覆蓋，但這是觀察結果而非保證。
- 已知地址：LIBC_BASE=0xfffff7b50000, SYSTEM_ADDR=LIBC_BASE+0x4bf90, LIBPHP_BASE=0xfffff6580000
- SID_ARM="u0123456789abcdefghijklmnopqrstuv"

## 已確認的阻塞點

### P1: FIRE 不能用 SID_ARM（已確認）
FIRE 的 upload progress 會 decode 同一 25MB session → 再次 OOM。
**解法**：用獨立 SID_FIRE 搭配預寫的小型 crafted session 檔。

### P2: Spray context 會壞 var_push（已分析）
若 spray 3-page 區塊（reclaim orphan context），zend_string gc 欄位覆蓋 `last` 指標 → `var_push` 讀 `last->used_slots` 時 crash。
**解法**：不 spray context。依賴 `zend_mm_shutdown(full=0)` 只 reset free list 不清零 page 內容，orphan bytes 原封不動（`last = &entries` 在 context+56 仍可讀）。
**風險**：若 FIRE request 的 early-stage emalloc 恰好 reclaim 同一 3-page bin，context 會被覆蓋。MaxRequestWorkers=1 + upload progress 在 sapi_activate 早期 decode 使此可能性極低，但非零。

### P3: entries.data[] 指向什麼（待驗證）
`var_push(rval)` 存的是 `zval*` 指標，不是 copy。指向 stack 或 heap 取決於呼叫者。

以下分組是從 session decode 路徑**推斷**，不是 PHP 固定規則，需 trace 確認：
- data[0], data[3], data[6], data[9] = `&entry`（`php_var_unserialize` 的 stack local）→ 函數返回後 stack frame 失效 → **dangling（use-after-scope）**
- data[1], data[4], data[7] = heap 位址（parent array 的 Bucket->val）→ `zend_mm_shutdown(full=0)` 已標記為 free，但 **bytes 仍在原位**（同 context 本身）
- data[2], data[5], data[8] = heap 位址（file info 子陣列）→ 同上

**重要修正**：先前描述「仍 allocated（OOM 跳過 request_shutdown，heap 不清）」不正確。`php_request_shutdown` 在 OOM bailout 後仍然執行，heap 已被 reset。正確狀態是「已被 zend_mm reset 釋放，但 bytes 未清零」。從 exploit 角度效果相同（bytes 可讀），但 root cause 分類為 heap UAF 而非 memory leak。
- **需加 trace 確認實際值與地址**

### P4: Refcount 問題（已分析）
`r:N` handler 做 `ZVAL_COPY` → 對 fake object gc.refcount +1。若初始 refcount=1，copy 後=2，replacement dtor 只 -1 → 不到 0。
**可行路徑**：
- (a) 初始 refcount=0 → copy 後=1 → dtor 時 1→0 → 但 system("\x00") 無效
- (b) 用 R:N（大寫）→ ZVAL_NEW_REF 包裝 → refcount 設 2 → copy 後 3 → 不到 0
- (c) **最佳方案**：不依賴 refcount 歸零。改為在 session decode 的 **陣列反序列化中用重複 key 觸發 dtor**：
  ```
  upload_progress_fire|a:2:{s:1:"a";r:1;s:1:"a";i:0;}
  ```
  第二個 "a" 覆蓋第一個 → HashTable pDestructor 對舊值呼叫 zval_ptr_dtor。
  舊值 = r:1 解出的 fake zval → IS_OBJECT → GC_DELREF → 若 refcount=1（copy 後）→ 0 → 觸發 destruction！
  **但**：r:1 的 ZVAL_COPY 已讓 refcount +1（fake object 變 2），dtor 只 -1 → 1 → 不到 0。
  **修正**：fake object 初始 refcount=0 → ZVAL_COPY 後=1 → array dtor 時 1→0 → destruction 觸發！→ `system("\x00")` 仍無效。

### P5: system() 引數問題（已分析）
dtor_obj 收到 object pointer。system(object_ptr) 會讀 gc 開頭的 bytes 作為 C 字串。
gc.refcount=0（上面需要的值）→ 首 byte 0x00 → system("") → 無效。
gc.refcount=1 → 首 byte 0x01 → system("\x01") → 需預建 `/usr/local/bin/\x01` 腳本。

**最終方案**：
1. Fake object gc.refcount = 0（讓 ZVAL_COPY 後=1，dtor 時 1→0 觸發）
2. 不行，system("\x00") 無效
3. **改用 refcount=1** + 找方法讓 dtor 時 refcount 已經是 1（不是 2）

**突破口**：如果 r:N 對應的 entries.data[N-1] 本身不是一個被 refcount-tracked 的 zval，而是我們直接控制的 raw bytes：
- entries.data[N-1] 和 data[N] 合起來的 16 bytes 被 var_access 當成一個 zval 返回
- r:N handler 的 ZVAL_COPY 對這 16 bytes 做 copy + addref
- addref 寫入 fake object 的 gc.refcount（在我們控制的記憶體中）
- 初始 refcount=0 → copy 後=1 → 陣列重複 key dtor 時 1→0 → destruction！
- system(object_ptr)：object 首 4 bytes = refcount = 0x00000001（被 addref 改過）→ "\x01\x00\x00\x00" → system("\x01")
- 預建 `/usr/local/bin/$'\x01'` 內含 `#!/bin/sh\ncat /etc/os-release > /tmp/p`

### P6: objects_store.object_buckets 可能 NULL（已分析）
`zend_objects_store_del` 第一行檢查 `object_buckets && IS_OBJ_VALID(buckets[handle])`。
upload progress 在 sapi_activate 階段（zend_activate 之後），EG(objects_store) 已初始化但 object_buckets 可能為 NULL（尚未建立任何 object）。
**解法**：在 crafted session 中先 deserialize 一個 `O:8:"stdClass":0:{}`（var_push 可用，因為 context 未被 spray），讓 objects_store 初始化。stdClass object handle=0。fake object 的 handle 也設 0 → `IS_OBJ_VALID(buckets[0])` 為 true。

但注意：stdClass deserialize 會呼叫 var_push（entries 追加）且 var_push_dtor（dtors 追加），不會 crash（context 原始資料有效）。

## 預計的 Exploit 資料流

```
1. SSH: 預建 /usr/local/bin/$'\x01' 腳本
2. SSH: 寫 /tmp/sess_SIDFIRE：
   "dummy|O:8:"stdClass":0:{}upload_progress_fire|a:2:{s:1:"a";r:N;s:1:"a";i:0;}"
   （N = ARM_used_slots + 2，指向 stdClass push 後、dummy array 的 heap entry）
3. 重啟 Apache, 清 log
4. SEED × 3（填 session for SID_ARM）
5. ARM × 1（OOM → orphan，level=1）
6. FIRE：用 SID_FIRE + PHP_SESSION_UPLOAD_PROGRESS=fire + 2 file parts
   → upload progress opens sess_SIDFIRE
   → decode: stdClass → objects_store 初始化
   → decode: a:2 array with duplicate key "a"
     → r:N → var_access → entries.data[N-1] = controlled heap data
     → ZVAL_COPY（addref）
     → 第二個 "a" 覆蓋 → dtor(old) → zval_ptr_dtor
     → IS_OBJECT → GC_DELREF → 0 → zend_objects_store_del
     → dtor_obj(fake_object) → system("\x01") → 執行腳本
     → /tmp/p 產生
```

## 待驗證事項（下次 session 第一步）

1. **加 trace 到 var_push / var_access**：fprintf entries.data 的實際地址和值
2. **確認 ARM used_slots**：幾個 SEED variable 各 push 幾次
3. **確認 heap entries 指向的記憶體 bytes 是否仍完整**（zend_mm reset 後未被 reclaim/覆蓋）
4. **測試 crafted session with r:N**：先不做 RCE，只看 decode 是否正常走完
5. **確認 stdClass deserialize 在 orphan reuse 時不 crash**
6. **如果 heap entries 內容不可控**：需額外 spray 特定 bin size 來 reclaim

## Context Memory Lifetime — 修正分析（2026-10-24）

在 Apache mod_php 的 request lifecycle 中，OOM 發生在 multipart parsing / session decode 階段。`zend_bailout()` 使 `php_var_unserialize_destroy()` 無法正常執行，`BG(unserialize)` 保留未清理的 context state。

Apache request cleanup 隨後執行 `php_request_shutdown()`，透過 `shutdown_memory_manager(..., 0)` 重設 ZendMM 的 request allocation state。Context 的 request-owned memory 在此時被回收。但 worker global state 繼續保存該地址，形成跨 request 的 dangling pointer。

`full=0` 保留部分 ZendMM chunk 供後續 request 重用，因此已釋放 allocation 的原始 bytes 可能仍留在映射的記憶體中；但不保證所有 chunk 或 pages 都不被 unmap。

Context 內部的 `entries.data[]` 具有獨立的生命週期問題：部分 entry 可能指向已結束的 stack frame（use-after-scope），其他 entry 指向已被 request heap 回收的 heap object（heap UAF）。

| Memory Object | OOM/Shutdown 後 | 問題分類 |
|---|---|---|
| `BG(unserialize)` | global state 未 reset | stale global pointer |
| `php_unserialize_data_t` | request allocation 被 ZendMM 回收 | heap UAF |
| `entries.data[]` stack pointer | 原 stack frame 已失效 | dangling stack reference |
| `entries.data[]` heap pointer | 原 request allocation 被回收 | heap UAF |

**證據層次區分**：
- **已確認原理**：ZendMM request reset 可回收 allocation，同時保留部分底層 chunk（PHP 原始碼 + PHP Internals Book）
- **本實驗觀察**：`BG(unserialize)` 在後續 request 被 reuse，且原 context bytes 尚未遭覆蓋（10/23 instrumented trace）
- **尚待驗證**：context allocation 的實際回收紀錄、各 reference entry 的有效性、FIRE crash 的 faulting instruction

本分析將 CVE-2026-109619 的核心漏洞分類為 **cross-request heap use-after-free**，不再將 context 描述成已確認仍處於 allocated 狀態的 memory leak。個別 entry 的有效性須以實際 trace 為準。

## A/B Runtime Validation Plan — 2026-10-24

### 問題拆分

1. **漏洞存在性（Vulnerability Existence）**：OOM 後是否留下 `BG(unserialize)` 的 stale context？
2. **漏洞可達性（Exploit Reachability）**：後續 request 是否真的能進入使用該 context 的 unserialize 路徑？

這兩個問題需要分開驗證。`OnUpdateSaveDir` patch 不改變 unserialize context 的生命週期，但可能改變後續 session decode 的可達性。

### save_path 與 SID_FIRE 的關係

使用不同的 `SID_FIRE` **不能直接繞過** `save_path` 問題。PHP files handler 用 `save_path` 決定目錄、用 SID 決定檔名：

| FIRE 時的 `save_path` | Session ID | 實際尋找的檔案 |
|---|---|---|
| `/tmp` | `SIDFIRE` | `/tmp/sess_SIDFIRE` |
| `1` | `SIDFIRE` | `1/sess_SIDFIRE` |

關鍵問題是：FIRE request 的 INI activate 是否成功把 `PS(save_path)` 恢復成 `/tmp`。原始 runtime 的 `OnUpdateSaveDir()` 受 `SESSION_CHECK_ACTIVE_STATE` 保護，如果 `PS(session_status)` 殘留異常值，save_path 更新可能被擋。**這是待驗證假設，不是已確認事實。**

### Environment A：Original PHP Runtime

- 未修改的 PHP 8.1.2 source
- 與研究版一致的 Apache config、PHP config、診斷環境
- 驗證項目：
  - OOM 後 `BG(unserialize)` 是否殘留
  - 後續 request 的 `PS(session_status)` 和 `PS(save_path)` 值
  - Session file open 是否成功
  - 後續 decode 是否可達

### Environment B：Patched Research Runtime

- 同一 PHP 8.1.2 source + `OnUpdateSaveDir()` patch（跳過 `SESSION_CHECK_ACTIVE_STATE`）
- 相同 runtime config
- 比較 INI activate/deactivate、session state 與 request lifecycle
- 確認 patch 是否僅改變 session path 更新結果，或同時改變後續執行路徑

### Verification Matrix

| 驗證項目 | Original (A) | Patched (B) |
|---|---|---|
| OOM 後 global state 是否殘留 | 待驗證 | 待核對 trace |
| Request shutdown 是否執行 | 待驗證 | 待驗證 |
| FIRE 時 `PS(save_path)` | 待驗證 | 待驗證 |
| Session file open 是否成功 | 待驗證 | 待驗證 |
| 後續 decode 是否可達 | 待驗證 | 待驗證 |
| Context memory ownership | 待驗證 | 待驗證 |

### 結論判定原則

1. A/B 都存在相同的 stale global state → patch 並非該 state corruption 的必要條件
2. 只有 B 能進入後續 decode → 須確認 `OnUpdateSaveDir()` 對 session path 及 request state 的影響
3. A/B 都能正常執行無害 session decode → 重新檢查 `save_path="1"` 是否取決於特定 request state
4. Memory safety 問題在原始 runtime 成立但特定 consumer path 不可達 → 分別記錄存在性與可達性，不視為等價的 RCE 證據

### 研究線定位

- **主線（A）**：原始 runtime，證明真實漏洞行為
- **研究線（B）**：修改版 runtime，解釋內部機制
- 兩條線都保留，但不混用測試結論
- 目前定位為 CVE-2026-109619 的 root cause 延伸研究，非已發現新 CVE

### 下一步（優先於 payload 調整）

1. 利用既有 GDB / session log 確認 FIRE request 的 `PS(session_status)`、`PS(save_path)` 及實際 session file open 結果
2. 在原始 runtime (A) 上觀察正常 OOM、shutdown、global state reset、context lifetime
3. 比較 A/B 差異後再決定是否需要調整 exploit payload

**目前狀態**：A/B 對照尚未完成。不能宣稱現有 patch 不影響利用可達性，也不能宣稱未修改 runtime 已能重現完整利用鏈。

## 檔案位置

- 工作目錄：`分析/php2shell-poc/`（所有後續開發在此）
- 封存副本：`分析/php2shell/archive/2026-10-24-claude-tmp/`
- target session.c：已 patch OnUpdateSaveDir + fprintf traces（Environment B）
