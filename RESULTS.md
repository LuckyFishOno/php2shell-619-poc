# CVE-2026-109619 — .54 實機測試結果

最後更新：2026-10-29（Claude）

## 環境

- Target: Ubuntu 24.04, Apache 2.4.58 prefork (MaxRequestWorkers=1)
- PHP: 8.4.26 (from source, `--with-apxs2`, mod_php)
- Config: memory_limit=8M, max_input_vars=1000, use_only_cookies=1,
  use_strict_mode=0, upload_progress.enabled=On, upload_progress.cleanup=On,
  auto_start=Off, sid_length=32, sid_bits_per_character=4, display_errors=On,
  post_max_size=64M
- Toolkit: php2shell third-party exploit toolkit (lab/bookworm profiles)

## 已確認 (純 HTTP)

### 1. UAF 觸發 ✅

Producer (1001 fields + PHPSESSID=\x00 + upload_progress + file + 12MB big):
- max_input_vars Warning → headers sent → Set-Cookie 失敗 → PS(send_cookie)=1 留存
- OOM Fatal → RSHUTDOWN 跳過 → PS globals (id, session_status, send_cookie) dangling

### 2. Stage 1 Heap Leak ✅

Consumer (PHPSESSID + upload_progress + 892 grooming fields + forge):
- Set-Cookie 回傳 **4096 bytes** 的 heap 洩漏資料
- chunk_base 從 2MB-aligned pointer 模式提取 (98+ 次出現)
- 100% 重現率 (每次嘗試都成功)

### 3. Worker Crash ✅

Stage 3 嘗試 (fake HashTable + reference grooming):
- 每次嘗試都造成 Apache child **SIGABRT** (5/5 crashes)
- Error log: `child pid XXXXX exit signal Abort (6), possible coredump`
- 證明 UAF 後的 heap corruption 可被武器化觸發

### 4. PS(send_cookie) 完整機制 — GDB 確認 ✅ (2026-10-29)

使用 targeted line breakpoints (非 awatch) 在 session.c 精確追蹤：

**Producer 序列：**
1. FILE_START: PS(send_cookie)=0 (line 3318)
2. update → initialize: PS(id) val0='\0' → "new ID" branch → PS(send_cookie)=1 (line 457)
3. reset_id → send_cookie: **SG(headers_sent)=1** → 立即返回 FAILURE
4. reset_id 返回 FAILURE → PS(send_cookie) 維持 1
5. initialize 返回 FAILURE → update **忽略**返回值
6. OOM during "big" field → 無 RSHUTDOWN → PS(send_cookie)=1 持續到下一個 request

**Consumer 序列：**
7. PS(id)=同地址 (dangling)，send_cookie=1，len=4096，val0=0x4c ('L')
8. PS(id) 指向 forge 資料 (892 spray fields grooming)
9. val0='L' ≠ '\0' → "new ID" branch **跳過**
10. reset_id: send_cookie=1 → send_cookie(): SG(headers_sent)=0 → **成功**
11. **回傳 4096 bytes heap 資料的 Set-Cookie**
12. PS(send_cookie)=0

**關鍵：** php_rinit_session_globals() (line 108-121) 重置 PS(id)=NULL 但**不重置** PS(send_cookie)。
OOM bailout 發生在 sapi_activate() 期間，zend_activate_modules() (RINIT) **從未被呼叫**，
因此 PS(id) 成為 dangling pointer。Consumer 的 rfc1867 callback 在 session RINIT 之前觸發。

### 5. SG(headers_sent) 初始化順序確認 (2026-10-29)

- `sapi_activate()` line 440: `SG(headers_sent) = 0` — 在 `sapi_read_post_data()` (line 469) **之前**
- Producer 在 rfc1867 callback 中看到 SG(headers_sent)=1 — 因為 max_input_vars Warning 觸發 HTML output
- Consumer 看到 SG(headers_sent)=0 — 乾淨的新 request

### 6. Worker 穩定性確認 (2026-10-29)

- 同一 Apache master 下，chunk_base 在 worker 輪換間**保持不變** (7/7 相同)
- Distance brute-force table (20 cross-restart samples):
  1. dist=+0x2400000 (45%)
  2. dist=-0x1800000 (20%)
  3. dist=-0x200000 (15%)
  4. dist=+0x1800000 (10%)
  5. dist=-0x3800000 (5%)
- 5 個距離覆蓋約 95% 的情況

## 未完成

### Stage 2 (libphp base leak) ❌

- Lab profile (t=443, v=1) 和 bookworm profile (t=406, v=16) 的 grooming 在 .54 上不匹配
- 需要重新校準 stage2_t 和 stage2_v 以配合 .54 的 heap layout
- 掃描了 80 組 (t, v) 組合，均未成功命中 pDestructor offset (0x6F0)
- **替代方案**：用 distance brute-force table 從 chunk_base 推算 libphp_base

### Stage 3 (RCE) ❌

- htdata_offset (fake HashTable 在 chunk 內的位置) 需要 .54 專屬校準
- stage3_pads (producer padding) 可能也需要調整
- Worker 確實 crash，但是 SIGABRT (heap canary 偵測) 而非 controlled execution
- Toolkit 自身聲明: "RCE end-to-end BELUM terbukti di mesin hidup"

**Stage 3 完整分析 (2026-10-30 更新):**

#### rfc1867 callback 流程（源碼確認）

`php_rinit_session(0)` + `php_session_track_init()` **只在** `MULTIPART_EVENT_FILE_START` 觸發 (session.c:3308)：
```
FILE_START (first file only):
  1. php_rinit_session(0) → ZVAL_UNDEF PS(http_session_vars), PS(id)=NULL
  2. PS(id) = progress->sid
  3. PS(send_cookie) = 0
  4. php_session_rfc1867_update → php_session_initialize → track_init → 新 reference
```

`MULTIPART_EVENT_END` (session.c:3368)：
```
if (Z_TYPE(progress->sid) && progress->key.s) {
    if (rfc1867_cleanup=On) → php_session_rfc1867_cleanup → php_session_initialize → track_init
    else → no-op (progress->data UNDEF without FILE_START)
    php_rshutdown_session_globals();  // ← 總是執行
}
```

#### RCE 觸發條件

**Consumer 必須滿足：**
1. 有 PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS form fields（觸發 MULTIPART_EVENT_END 的 rshutdown）
2. **沒有 file fields**（避免 FILE_START 觸發 rinit + track_init）
3. `session.upload_progress.cleanup = Off`（避免 rfc1867_cleanup 呼叫 initialize → track_init）

**觸發路徑（cleanup=Off, 無 file）：**
```
FORMDATA: PHPSESSID → progress->sid set
FORMDATA: upload_progress → progress->key.s set
FORMDATA: fillers, carrier, HT fields → heap grooming
MULTIPART_EVENT_END:
  → rfc1867_cleanup=Off → 跳過 cleanup
  → progress->data UNDEF → 跳過 else branch
  → php_rshutdown_session_globals():
      !Z_ISUNDEF(PS(http_session_vars)) → true (stale from producer)
      zval_ptr_dtor(&PS(http_session_vars))
      → ref at REF_OFFSET (carrier overwritten)
      → fake chain → zif_system → RCE!
```

**cleanup=On 時失敗原因：**
- `php_session_rfc1867_cleanup` (session.c:3211) 呼叫 `php_session_initialize()`
- initialize → `php_session_reset_id()` (PS(send_cookie)=0 → cookie skip → SUCCESS)
- → `php_session_track_init()` → 覆寫 PS(http_session_vars) 為新 reference
- Stale pointer 被摧毀，exploit chain 斷裂

**方案 A 無效：** sapi_add_header_ex 在 Apache2 SAPI 中對 response header 無大小限制，
cookie 不管多長都會成功加入 → reset_id 不會因 header size 失敗。

**方案 B（session file path traversal）：** 待驗證但非主要路徑。

**方案 D（推薦）：將 upload_progress.cleanup 設為 Off**
- 這是唯一確認可行的 RCE 路徑
- .54 目前 cleanup=On（PHP 預設值）
- 需要使用者確認修改

#### ZMM page map 驗證 (2026-10-30)

用 C 程式讀取 `/proc/PID/mem` (worker PID 208670)：
- `mm_heap = 0x727af0a00040`, chunk = 0x727af0a00000 (2MB aligned ✓)
- **Pages 70-101 全部 FREE** — idle 狀態下 page map 完全清空 (zend_mm_shutdown 確認)
- Stale data 保留：REF_OFFSET 0x56380 有非零 bytes `e0 60 a5 f0 7a 72 ...`

**Carrier alignment 分析：**
```
REF_OFFSET = 0x56380 → page 86, in-page offset 896 (0x380)
bin-32: slot 28, remainder 0 ← ALIGNED (reference fits)
bin-40: slot 22, remainder 16 ← NOT aligned for carrier val overlap
```

Carrier 需要 `in-page_offset mod 40 = 24`（val[] 在 zend_string+24）。
896 mod 40 = 16 ≠ 24 → **slot 28 不可用**。

**修正方案：** 將 reference 移至 slot 27 (offset 864)：
- 864 mod 40 = 24 ✓ → bin-40 slot 21 的 val[0] 對齊 reference 起始位址
- 方法：producer stage3_pads 減 1（少一個 bin-32 分配）
- 新 REF_OFFSET = 0x56360

### 9. pDestructor dispatch 路徑（源碼確認 2026-10-30）

**完整 RCE dispatch chain（從 stale reference 到 command execution）：**

```
zval_ptr_dtor(&PS(http_session_vars))           // PS zval type=IS_REFERENCE, value→REF_OFFSET
 → Z_COUNTED = ref at REF_OFFSET                // carrier: gc={rc=1, type_info=0x1A}
 → rc_dtor_func(ref)                            // GC_DELREF: 1→0
 → zend_rc_dtor_func[GC_TYPE(ref)](ref)         // GC_TYPE = 0x1A & 0x0F = 0x0A = IS_REFERENCE
 → zend_reference_destroy(ref)                  // zend_variables.c
    → i_zval_ptr_dtor(&ref->val)                // ref->val: type=IS_ARRAY_EX, value=htdata
    → Z_COUNTED = htdata (fake HashTable)       // GC_DELREF: 1→0
    → rc_dtor_func(htdata)                      // GC_TYPE = 0x07 = IS_ARRAY
    → zend_array_destroy(htdata)                // zend_hash.c:1815
       → ht->pDestructor (=zif_system) != ZVAL_PTR_DTOR (=zval_ptr_dtor)
       → zend_hash_destroy(htdata)              // zend_hash.c:1734
          → HT_HAS_STATIC_KEYS_ONLY (flags=0x10) ✓
          → HT_IS_WITHOUT_HOLES (nNumUsed==nNumOfElements==1) ✓
          → ht->pDestructor(&bucket[0].val)     // 無 Z_TYPE 檢查！
          → zif_system(htdata+0x20)             // bucket[0] at arData=htdata+0x20
             → 讀取 num_args=1 from execute_data+0x2C
             → arg1 zval at execute_data+0x50 → zend_string at htdata+0x80
             → system(command) → **RCE**
```

**關鍵源碼位置：**
- `zend_array_destroy` (zend_hash.c:1815): `if (UNEXPECTED(ht->pDestructor != ZVAL_PTR_DTOR))` → fall through to zend_hash_destroy
- `zend_hash_destroy` (zend_hash.c:1734): STATIC_KEYS + WITHOUT_HOLES → `pDestructor(&p->val)` 無條件呼叫
- `rc_dtor_func` (zend_variables.c): TABLE DISPATCH `zend_rc_dtor_func[GC_TYPE(p)](p)` — 由 GC_TYPE_INFO 低 4 bits 索引
- `zend_reference_destroy`: `i_zval_ptr_dtor(&ref->val)` → 遞迴進入 array path

**Carrier 必要性：**
沒有 carrier，bin-32 zend_string 覆寫 reference 時 gc.type_info = IS_STRING (0x06)。
rc_dtor_func dispatch 到 `zend_string_destroy` 而非 `zend_reference_destroy`，reference chain 斷裂。
Carrier 寫入 gc.type_info = 0x1A (IS_REFERENCE) 保持 chain 完整。

### 7. 修正 sizeof 與 Stage 3 校準 (2026-10-29)

**結構尺寸（源碼 + 編譯確認）：**
- `zend_property_info_source_list` 是 **UNION**（8 bytes），非 struct（16 bytes）
- `sizeof(zend_reference) = 32` → **bin-32**（之前誤判為 40/bin-40）
- `sizeof(zend_array) = 56` → **bin-56**（之前誤判為 64/bin-64）
- pDestructor 在 zend_array offset 48（與 GDB 觀測一致）

**Stage 3 GDB 校準（stage 3 producer，~10 fields）：**
- REF_OFFSET = 0x56380（bin-32 page 86, slot 28/128）
- ARR_OFFSET = 0x58230（bin-56 page 88, slot 10/73）
- ARR_OFFSET 與 stage 1 相同（bin-56 的前置分配相同）
- REF_OFFSET 比 stage 1 低（0x56380 vs 0x93840，因無 1001-field overflow）

### 8. ZMM Shutdown 機制分析 (2026-10-29) — 關鍵突破

**`php_request_shutdown` (main.c:1981) 呼叫：**
```c
shutdown_memory_manager(CG(unclean_shutdown) || !report_memleaks, 0);
//                      ^^^silent                                ^^^full_shutdown=0!
```

**full_shutdown = 0 即使在 OOM 後！** 含義：
- `zend_mm_shutdown(heap, full=false, silent=true)` — 非完全銷毀
- 主 chunk 保留（不 munmap），虛擬位址不變
- `memset(heap->free_slot, 0, ...)` — 清除所有 bin free list
- `memset(p->free_map, 0, sizeof(free_map) + sizeof(map))` — 清除頁面映射
- `free_pages = ZEND_MM_PAGES - ZEND_MM_FIRST_PAGE` — 所有頁標記為 free
- **但頁面資料不清零！** 舊 ref/arr 的 bytes 保留在原位

**對 exploit 的意義：**
1. OOM producer 在 chunk 的固定 offset 寫入 ref + arr
2. zend_mm_shutdown(full=false) 只清 metadata，不碰資料
3. Consumer 的新 request 重用同一 chunk，同一虛擬地址
4. Consumer 的 zend_activate 重建相同的 page→bin 映射（相同啟動程式碼）
5. Consumer 的 multipart 分配可以命中 freed ref 的 bin-32 slot
6. 用 7-byte form value（→ bin-32 zend_string）覆寫 stale ref data → 控制 pointer

**仍待解決：**
- zend_string 的 h 欄位（hash，offset 8）覆蓋 ref->val.value — 需要 h 是有效 pointer
- form value 的 hash 預設 lazy=0 → ref->val.value=0 → SIGSEGV
- form name 的 hash 被計算但高位 bit 強制設 1 → 非有效 userspace 地址
- 需要找到方法使 h 欄位等於 fake HT 地址（或用其他 bin overlap 策略）

## .54 Binary Offsets

```
libphp.so: /usr/lib/apache2/modules/libphp.so (52MB, PHP 8.4.26 compiled)
zif_system:              0x4590A0
zval_ptr_dtor:           0x6386F0
zend_hash_destroy:       0x5eeec0
executor_globals:        0x12f5040
ps_globals:              0x12df660
_efree:                  0x546cb0
_emalloc:                0x546bc0
php_session_initialize:  0x406080
php_session_reset_id:    0x4051b0
```

## ps_globals 結構 Offsets (GDB ptype 確認)

```
PS(id):                  offset 16  (0x10)   — zend_string*
PS(mod):                 offset 80
PS(mod_data):            offset 96
PS(session_status):      offset 104
PS(use_cookies):         offset 347
PS(use_only_cookies):    offset 348
PS(send_cookie):         offset 350 (0x15E)  — bool
PS(rfc1867_cleanup):     offset 433
PS(use_strict_mode):     offset 434
```

## 關鍵發現: max_input_vars 是 Set-Cookie 能否洩漏的關鍵

- Docker lab 的 max_input_vars=1000 (default) → 第 1001 個 field 觸發 Warning → 輸出 HTML → headers sent → php_session_send_cookie 失敗 → PS(send_cookie) 留 1
- .54 原本 max_input_vars=3000 → 1001 個 field 不觸發 Warning → cookie send 成功 → PS(send_cookie) 清 0 → consumer 無 Set-Cookie
- 修正: 設 max_input_vars=1000 → 行為與 Docker 一致 → stage 1 成功

## Request Startup 順序 (PHP 8.4.26 main/main.c)

```
sapi_activate();          // Line 1837 — 讀 POST data，觸發 rfc1867 callbacks
                          //   ↳ sapi_activate line 440: SG(headers_sent) = 0
                          //   ↳ sapi_read_post_data() line 469
php_hash_environment();   // Line 1873
zend_activate_modules();  // Line 1874 — 呼叫所有模組的 RINIT (包含 session)
```

OOM bailout 在 sapi_activate() 期間意味著 zend_activate_modules() (RINIT) **永不執行**
→ PG(modules_activated)=0 → zend_deactivate_modules() (RSHUTDOWN) 也**永不執行**

## Toolkit Stage 3 結構 (chain.py 分析)

```python
# htdata 是 heap 地址，不是 libphp offset
htdata = chunk_base + htdata_offset  # lab: 0x6E0D8, bookworm: 0x690D8

# 167-byte fake HashTable:
#   gc: rc=1, IS_ARRAY
#   arData → htdata + 0x20
#   pDestructor → zif_system (libphp_base + 0x4590A0)
#   execute_data at offset 0x20, zend_string at 0x80 with command

# 55-byte fake reference:
#   IS_REFERENCE, val.value → htdata (fake HT), IS_ARRAY_EX

# Stage 3 producer: PHPSESSID="a"*19 (不是 "\x00")
# Stage 3 consumer: 15 ht copies + 2 ref copies (或 carrier approach)
```

## 檔案

- `full_chain54.py` — 完整鏈路 (SSH assist for stage 2)
- `full_chain54_v2.py` — 修正 ASLR 處理的版本
- `run_toolkit54.py` — 直接用 toolkit Chain class + patched pointer range
- `test_leak54.py` — Stage 1 獨立測試
- `stage1_libphp_scan.py` — 確認 stage 1 leak 中無 libphp pointers
- `stage2_scan54.py` — 掃描 80 組 (t,v)，確認 stage 2 在 .54 上失敗
- `stage3_calibrate.py` — Stage 3 校準 v1 (producer 機制錯誤)
- `stage3_calibrate_v2.py` — Stage 3 校準 v2 (正確 producer，結果全 200 OK)

### Scratchpad 腳本 (暫存，已封存)

- `gdb_sendcookie_return.py` — targeted line breakpoints 追蹤 send_cookie 返回路徑
- `gdb_send_cookie_trace.py` — 原始 awatch 版 GDB trace
- `cookie_content_test.py` — baseline/producer/consumer cookie 測試
- `forge_verify.py` — 證明 forge 內容控制 Set-Cookie
- `leak_sessfile.py` — 確認無 session files 被建立
- `check_worker_stability.py` — chunk_base 跨 worker 穩定性確認
- `distance_survey.py` — 20 cross-restart samples，brute-force table
- `diag_send_cookie.py` — 7 項 PS(send_cookie) 診斷測試
