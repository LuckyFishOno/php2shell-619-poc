# 攻擊分析報告 — PHP 7.4 + WordPress (CentOS)

## 目標環境
- PHP 7.4.33, WordPress 6.8.1, Apache 2.4.6 (CentOS), OpenSSL/1.0.2k-fips
- 唯一使用者: louis (author ID 1)
- 插件: Akismet, Elementor free 3.28.4
- 主題: hello-biz 1.1.0
- HTTPS, 無 SSH 存取

## PHP 設定（推斷）
- `post_max_size` = 8M（預設）— 已驗證：>8MB POST 資料被 PHP 忽略
- `memory_limit` ≥ 128M — 無法透過 8MB POST 觸發 OOM
- `max_file_uploads` = 20（預設）
- `max_input_vars` = 1000（預設）
- `session.upload_progress.enabled` = On（預設）

## 攻擊路徑分析

### 1. CVE-2026-109619 (OOM → session file preservation) ❌
**問題**: 無法觸發 OOM
- post_max_size=8M 限制了 PHP 實際處理的 POST 資料量
- Apache 接受任何大小的 body（1.2GB 測試通過），但 PHP 忽略超過 8M 的部分
- 71,816 個 multipart file parts（7.5MB）測試：記憶體放大不足以超過 memory_limit
- 沒有 .htaccess 寫入能力來覆蓋 php_value memory_limit/post_max_size

### 2. CVE-2026-87902 (WordPress LFI) ❌
**問題**: 主題不符前置條件
- hello-biz 主題沒有 `page-*` 目錄
- 此 CVE 需要主題中存在以 "page-" 為前綴的目錄

### 3. CVE-2026-60137 (SQL injection in author__not_in) ❌
**問題**: REST API schema 驗證阻擋
- `author_exclude` 的 scalar string 被 REST API 拒絕（400 Bad Request）
- batch endpoint 在 6.8.x 只接受 GET 子請求
- Elementor site-navigation/recent-posts 接受 post__not_in 但需要驗證（401）
- 所有 Elementor REST endpoints 需要驗證

### 4. CVE-2026-63030 (batch route confusion) ❌
**問題**: 只存在於 WordPress 6.9+
- WordPress 6.8.1 沒有此漏洞

### 5. 密碼爆破 ❌
- wp-login.php POST 表單：570+ 組密碼嘗試，全部失敗
- 包含基於 tagline "Louis_wordpress" 的針對性密碼
- xmlrpc.php 完全無法使用（XML parser 壞掉）

### 6. xmlrpc.php ❌
- 對所有輸入回傳 "parse error. not well formed"
- PHP XML extension 很可能未安裝/損壞（CentOS 最小安裝）

### 7. Elementor 3.28.4 Free ❌
- 所有 REST endpoints 需要驗證
- Free 版本沒有已知的未驗證 RCE/檔案寫入漏洞

### 8. 其他攻擊面
- 檔案探索：無 wp-config 備份、.git、debug.log、SQL dump
- TRACE 方法已啟用但不可用於 RCE
- 註冊已停用
- 留言功能可用但無注入向量
- install.php 顯示「已完成安裝」
- uploads/ 目錄全空
- 無 phpMyAdmin/adminer

## 結論

CVE-2026-109619 是一個 **檔案建立原語**（session file with controlled content）。
將它轉化為 RCE 需要 **第二個漏洞**：

1. **檔案寫入**（.htaccess 覆蓋 php_value auto_prepend_file）— 需要 SSH 或 admin
2. **LFI**（包含 session 檔案）— 此安裝上找不到

在 PHP 預設設定（post_max_size=8M < memory_limit=128M）下，
甚至連 session 檔案保留（第一步 OOM）都無法觸發。

**此目標在純 HTTP 黑盒情境下，使用已知攻擊向量無法達成 RCE。**

### 對比 Target A（成功案例）
| 條件 | Target A (Ubuntu) | Target B (CentOS) |
|------|-------------|--------------|
| SSH 存取 | ✓ | ✗ |
| .htaccess 寫入 | ✓ (via SSH) | ✗ |
| php_value 覆蓋 | ✓ | ✗ |
| OOM 觸發 | ✓ (.htaccess 降低 memory_limit) | ✗ (預設值無法觸發) |
| Session 檔案包含 | ✓ (auto_prepend_file) | ✗ (無法設定) |
