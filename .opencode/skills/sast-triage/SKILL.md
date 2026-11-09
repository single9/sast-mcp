---
name: SAST Triage
description: Use the local SAST MCP server to scan a repository, triage Semgrep findings against real source code, classify true/false positives, propose minimal fixes, and re-scan. Use when asked to run SAST, do a security scan, review security findings, or harden code quality.
---

# SAST Triage

## 目標

把「掃描」與「判讀」分開：

- **MCP 工具**負責確定性動作：建立掃描、輪詢、查詢、彙總、輸出 SARIF。
- **這個 Skill** 負責工作流程：如何挑範圍、如何驗證 finding、如何分類、如何修、如何證明修好了。

不要把所有 findings 直接倒進上下文，也不要把 Semgrep 的輸出當成最終結論。

## 前置條件

1. SAST 服務必須在跑。先呼叫 `health`。
2. 若 `reachable=false`，請使用者啟動服務：
   - `cd <sast-repo> && make run`
   - 或 `docker compose up -d`
   - 再確認 `SAST_BASE_URL`（預設 `http://127.0.0.1:8000`）。
3. 若 `health.engines` 顯示 `builtin-regex` 為 active，代表 Semgrep 不可用；提醒使用者誤報率會上升。
4. 若 API 回 401，代表服務設定了 `SAST_API_KEY`，MCP server 也必須帶同一組。

## 工具呼叫方式

在 OpenCode Code Mode 中，MCP server `sast` 的工具位於 `tools.sast`：

```js
const h = await tools.sast.health({});
const scan = await tools.sast.scan_path({ path: ".", wait: false });
const done = await tools.sast.wait_for_scan({ scan_id: scan.scan.id, timeout_sec: 300 });
const summary = await tools.sast.summarize_scan({ scan_id: scan.scan.id });
const findings = await tools.sast.get_findings({
  scan_id: scan.scan.id,
  severity: ["critical", "high"],
  limit: 50,
});
```

在其他 MCP 客戶端（Claude Desktop 等）直接呼叫 `health`、`scan_path`、`get_findings` 等工具名稱。

| 目的 | 工具 |
| --- | --- |
| 確認服務與引擎 | `health` |
| 掃描目前專案目錄 | `scan_path` |
| 掃描既有 ZIP | `scan_zip` |
| 掃描公開 Git repo | `scan_git` |
| 等待完成 | `wait_for_scan` |
| 單一掃描狀態 | `get_scan` |
| 最近掃描 | `list_scans` |
| 群組摘要（先看這個） | `summarize_scan` |
| 過濾 findings | `get_findings` |
| 記錄誤報／接受風險／已修補 | `triage_findings` |
| 列出已保存判定 | `list_triage` |
| 移除判定 | `delete_triage`（需 `confirm=true`） |
| 匯出／匯入 baseline | `export_triage` / `import_triage` |
| 輸出 SARIF | `export_sarif` |
| 刪除掃描與工作區 | `delete_scan`（需 `confirm=true`） |

## 工作流程

### 1. 確認範圍

- 預設掃描目前專案：`scan_path({ path: "." })`。
- 只想看某個子系統時，傳子目錄，例如 `path: "src"`；這比掃完整 repo 更快，也減少 noise。
- Git repo 預設只送 tracked + untracked（排除 `.gitignore` 內容）。若懷疑 ignored 檔案有問題，才設 `include_gitignored: true`。
- 需要掃描遠端 repo 時用 `scan_git`；只支援公開 http(s)，不支援 ssh 或帳密。
- **目前沒有 diff / baseline / PR 增量掃描**。要聚焦變更時，掃描受影響的子目錄，並在報告中說明這個限制。

### 2. 建立掃描

```js
const scan = await tools.sast.scan_path({ path: ".", wait: false });
const scanId = scan.scan.id;
```

- 大型專案不要用 `wait: true` 賭單次呼叫不會逾時；先建立，再用 `wait_for_scan`。
- `wait_for_scan` 逾時會回傳 `timed_out: true` 與最後狀態，不是失敗；可以再等一次。
- 若 `scan.status === "failed"`，先讀 `scan.error`，不要直接重試。

### 3. 先摘要，不要先拉明細

```js
const summary = await tools.sast.summarize_scan({ scan_id: scanId, top: 20 });
```

閱讀順序：

1. `scan.stats.files_scanned`：0 或異常少，代表來源、排除規則或語言支援有問題。
2. `scan.stats.languages` / `primary_language_name`：專案實際使用哪些語言；若主要語言不在規則支援範圍，先說明覆蓋率限制。
3. `by_language`：每個語言的 findings 數、severity 分佈、`risk_level` 與熱門規則；先處理風險最高的語言。
4. `scan.severity_counts`：整體風險輪廓。
5. `by_rule`：哪些規則在吵；同一規則大量出現通常是一個系統性問題或一個誤報模式。
6. `by_file`：集中在哪些檔案；優先看生產程式碼。
7. `omitted_rule_groups`：還有多少群組沒顯示，必要時提高 `top`。
8. `by_engine`：區分 `semgrep` / `builtin-regex` / `osv` / `supply-chain`；不要把依賴漏洞與原始碼 pattern 混在一起排序。
9. `dependencies` / `supply_chain`：`lockfiles`、`packages`、`vulnerabilities`、`vulnerable_packages`、`manifests`、`build_scripts`。若 `dependencies.enabled=false`，先確認是設定關閉還是舊掃描沒有這個階段。

### 4. 逐一驗證高風險 finding

對每個 `critical` / `high`（以及被大量重複的 `medium`）：

```js
const page = await tools.sast.get_findings({
  scan_id: scanId,
  severity: ["critical", "high"],
  limit: 50,
});
```

對每一筆：

1. 用 `read` 工具打開 `file`，定位到 `line` 附近，**不要只看 snippet**。
2. 往上看資料來源（request、env、DB、檔案），往下看 sink 與防護。
3. 確認程式碼是否真的會被執行：路由是否註冊、函式是否被呼叫、是否 dead code。
4. 確認是否為測試／範例／fixture：路徑含 `test`、`spec`、`__tests__`、`fixtures`、`examples` 等，仍要確認是否會進生產。
5. 檢查框架或語言層的保護：ORM / prepared statement、輸出 escaping、`shell=False`、`yaml.safe_load`、路徑正規化、auth middleware。
6. 只有在你說得出「為什麼這裡安全」或「為什麼這裡可利用」時才下結論。

需要更多上下文時，再要求 snippet：

```js
const withSnippet = await tools.sast.get_findings({
  scan_id: scanId,
  file_contains: "src/api/login.py",
  include_snippet: true,
  limit: 20,
});
```

Snippet 預設會遮蔽常見憑證樣式。不要要求 `redact_secrets: false`，除非使用者明確同意，而且真的需要看原始值。

### 4a. 依賴漏洞（engine = `osv`）

這類 finding 的 `file` 是 `Cargo.lock`，`line` 指向 `[[package]]` 的 name。判讀方式與原始碼不同：

1. 確認 `dependencies.vulnerabilities` 與 `by_severity`；critical/high 先處理。
2. 打開 `Cargo.lock` 確認 crate 名稱、版本、來源；只有 `source` 含 crates.io 的套件會被查詢。
3. 讀 finding 訊息中的 affected range、fixed version 與 CVE/GHSA alias。
4. 確認專案是否真的使用受影響的 API／feature，而不是只看版本號。不可達的程式路徑可以是 `ACCEPTED_RISK`，但仍要記錄。
5. 建議升級到 fixed version；若跨 major，先確認 breaking change 與 transitive dependency 衝突。
6. 不要把 `osv` finding 當成「原始碼有漏洞」；也不要直接修改 `Cargo.lock` 而不更新 `Cargo.toml`。

### 4b. 供應鏈（engine = `supply-chain`）

- `build.rs`：打開檔案確認沒有下載、執行或改寫專案外內容；必要時要求 pin 來源。
- `.cargo/config.toml`：`replace-with`、`runner`、明文 HTTP registry、自訂 linker 參數都要有明確理由。
- `Cargo.toml`：未 pin 的 git 依賴、`*` 萬用版本、指向專案外的 `path`、`[patch]` 覆寫，都屬 `NEEDS_HUMAN` 或 `ACCEPTED_RISK`，不要自行改動依賴策略。
- 缺少 `Cargo.lock`：應用程式應提交 lockfile；library 則可接受，但要在報告說明。

### 5. 分類

每一筆 finding 給一個 verdict：

- `TRUE_POSITIVE`：有具體攻擊路徑或明確弱點，應修。
- `FALSE_POSITIVE`：有證據顯示不可達、已防護、或規則誤解了語意。
- `TEST_ONLY`：只存在於測試／fixture，且不會進生產；仍建議避免真實憑證。
- `ACCEPTED_RISK`：使用者已知且接受；記錄理由與到期日。
- `NEEDS_HUMAN`：需要架構、業務或部署資訊才能判斷。

不要用「Semgrep 說的」當理由。每個 verdict 都要有程式碼證據。

### 5a. 記錄判定（避免下次重複判讀）

分類完成後，把確認的結果寫回服務。fingerprint 由 `rule_id + file + 程式碼片段（或訊息）` 雜湊而來，不含行號，所以程式碼上下移動不會讓判定失效。

```js
await tools.sast.triage_findings({
  scan_id: scanId,
  fingerprints: ["<fingerprint1>", "<fingerprint2>"],
  status: "false_positive", // false_positive | accepted_risk | wontfix | fixed | needs_review
  note: "已對照 src/api.rs:441：值來自固定 enum，不會進入 shell",
  author: "agent",
});
```

狀態對應：

| Verdict | triage status | 效果 |
| --- | --- | --- |
| `FALSE_POSITIVE` | `false_positive` | 抑制，之後摘要與預設 findings 不再列出 |
| `ACCEPTED_RISK` | `accepted_risk` | 抑制，但保留原因 |
| `TRUE_POSITIVE` 但暫不修 | `wontfix` | 抑制，記錄已知問題 |
| 已修補 | `fixed` | 不抑制；若重掃又出現會標成 `regressed` |
| `NEEDS_HUMAN` | `needs_review` | 只記錄，不抑制 |
| `TEST_ONLY` | `false_positive` | 註明只在測試／fixture，不會進生產 |

規則：

1. **先讀過原始碼才能標 `false_positive` / `accepted_risk` / `wontfix`**；不確定就用 `needs_review`。
2. `note` 要寫「為什麼安全／為什麼接受」，不要只寫「誤報」。
3. 一次最多 1000 個 fingerprint；分批處理。
4. 已抑制項目要覆核時：

```js
await tools.sast.get_findings({
  scan_id: scanId,
  include_suppressed: true,
  triage_status: ["false_positive"],
  limit: 50,
});
```

5. 需要把判定帶到另一台機器或提交進 repo 時：

```js
await tools.sast.export_triage({ output_path: "sast-triage.json", overwrite: true });
await tools.sast.import_triage({ path: "sast-triage.json" });
```

6. 如果某個誤報其實只適用於單一行，也可以請使用者加原始碼註解，判定會跟著 repo 走：

```python
dangerous_call()  # sast:ignore
# sast:ignore: rule-id-a, rule-id-b -- 原因
```

`# sast:ignore` 影響同一行（寫在上一行也有效），狀態為 `inline_ignored`。

### 6. 修補

- 先提出最小修補，不要順手大重構。
- 一次處理一個規則／一個檔案群，避免把無關變更混進同一個 patch。
- 修完後跑相關測試；若沒有測試，先補一個能重現問題的測試。
- 不要執行被掃描的程式碼來「驗證」漏洞；用測試或靜態推理。
- 涉及認證、加密、SQL、檔案上傳的修改，先向使用者確認設計。

### 7. 重新掃描與比較

```js
const rescan = await tools.sast.scan_path({ path: ".", wait: true, wait_timeout_sec: 300 });
const after = await tools.sast.summarize_scan({ scan_id: rescan.scan.id });
```

報告「修復前 → 修復後」的數量變化，並確認：

- 目標規則真的消失，或 severity 下降。
- 沒有為了讓掃描變乾淨而放寬規則或排除檔案。
- 沒有新增其他規則的 finding。
- 先前標記的誤報／接受風險沒有重新出現在預設摘要中；`suppressed_findings` 應與 `list_triage` 的紀錄一致。
- 已標 `fixed` 的項目若又出現，會是 `regressed`，要優先處理。

### 8. 輸出報告

建議格式：

```markdown
## SAST 摘要
- Scan: <id>（engine, files scanned, duration）
- 總計：critical X / high X / medium X / low X / info X
- Verdict：TP X / FP X / test-only X / needs-human X
- 已抑制：X（false_positive X / accepted_risk X / wontfix X / inline_ignored X）

## 需要處理
| Severity | Rule | Location | Verdict | 證據 | 建議修補 |
| --- | --- | --- | --- | --- | --- |

## 誤報與測試資料
| Rule | Location | 為什麼不是問題 |
| --- | --- | --- |

## 修復與驗證
- 已修改：...
- 測試：...
- 重掃結果：...

## 殘餘風險與覆蓋率
- 引擎／規則集：...
- 依賴：Cargo.lock N 個、查詢 N 個套件、N 個已知漏洞（OSV）
- 供應鏈：build.rs N、.cargo 設定 N、未 pin git 依賴 N
- 未掃描或排除的內容：...
- 已知限制：...
```

不要貼出完整秘密、完整 SARIF 或大量原始碼。用 `file:line` 指路。

## Token 預算

- 先 `summarize_scan`，再 `get_findings`。
- 用 `severity`、`rule_id_contains`、`file_contains` 收窄，預設 `limit=50`。
- 不要一次拉 5000 筆；用 `offset` 分頁。
- 不要把 SARIF 內容讀進上下文；`export_sarif` 只回傳路徑與統計。
- 同一個 finding 不要重複貼全文；引用 `file:line` 即可。

## 失敗處理

| 症狀 | 處理 |
| --- | --- |
| `health` 連不上 | 啟動服務；確認 `SAST_BASE_URL`、port、防火牆。 |
| `401` | 服務與 MCP server 都要設定同一組 `SAST_API_KEY`。 |
| `scan.error` 提到 ZIP 上限 | 縮小 `path`，或調整 `SAST_MAX_UPLOAD_MB` / `SAST_MAX_EXTRACT_MB` / `SAST_MAX_FILES`。 |
| `scan.error` 提到 git | 只支援公開 http(s)；檢查 URL、網路與 `SAST_ALLOW_GIT_SOURCES`。 |
| `timed_out: true` | 再呼叫 `wait_for_scan`；必要時看服務日誌。 |
| `files_scanned` 為 0 | 檢查來源是否為空、是否全部被排除、是否只有不支援的副檔名。 |
| Semgrep 不可用 | `pip install -r requirements-semgrep.txt`，或設定 `SAST_SEMGREP_BIN`。 |
| `dependencies.warnings` 有 OSV 失敗 | 容器無法連外或 OSV 逾時；檢查網路、`SAST_OSV_API_URL`，必要時調高 `SAST_OSV_TIMEOUT_SEC`。掃描本身仍有效。 |
| `dependencies.enabled=false` | 服務設定了 `SAST_OSV_ENABLED=false`，或這是舊掃描；需要時重新掃描。 |
| `triage_findings` 顯示 fingerprint 不在掃描中 | fingerprint 來自別的掃描或已因程式碼變更失效；先用 `get_findings` 取得目前掃描的 fingerprint。 |
| 標記後 finding 仍在 | 確認是 `fixed` / `needs_review`（不抑制），或用 `include_suppressed: true` 覆核；也檢查是否為不同的 fingerprint。 |

## 已知限制

- 依賴漏洞只涵蓋 Rust 的 crates.io（解析 `Cargo.lock` 查 OSV），沒有 npm / PyPI / Maven / NuGet 的 SCA。供應鏈檢查目前也只針對 Cargo。
- 內建規則涵蓋 Python / JS / TS / Node.js / Java / Go / PHP / Ruby / Rust / C / C++ / C#；Rust 另有 `p/rust` registry pack 會預設疊加（下載失敗時自動退回內建規則）。
- 沒有 diff、PR 註解、issue tracker 整合。Triage baseline 可跨掃描／跨機器沿用，但不是 diff 掃描。
- Triage 判定以 fingerprint 為準；程式碼片段改變會產生新 fingerprint，需要重新判讀。
- 服務是基本版：程序內佇列、單一 worker、無多租戶與速率限制；不要直接暴露到公網。
- MCP HTTP transport 目前沒有內建認證；請只綁 loopback，或放在有認證的反向代理後。
- `scan_path` 讀取的是 **MCP server 所在機器** 的檔案系統；遠端部署時要特別確認這一點。
- 空結果不代表安全：規則沒命中可能只是沒有對應規則、語言不支援、或檔案被排除。
