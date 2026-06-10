# Code Security Skill — 專案詳細說明書

> 版本：v3.0.0　｜　標準：OWASP Top 10 2025 · ASVS 5.0.0 · CWE Top 25 2025

---

## 目錄

1. [專案簡介](#1-專案簡介)
2. [核心概念](#2-核心概念)
3. [系統架構](#3-系統架構)
4. [知識庫內容](#4-知識庫內容)
5. [安裝指南](#5-安裝指南)
6. [使用方式](#6-使用方式)
7. [搜尋引擎說明](#7-搜尋引擎說明)
8. [支援的 AI 編程工具](#8-支援的-ai-編程工具)
9. [MCP 伺服器整合](#9-mcp-伺服器整合)
10. [開發者指南](#10-開發者指南)
11. [測試與驗證](#11-測試與驗證)
12. [持續整合（CI/CD）](#12-持續整合cicd)
13. [貢獻與維護](#13-貢獻與維護)
14. [資安標準對應表](#14-資安標準對應表)

---

## 1. 專案簡介

### 1.1 問題背景

工程師在撰寫程式碼時，往往因為趕工或不熟悉資安細節，在無意間埋下安全漏洞。常見狀況如：

- 忘記對資料庫查詢使用參數化查詢，導致 SQL Injection
- 使用 MD5 或 SHA1 儲存密碼，導致密碼洩露後大規模破解
- 缺少授權驗證，造成越權存取（IDOR）
- 未設定 CSRF Token，導致跨站請求偽造攻擊

這些問題不是因為工程師能力不足，而是**安全知識的觸發時機不對**——等到 Code Review 或滲透測試才發現，修復成本已大幅提高。

### 1.2 解決方案

**Code Security Skill** 是一個安裝於 AI 編程助理（Claude Code、Cursor、GitHub Copilot 等）的**自動化資安智慧外掛**。  
它讓 AI 在每一次產生程式碼時，**自動套用最高等級的資安標準**，無需工程師主動詢問。

### 1.3 核心價值

| 傳統做法 | 使用本技能後 |
|---------|------------|
| 事後資安審查 | **事前自動注入**安全模式 |
| 依賴工程師記憶 | **知識庫自動檢索**相關規則 |
| 每次手動查詢 OWASP | **即時對應** 50+ 漏洞檔案 |
| 僅支援特定語言 | **11 種語言** / 6 大 AI 工具 |

---

## 2. 核心概念

### 2.1 技能（Skill）是什麼？

技能（Skill）是一組安裝到 AI 編程工具的**結構化知識與指令**。安裝後：

1. AI 偵測到特定**觸發關鍵字**（如 `login`、`upload`、`jwt`、`database`）
2. 自動從本地知識庫**搜尋對應的資安資料**
3. 在產生程式碼時**主動套用**正確的安全模式

### 2.2 自動觸發機制

技能預設 **50+ 個觸發關鍵字**，涵蓋中英文，例如：

- 英文：`authentication`、`password`、`upload`、`sql`、`token`、`encrypt`
- 繁體中文：`登入`、`密碼`、`上傳`、`資料庫`、`加密`、`授權`

一旦偵測到這些關鍵字，技能就會自動啟動，**無需工程師手動呼叫**。

### 2.3 搜尋引擎架構

搜尋引擎採用 **BM25 + 關鍵字混合搜尋**：

```
使用者輸入（中/英文）
        ↓
  中文別名映射（登入 → login）
        ↓
  BM25 相關性計算
        ↓
  關鍵字精確匹配加權
        ↓
  結果排序 + 格式化輸出
```

---

## 3. 系統架構

### 3.1 目錄結構

```
code-security-skill/
│
├── src/code-security/              ← 知識庫正式來源（唯一真實版本）
│   ├── data/                       ← 8 個 CSV 知識庫檔案
│   │   ├── vulnerabilities.csv     ← 50 個漏洞檔案
│   │   ├── checklists.csv          ← 26 個功能安全清單
│   │   ├── rules.csv               ← 51 條語言安全規則
│   │   ├── crypto.csv              ← 12 份加密最佳實踐指南
│   │   ├── asvs.csv                ← OWASP ASVS 5.0.0（17 章 345 條需求）
│   │   ├── cwe_top25.csv           ← MITRE CWE Top 25 2025
│   │   ├── cwe_extended.csv        ← 延伸 CWE 映射（SSTI、NoSQL）
│   │   └── assurance.csv           ← 15 個受管資安保證控制
│   ├── scripts/
│   │   ├── search.py               ← BM25 搜尋引擎主程式
│   │   └── validate_data.py        ← 資料完整性驗證工具
│   ├── templates/
│   │   ├── skill-content.md        ← 注入 AI 的核心指令文件
│   │   └── claude.json             ← 技能清單（含 8 種搜尋模式）
│   └── mcp_server.py               ← MCP 協議伺服器
│
├── scripts/
│   └── install_skill.py            ← 跨平台安裝腳本（Python）
│
├── bin/
│   └── codesecurity.js             ← Node.js CLI 包裝器
│
├── tests/
│   └── test_search.py              ← 自動化測試套件（14 個測試）
│
├── .github/workflows/
│   └── test.yml                    ← CI/CD 工作流程
│
├── install.sh                      ← Unix/macOS 快速安裝腳本
├── install.ps1                     ← Windows PowerShell 安裝腳本
├── package.json                    ← npm 套件清單（v3.0.0）
├── CLAUDE.md                       ← Claude Code 專用說明
└── README.md                       ← 英文主說明文件
```

### 3.2 資料流向

```
[正式來源] src/code-security/
         ↓ install_skill.py 安裝
         ↓
[安裝目標（AI 工具）]
├── .claude/skills/code-security/   ← Claude Code
├── .cursor/rules/                  ← Cursor
├── .github/copilot-instructions.md ← GitHub Copilot
├── .windsurf/rules/                ← Windsurf
├── .codex/config.toml              ← OpenAI Codex
└── ~/.gemini/config/               ← Antigravity
```

> **重要：** `.claude/skills/code-security/` 是**生成的副本**，已加入 `.gitignore`，不應提交至版本庫。正式來源永遠是 `src/code-security/`。

---

## 4. 知識庫內容

### 4.1 漏洞檔案（vulnerabilities.csv）

共 **50 個漏洞檔案**，每筆記錄包含：

| 欄位 | 說明 |
|------|------|
| `id` | 漏洞編號（V001–V050） |
| `name` | 漏洞名稱（如 SQL Injection） |
| `category` | 分類（Injection、Auth、Crypto 等） |
| `severity` | 嚴重程度（CRITICAL / HIGH / MEDIUM） |
| `owasp_ref` | 對應 OWASP 2025 類別（如 A05:2025） |
| `description` | 漏洞描述 |
| `trigger_keywords` | 觸發關鍵字列表 |
| `fix_pattern` | 修補模式說明 |
| `languages` | 適用語言 |

涵蓋的漏洞類型：
- SQL/NoSQL/Command Injection
- XSS（反射型、儲存型、DOM 型）
- CSRF、SSRF、XXE
- 路徑穿越（Path Traversal）
- JWT 不安全實作
- 不安全的反序列化
- SSTI（伺服器端範本注入）
- 競態條件（Race Condition / TOCTOU）
- 供應鏈攻擊
- LLM Prompt Injection（AI 應用特有）

### 4.2 功能安全清單（checklists.csv）

共 **26 個功能導向清單**，例如：

| 功能 ID | 功能名稱 | 觸發關鍵字 |
|---------|---------|----------|
| F001 | 身份驗證系統 | login, signin, auth |
| F002 | 檔案上傳 | upload, file, attachment |
| F003 | JWT 實作 | jwt, token, bearer |
| F004 | 資料庫查詢 | sql, database, query |
| F005 | API 端點 | api, rest, graphql |
| F006 | 密碼重置 | password reset, forgot |
| F007 | 付款處理 | payment, stripe, credit card |
| F008 | 管理後台 | admin, dashboard |
| ... | NoSQL、CI/CD、隱私、WebSocket、無伺服器架構、行動應用等 | |

每個清單包含：
- 逐項勾選的安全需求（如 `[AUTH-1] 使用 argon2id 雜湊密碼`）
- Python / JavaScript 推薦函式庫
- 跳過此清單的嚴重性評估

### 4.3 語言安全規則（rules.csv）

共 **51 條規則**，按語言分類：

| 語言 | 規則範例 |
|------|---------|
| Python | 禁止用字串格式化建構 SQL；使用 `parameterized queries` |
| JavaScript | 禁止 `eval()`；使用 `innerHTML` 前須過濾 |
| PHP | 使用 `PDO` 或 `mysqli prepared statements` |
| Java | 使用 `PreparedStatement`；避免 `Runtime.exec()` |
| Go | 使用 `database/sql` 佔位符；避免 `exec.Command` 串接 |
| Ruby | 使用 ActiveRecord 佔位符；避免 `system()` 串接 |
| C# | 使用 LINQ 或 `SqlParameter`；啟用 ASP.NET Core 防護 |
| C/C++ | 使用 `snprintf` 而非 `sprintf`；啟用 AddressSanitizer |
| Rust | 優先使用安全的 Rust API；謹慎使用 `unsafe` |
| Terraform | 最小權限 IAM；加密靜態資料；限制 CIDR 範圍 |

每條規則均附：
- 壞例（`bad_example`）
- 好例（`good_example`）
- OWASP 參考標準

### 4.4 加密最佳實踐（crypto.csv）

共 **12 份指南**，涵蓋：

| 使用場景 | 推薦方案 | 應避免 |
|---------|---------|-------|
| 密碼雜湊 | bcrypt（cost≥12）/ argon2id | MD5、SHA1、SHA256 明文 |
| 對稱加密 | AES-256-GCM | DES、AES-ECB |
| 非對稱加密 | RSA-4096 / ECDSA P-256 | RSA-1024、MD5WithRSA |
| JWT 簽署 | RS256（非對稱） | HS256 共享金鑰 |
| 傳輸安全 | TLS 1.3 / mTLS | TLS 1.0/1.1、自簽憑證 |
| 金鑰管理 | KMS（AWS/GCP/Azure） | 硬編碼金鑰 |
| 秘密儲存 | HashiCorp Vault / 環境變數 | 明文寫入程式碼 |
| 安全令牌 | `secrets.token_urlsafe()` | `random.random()` |

每份指南均附 Python 與 JavaScript 的完整程式碼範例。

### 4.5 OWASP ASVS 5.0.0（asvs.csv）

**OWASP 應用程式安全驗證標準** v5.0.0，共 **17 章、345 條需求**：

| 章節 | 名稱 | 需求數 |
|------|------|--------|
| V1 | 架構、設計與威脅模型 | 約 20 條 |
| V2 | 身份驗證 | 約 25 條 |
| V3 | 工作階段管理 | 約 15 條 |
| V4 | 存取控制 | 約 15 條 |
| V5 | 驗證、清理與編碼 | 約 25 條 |
| V6 | 儲存的加密 | 約 10 條 |
| V7 | 錯誤處理與日誌記錄 | 約 15 條 |
| V8 | 資料保護 | 約 15 條 |
| V9 | 通訊安全 | 約 10 條 |
| V10 | 惡意程式碼 | 約 10 條 |
| V11 | 商業邏輯 | 約 10 條 |
| V12 | 檔案與資源 | 約 15 條 |
| V13 | API 與 Web 服務 | 約 20 條 |
| V14 | 設定 | 約 15 條 |
| V15 | 加密 | 約 15 條 |
| V16 | 供應鏈安全（新增） | 約 10 條 |
| V17 | AI 與 LLM 安全（新增） | 約 10 條 |

### 4.6 MITRE CWE Top 25 2025（cwe_top25.csv）

**MITRE 最危險軟體弱點前 25 名**（2025 年版），範例：

| 排名 | CWE 編號 | 名稱 | 類別 |
|------|---------|------|------|
| 1 | CWE-79 | Cross-site Scripting | 注入 |
| 2 | CWE-787 | Out-of-bounds Write | 記憶體安全 |
| 3 | CWE-89 | SQL Injection | 注入 |
| 4 | CWE-416 | Use After Free | 記憶體安全 |
| 5 | CWE-78 | OS Command Injection | 注入 |
| ... | ... | ... | ... |

延伸映射（cwe_extended.csv）補充：
- **CWE-1336**：伺服器端範本注入（SSTI）
- **CWE-943**：NoSQL 查詢注入

### 4.7 資安保證控制（assurance.csv）

共 **15 個受管控制項**，依開發生命週期階段分類：

| 階段 | 控制項 | 自動化工具 |
|------|--------|----------|
| 設計 | 威脅模型（STRIDE） | — |
| 需求 | ASVS 等級選擇 | — |
| 實作 | 安全程式碼審查 | GitHub CODEOWNERS |
| 建置 | SAST 靜態分析 | Semgrep、Bandit、CodeQL |
| 建置 | 機密掃描 | Gitleaks、truffleHog |
| 建置 | SBOM / SCA 套件分析 | Dependabot、Snyk |
| 測試 | 負向測試（Auth/AuthZ） | OWASP ZAP |
| 測試 | DAST 動態測試 | OWASP ZAP |
| 部署 | 機密輪換 | Vault、AWS Secrets Manager |
| 事故 | 事故回應程序 | PagerDuty、SIEM |

---

## 5. 安裝指南

### 5.1 前置需求

```bash
# 確認 Python 版本（必須 3.x）
python3 --version

# 安裝選用依賴（改善 MIME 偵測）
pip install python-magic
```

### 5.2 快速安裝（推薦）

**Unix / macOS：**
```bash
curl -sSL https://raw.githubusercontent.com/<owner>/code-security-skill/main/install.sh | bash
```

**Windows PowerShell：**
```powershell
irm https://raw.githubusercontent.com/<owner>/code-security-skill/main/install.ps1 | iex
```

**npm 全域安裝：**
```bash
npm install -g codesecurity
codesecurity init
```

### 5.3 手動安裝

```bash
# 複製專案
git clone https://github.com/<owner>/code-security-skill.git
cd code-security-skill

# 安裝至所有 AI 工具
python3 scripts/install_skill.py /path/to/your-project

# 只安裝至特定工具
python3 scripts/install_skill.py /path/to/your-project --ai claude cursor

# 強制覆蓋現有安裝
python3 scripts/install_skill.py /path/to/your-project --force
```

### 5.4 支援的安裝目標（--ai 參數）

| 參數值 | 對應 AI 工具 | 安裝位置 |
|--------|------------|---------|
| `claude` | Claude Code | `.claude/skills/code-security/` |
| `cursor` | Cursor | `.cursor/rules/code-security.md` |
| `copilot` | GitHub Copilot | `.vscode/mcp.json` + `.github/copilot-instructions.md` |
| `windsurf` | Windsurf | `.windsurf/mcp_config.json` + `.windsurf/rules/code-security.md` |
| `codex` | OpenAI Codex | `.codex/config.toml` + `AGENTS.md` |
| `antigravity` | Antigravity | `~/.gemini/config/mcp_config.json` (全域) + `GEMINI.md` |

### 5.5 解除安裝

```bash
# CLI 方式
codesecurity uninstall

# 只解除特定工具
codesecurity uninstall --ai claude

# 同時移除全域 MCP 伺服器
codesecurity uninstall --global-server

# 腳本方式
python3 scripts/install_skill.py /path/to/your-project --uninstall
```

### 5.6 升級

```bash
# 重新安裝即可升級（使用 --force 覆蓋）
python3 scripts/install_skill.py /path/to/your-project --force
```

---

## 6. 使用方式

### 6.1 自動觸發（無需任何操作）

安裝後，只要在 AI 工具中輸入包含觸發關鍵字的程式碼需求，技能就會自動啟動：

```
# 範例：AI 自動套用安全規則
使用者：「幫我寫一個使用者登入 API」
AI 自動：
  1. 偵測到 "login" → 載入 F001 身份驗證清單
  2. 載入 V003 暴力破解防護漏洞檔案
  3. 套用 argon2id 密碼雜湊
  4. 套用速率限制
  5. 套用安全的 session 管理
```

### 6.2 手動搜尋（8 種模式）

```bash
# 完整資安報告（預設模式）
python3 .claude/skills/code-security/scripts/search.py "login authentication" --lang python

# 功能安全清單
python3 .claude/skills/code-security/scripts/search.py "file upload" --mode checklist

# 漏洞檔案查詢
python3 .claude/skills/code-security/scripts/search.py "sql injection" --mode vuln

# 加密建議
python3 .claude/skills/code-security/scripts/search.py "password hashing" --mode crypto

# 語言特定規則
python3 .claude/skills/code-security/scripts/search.py "database query" --mode rules --lang javascript

# ASVS 驗證章節
python3 .claude/skills/code-security/scripts/search.py "authentication" --mode asvs

# CWE 根本原因
python3 .claude/skills/code-security/scripts/search.py "memory buffer" --mode cwe

# 資安保證控制
python3 .claude/skills/code-security/scripts/search.py "sast sbom" --mode control
```

### 6.3 搜尋模式對照表

| 模式 | 說明 | 適合查詢 |
|------|------|---------|
| `all`（預設） | 全資料庫搜尋，回傳完整報告 | 任何功能特性 |
| `checklist` | 功能導向安全清單 | 「我要做 X 功能」 |
| `vuln` | 漏洞檔案 | 「X 漏洞怎麼防止」 |
| `crypto` | 加密建議 | 「加密/雜湊怎麼做」 |
| `rules` | 語言安全規則 | 「Python 裡 Y 怎麼寫安全」 |
| `asvs` | ASVS 5.0.0 章節 | 「有哪些驗證需求」 |
| `cwe` | CWE Top 25 根本原因 | 「這種錯誤 CWE 是什麼」 |
| `control` | 資安保證控制 | 「CI/CD 要做哪些掃描」 |

### 6.4 繁體中文查詢支援

搜尋引擎內建繁體中文別名映射，可直接用中文查詢：

```bash
python3 .claude/skills/code-security/scripts/search.py "登入驗證" --lang python
python3 .claude/skills/code-security/scripts/search.py "檔案上傳" --mode checklist
python3 .claude/skills/code-security/scripts/search.py "資料庫注入" --mode vuln
python3 .claude/skills/code-security/scripts/search.py "密碼加密" --mode crypto
```

---

## 7. 搜尋引擎說明

### 7.1 演算法架構

搜尋引擎位於 [src/code-security/scripts/search.py](src/code-security/scripts/search.py)，採用：

**BM25（Best Match 25）**
- 相關性排序演算法，考量詞頻（TF）與逆文件頻率（IDF）
- 不需外部機器學習模型，純 Python 實作
- 結果可解釋、可預測

**關鍵字精確匹配加權**
- 完全匹配 `trigger_keywords` 欄位的詞彙會獲得額外分數
- 確保精確查詢（如 `sql injection`）優先回傳最相關結果

### 7.2 中文別名映射

| 繁體中文 | 英文映射 |
|---------|---------|
| 登入 | login |
| 驗證 | authentication |
| 密碼 | password |
| 資料庫 | database |
| 上傳 | upload |
| 加密 | encryption |
| 授權 | authorization |
| 令牌 | token |
| 注入 | injection |
| 工作階段 | session |

### 7.3 搜尋流程

```
1. 讀取輸入查詢
2. 套用繁體中文別名轉換
3. 根據 --mode 選擇搜尋目標 CSV
4. 對每筆記錄計算 BM25 分數
5. 加計 trigger_keywords 精確匹配分數
6. 依語言過濾（若指定 --lang）
7. 排序輸出，顯示最高相關結果
```

### 7.4 支援語言（--lang 參數）

`python` · `javascript` · `typescript` · `java` · `go` · `php` · `ruby` · `csharp` · `cpp` · `rust` · `terraform`

---

## 8. 支援的 AI 編程工具

### 8.1 Claude Code（主要支援）

安裝後，技能會被注入至 `.claude/skills/code-security/`，並在 `CLAUDE.md` 中加入使用說明。

**特色：**
- 完整 8 種搜尋模式
- MCP 伺服器整合（即時查詢）
- 自動觸發機制

### 8.2 Cursor

安裝後，會在 `.cursor/rules/code-security.md` 建立規則檔案，Cursor 的 AI 會自動套用這些規則。

### 8.3 GitHub Copilot

安裝後，同時建立兩個檔案：
- `.vscode/mcp.json`：VS Code 專案層級 MCP 設定，讓 Copilot 可即時呼叫 `search_security()`
- `.github/copilot-instructions.md`：注入靜態資安指令，Copilot 在自動完成時會考量這些指令

> **注意：** VS Code GitHub Copilot 的 MCP 設定格式使用 `"servers"` 鍵（含 `"type": "stdio"`），與 Claude/Cursor 使用的 `"mcpServers"` 格式不同。

### 8.4 Windsurf

安裝後，會在 `.windsurf/rules/code-security.md` 建立規則檔案。

### 8.5 OpenAI Codex

安裝後，會在 `.codex/config.toml` 加入 TOML 格式的設定。

### 8.6 Antigravity

安裝後，同時建立兩個設定：
- `~/.gemini/config/mcp_config.json`：全域 MCP 設定（對所有專案生效）
- `GEMINI.md`：專案根目錄的靜態規則注入檔案，提供離線基準保護

---

## 9. MCP 伺服器整合

### 9.1 什麼是 MCP？

**Model Context Protocol（MCP）** 是一個讓 AI 工具與外部工具互動的開放協議。透過 MCP 伺服器，AI 可以在對話中**即時執行搜尋**，而不只是依賴預先注入的靜態規則。

### 9.2 MCP 伺服器位置

全域安裝於：`~/.code-security-skill/mcp_server.py`

### 9.3 提供的工具

MCP 伺服器公開 `search_security` 工具，參數如下：

```json
{
  "name": "search_security",
  "parameters": {
    "query": "string（必填）— 功能描述或主題",
    "mode": "enum（選填）— all/checklist/vuln/crypto/rules/asvs/cwe/control",
    "lang": "enum（選填）— python/javascript/java/go/php/ruby/csharp/cpp/rust/terraform"
  }
}
```

### 9.4 MCP 伺服器工作原理

MCP 伺服器是 `search.py` 的包裝器，以子程序形式呼叫，支援 UTF-8 編碼（含繁體中文）。

---

## 10. 開發者指南

### 10.1 修改知識庫

所有知識庫修改**必須在 `src/code-security/data/` 中進行**，不可直接修改安裝目標。

```bash
# 修改漏洞檔案
edit src/code-security/data/vulnerabilities.csv

# 新增安全清單
edit src/code-security/data/checklists.csv

# 驗證修改
python3 src/code-security/scripts/validate_data.py

# 重新安裝到目標專案
python3 scripts/install_skill.py /path/to/project --force
```

### 10.2 新增漏洞檔案

在 `vulnerabilities.csv` 中新增一行，遵循以下格式：

```csv
V051,新漏洞名稱,分類,CRITICAL,A05:2025,漏洞描述,觸發,關鍵字,修補模式,python,javascript
```

規則：
- `id` 必須唯一（V001–V999）
- `severity` 只能是 `CRITICAL`、`HIGH`、`MEDIUM`
- `owasp_ref` 必須對應有效的 OWASP 2025 類別（A01–A10）
- 不可使用舊版 2021 參考（如 `A01:2021`）

### 10.3 新增語言規則

在 `rules.csv` 中新增，格式：

```csv
R052,python,新分類,規則說明,壞例,好例,OWASP A05:2025
```

### 10.4 核心指令檔修改

技能的 AI 指令位於 [src/code-security/templates/skill-content.md](src/code-security/templates/skill-content.md)。

此檔案定義：
- 觸發條件（何時啟動）
- 安全推理引擎（5 步驟流程）
- 強制規則（CRITICAL / HIGH / MEDIUM 分級）
- 功能特定模式

修改後需重新安裝技能以套用變更。

### 10.5 安裝腳本架構

[scripts/install_skill.py](scripts/install_skill.py) 的主要函式：

| 函式 | 說明 |
|------|------|
| `install(target_dir, platforms, force)` | 主安裝邏輯 |
| `uninstall(target_dir, platforms)` | 解除安裝邏輯 |
| `_install_claude(target_dir, force)` | Claude Code 專用安裝 |
| `_install_cursor(target_dir, force)` | Cursor 專用安裝 |
| `_install_copilot(target_dir, force)` | Copilot 專用安裝 |
| `_setup_mcp_server(force)` | 全域 MCP 伺服器安裝 |

---

## 11. 測試與驗證

### 11.1 執行測試套件

```bash
# 執行所有自動化測試
python3 -m pytest tests/ -v

# 或使用 unittest
python3 -m unittest discover -s tests -v
```

### 11.2 測試類別說明

**DataIntegrityTests（資料完整性測試，9 個）：**

| 測試名稱 | 驗證內容 |
|---------|---------|
| `test_csv_schema` | 所有 CSV 欄位正確、ID 唯一 |
| `test_owasp_web_coverage` | OWASP Web Top 10 2025（A01–A10）完整覆蓋 |
| `test_owasp_api_coverage` | OWASP API Security Top 10 2023 完整覆蓋 |
| `test_owasp_llm_coverage` | OWASP LLM Top 10 2025 完整覆蓋 |
| `test_no_legacy_2021_refs` | 不存在舊版 2021 參考 |
| `test_asvs_completeness` | ASVS 5.0.0 章節 V1–V17 完整 |
| `test_cwe_completeness` | CWE Top 25（25 條唯一排名） |
| `test_installer_no_self_duplication` | 安裝腳本不會將自身安裝到 src/ |
| `test_skill_manifest` | claude.json 含所有 8 種搜尋模式 |

**SearchTests（搜尋功能測試，5 個）：**

| 測試名稱 | 驗證內容 |
|---------|---------|
| `test_chinese_query` | 繁體中文查詢能正確映射（登入驗證→Authentication） |
| `test_unknown_query` | 未知查詢回傳空結果（不亂回傳） |
| `test_bm25_ranking` | SQL injection 為最高相關結果 |
| `test_llm_filtering` | 泛用詞（security）不稀釋 LLM 相關結果 |
| `test_memory_safety_cross_search` | 跨資料集搜尋記憶體安全相關主題 |

### 11.3 資料驗證工具

```bash
python3 src/code-security/scripts/validate_data.py
```

驗證項目：
- CSV schema 完整性
- OWASP 2025 覆蓋率
- ASVS 5.0.0 章節完整性
- CWE Top 25 2025 排名唯一性
- 延伸 CWE 必要項目（SSTI、NoSQL）
- 無舊版 2021 參考

---

## 12. 持續整合（CI/CD）

### 12.1 GitHub Actions 工作流程

設定檔：[.github/workflows/test.yml](.github/workflows/test.yml)

**觸發條件：** `push` 或 `pull_request`

**執行環境：** `ubuntu-latest`、Python 3.12

**工作步驟：**

```
步驟 1：驗證知識庫 CSV 資料
  └── python3 src/code-security/scripts/validate_data.py

步驟 2：執行自動化測試套件
  └── python3 -m unittest discover -s tests
```

### 12.2 PR 合併標準

每個 Pull Request 都必須通過：
- 資料完整性驗證（14 個驗證點）
- 自動化測試套件（14 個測試）
- 無舊版 2021 OWASP 參考
- 新增漏洞需有對應的 OWASP 2025 映射

---

## 13. 貢獻與維護

### 13.1 貢獻流程

```bash
# 1. Fork 並複製
git clone https://github.com/<your-fork>/code-security-skill.git
cd code-security-skill

# 2. 建立功能分支
git checkout -b feat/add-graphql-injection

# 3. 修改 src/ 中的知識庫
edit src/code-security/data/vulnerabilities.csv

# 4. 執行驗證
python3 src/code-security/scripts/validate_data.py
python3 -m unittest discover -s tests

# 5. 提交並推送
git add src/
git commit -m "feat: add GraphQL injection vulnerability profile"
git push origin feat/add-graphql-injection

# 6. 開 Pull Request
```

### 13.2 知識庫更新時機

應在以下情況更新知識庫：
- OWASP 發布新版 Top 10
- MITRE 更新 CWE Top 25
- 發現新的高影響力漏洞類型
- 新增對語言/框架的支援

### 13.3 版本命名規則

遵循 [Semantic Versioning](https://semver.org/)：

| 版本類型 | 適用情況 |
|---------|---------|
| MAJOR（x.0.0） | 重大架構變更、OWASP 大版本更新 |
| MINOR（x.y.0） | 新增漏洞、新支援語言、新 AI 工具 |
| PATCH（x.y.z） | 修正現有規則、改善說明文字 |

---

## 14. 資安標準對應表

### 14.1 OWASP Top 10 2025

| 類別 | 名稱 | 本技能覆蓋 |
|------|------|----------|
| A01:2025 | 存取控制失效 / IDOR / SSRF（合併） | ✅ V010–V015 |
| A02:2025 | 安全設定錯誤 / Cookie / 安全標頭 | ✅ V016–V020 |
| A03:2025 | **軟體供應鏈失效（新增）** | ✅ V021–V023 |
| A04:2025 | 加密失效 / 硬編碼秘密 | ✅ V024–V028 |
| A05:2025 | 注入 / XSS / XXE / 不安全檔案上傳 | ✅ V001–V009 |
| A06:2025 | 不安全設計 / 缺少濫用控制 / ReDoS | ✅ V029–V033 |
| A07:2025 | 身份驗證失效 / JWT | ✅ V034–V038 |
| A08:2025 | 軟體或資料完整性失效 / 反序列化 | ✅ V039–V043 |
| A09:2025 | 安全日誌與警示失效 | ✅ V044–V046 |
| A10:2025 | **例外狀況錯誤處理（新增）** | ✅ V047–V050 |

### 14.2 OWASP API Security Top 10 2023

| 類別 | 名稱 | 覆蓋 |
|------|------|------|
| API1:2023 | 物件層級授權失效（BOLA） | ✅ |
| API2:2023 | 身份驗證失效 | ✅ |
| API3:2023 | 物件屬性層級授權失效 | ✅ |
| API4:2023 | 無限制資源消耗 | ✅ |
| API5:2023 | 功能層級授權失效 | ✅ |
| API6:2023 | 敏感商業流程無限制存取 | ✅ |
| API7:2023 | 伺服器端請求偽造 | ✅ |
| API8:2023 | 安全設定錯誤 | ✅ |
| API9:2023 | 不當資產管理 | ✅ |
| API10:2023 | 安全 API 使用不安全 | ✅ |

### 14.3 OWASP LLM Top 10 2025

| 類別 | 名稱 | 覆蓋 |
|------|------|------|
| LLM01:2025 | Prompt Injection | ✅ |
| LLM02:2025 | 敏感資訊洩露 | ✅ |
| LLM03:2025 | 供應鏈漏洞 | ✅ |
| LLM04:2025 | 資料與模型投毒 | ✅ |
| LLM05:2025 | 不當輸出處理 | ✅ |
| LLM06:2025 | 過度代理 | ✅ |
| LLM07:2025 | 系統提示洩露 | ✅ |
| LLM08:2025 | 向量與嵌入弱點 | ✅ |
| LLM09:2025 | 錯誤資訊 | ✅ |
| LLM10:2025 | 無限制消耗 | ✅ |

---

## 附錄

### 附錄 A：快速命令參考

```bash
# 安裝
npm install -g codesecurity && codesecurity init

# 搜尋
python3 .claude/skills/code-security/scripts/search.py "<查詢>" --mode <模式> --lang <語言>

# 驗證
python3 src/code-security/scripts/validate_data.py

# 測試
python3 -m unittest discover -s tests -v

# 解除安裝
codesecurity uninstall
```

### 附錄 B：常見問題

**Q：安裝後 AI 沒有自動套用安全規則？**  
A：確認 AI 工具已重新載入設定。Claude Code 需要重啟工作階段；Cursor 需要關閉並重開資料夾。

**Q：搜尋結果出現亂碼（Windows）？**  
A：搜尋引擎已內建 Windows 終端機相容模式，若仍有問題，嘗試設定 `PYTHONIOENCODING=utf-8`。

**Q：可以在沒有網路的環境使用嗎？**  
A：可以。安裝後所有知識庫為本地 CSV 檔案，搜尋引擎完全離線運作。

**Q：如何確認已安裝最新版本？**  
A：執行 `codesecurity --version` 或查看 `package.json` 中的 `version` 欄位。

**Q：支援 TypeScript 嗎？**  
A：支援。TypeScript 查詢會對應到 `javascript` 規則，兩者共用同一組規則。

### 附錄 C：技術規格

| 項目 | 規格 |
|------|------|
| 版本 | 3.0.0 |
| Node.js 需求 | ≥ 14 |
| Python 需求 | 3.x |
| 漏洞檔案數 | 50 |
| 安全清單數 | 26 |
| 語言規則數 | 51+ |
| 加密指南數 | 12 |
| ASVS 需求數 | 345（17 章） |
| CWE Top 25 | 25 條（2025 年版） |
| 保證控制項 | 15 |
| 支援 AI 工具 | 6 |
| 支援語言 | 11 |
| 搜尋模式 | 8 |
| 自動化測試 | 14 |
| 觸發關鍵字 | 50+ |

---

*本說明書對應 Code Security Skill v3.0.0，OWASP Top 10 2025 / ASVS 5.0.0 / CWE Top 25 2025 版本。*
