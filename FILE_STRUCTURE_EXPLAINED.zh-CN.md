# DevSecOps Security Automation Platform：逐文件代码结构详解（已更新）

本文档已根据当前仓库最新实现更新，重点覆盖：
- 仅扫描本次变更的 `demo_app` 文件
- CI 自动回写 `findings_db.json`
- policy 失败时仍上传 SARIF
- `findings_db.json` 已从扫描范围排除
- demo_app 当前为故意漏洞演示版本

## 1. 总体分层
- CLI 调度层：`secscan/cli.py`
- 扫描执行层：`secscan/scanners.py`
- 规则层：`secscan/rules/*.py`
- 报告层：`secscan/reporting/*.py`
- 治理层：`secscan/governance/*.py`
- 集成层：`Makefile`、`.github/workflows/security-scan.yml`、README、tests

核心数据对象是 `Finding`，从规则检测到报告、门禁、治理全链路复用。

---

## 2. 工程与配置文件

### `.github/workflows/security-scan.yml`
职责：CI 主流程（扫描、治理同步、门禁、SARIF 上传）。

当前关键行为：
- 触发条件：`push`/`pull_request` 且路径命中
  - `demo_app/**`
  - `secscan/**`
  - `.github/workflows/security-scan.yml`
  - `policy.yml`
- 并发控制：
  - `concurrency.group = security-scan-${{ github.ref }}`
  - 同一分支并发互斥，减少回写冲突
- 扫描范围控制：
  - 先计算变更文件
  - 仅复制变更的 `demo_app` 文件到 `scan_scope/`
  - 对 `scan_scope/demo_app` 执行 SAST/Secrets
- 退出码策略：
  - 扫描返回 `1`（有发现）不中断
  - 返回 `>1`（运行错误）中断
- 治理回写：
  - `sync` 更新 `findings_db.json`
  - 仅在 `push` 到 `main` 且有变更文件时回写仓库
  - commit 信息带 `[skip ci]` 防止无意义循环
- policy 门禁：
  - `python -m secscan.cli policy --input findings.json --policy policy.yml`
- SARIF 上传：
  - `Upload SAST SARIF` + `Upload Secrets SARIF`
  - 各自有独立 `category`
  - `if: always()`，即使 policy 失败也上传

### `.gitignore`
职责：忽略本地产物与缓存。

当前包含：
- `.DS_Store`
- `.venv/`
- `__pycache__/`
- `*.pyc`
- `artifacts/`

### `Makefile`
职责：本地开发命令入口。

关键目标：
- `setup`：创建 `.venv` 并升级 pip
- `scan`：全仓本地扫描、生成 `artifacts/`、baseline、sync
- `gate`：单独执行 policy
- `test`：单元测试
- `run-demo`：运行 demo app（检查 Flask/requests/PyYAML 依赖）
- `artifacts`：只针对 `demo_app` 生成 SARIF

备注：`scan`/`artifacts` 的 `--exclude` 已包含 `findings_db.json`，避免自扫描噪声。

### `policy.yml`
职责：门禁策略。

当前：
- `fail_on_severities: [high, critical]`
- `max_severity` 存在，但当前 CLI 实际按 `fail_on_severities` 执行。

### `findings_db.json`
职责：治理生命周期存储。

结构：
- `items` 字典（key 为 fingerprint）
- 每项记录：`status/first_seen/last_seen/owner/severity/file/...`

状态枚举：
- `OPEN`
- `FIXED`
- `ACCEPTED_RISK`

---

## 3. secscan 包核心文件

### `secscan/cli.py`
职责：命令入口与流程编排。

子命令：
- `sast`
- `secrets`
- `report`
- `baseline`
- `policy`
- `sync`
- `dast`

关键点：
- 统一退出码：`0/1/2`
- 默认排除目录/文件含：`findings_db.json`
- `policy` 返回 `1` 表示命中门禁（非运行错误）

### `secscan/scanners.py`
职责：文件遍历 + 规则执行。

行为：
- `run_sast`：仅 `.py`，AST 解析后跑规则
- `run_secrets`：文本模式扫描 + 去重
- 输出按文件/行号/规则 ID 稳定排序

### `secscan/models.py`
职责：`Finding` 数据模型定义。

### `secscan/utils.py`
职责：通用函数。

包括：
- 严重度比较
- 文件遍历与过滤
- 指纹计算
- JSON 存储

---

## 4. 规则层（OWASP 对齐）

目录：`secscan/rules/`

规则文件：
- `sql_injection.py` -> `SEC-SQLI-001`
- `xss.py` -> `SEC-XSS-001/002`
- `ssrf.py` -> `SEC-SSRF-001`
- `insecure_deserialization.py` -> `SEC-DESER-001/002`
- `command_injection.py` -> `SEC-CMDI-001`
- `secrets.py` -> `SEC-SECRET-*` + entropy
- `common.py` -> AST 公共工具

实现风格：
- 轻量启发式（AST + regex + 低成本 taint）
- 输出统一映射为 `Finding`

---

## 5. 报告层

### `secscan/reporting/sarif.py`
职责：将 findings 转 SARIF 2.1.0。

重要更新（已修复）：
- `security-severity` 改为 GitHub 要求的**数值字符串**（`0.0-10.0`）
  - low -> `3.0`
  - medium -> `5.0`
  - high -> `8.0`
  - critical -> `9.0`

### `secscan/reporting/html.py`
职责：生成 `report.html` 概览页（总数 + severity 分布 + 表格）。

---

## 6. 治理层

### `secscan/governance/sync.py`
职责：生命周期同步逻辑。

核心规则：
- 本次出现且历史不存在 -> `OPEN`
- 历史 `OPEN` 本次未出现 -> `FIXED`
- 历史 `FIXED` 再次出现 -> `OPEN`
- `ACCEPTED_RISK` 保留

---

## 7. demo_app（当前：故意漏洞版）

文件：`demo_app/app.py`

当前故意保留的风险点：
- 硬编码 secrets（token/password/aws key）
- SQL 注入（动态 SQL）
- SSRF（用户可控 URL 请求）
- 不安全反序列化（`pickle.loads`、`yaml.load`）
- 命令注入（`subprocess ... shell=True`、`os.system`）
- 模板型 XSS（`render_template_string` + 用户输入）

用途：用于验证扫描、门禁、Code Scanning 告警是否生效。

---

## 8. 测试

目录：`tests/`

- `test_rules.py`：规则命中测试
- `test_sarif.py`：SARIF 结构与严重度格式回归测试

---

## 9. 当前执行链路（CI）

一次命中触发条件的 push/PR 流程：
1. Checkout + Python 环境
2. 计算变更文件，抽取 `demo_app` 范围到 `scan_scope`
3. 运行 SAST/Secrets（SARIF + JSON）
4. 合并为 `findings.json`
5. 同步治理 DB（并在 main push 自动回写）
6. 执行 policy（可能失败）
7. 无论 policy 成败都上传 SARIF 到 Code Scanning

---

## 10. 你最关心的两个实现点（定位）

1. “为什么 policy 失败也能看到 SARIF”
- 在 workflow 的上传步骤用了 `if: always()`

2. “为什么不再扫描 findings_db.json”
- CLI 默认 exclude、Makefile、workflow 三处都已加入 `findings_db.json`

