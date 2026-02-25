# DevSecOps Security Automation Platform：逐文件代码结构详解

本文档面向当前仓库中的每个文件，说明其职责、核心结构、输入输出与在系统中的位置。

## 0. 总体架构

系统分为 6 层：
- CLI 调度层：`secscan/cli.py`
- 扫描执行层：`secscan/scanners.py`
- 规则层：`secscan/rules/*.py`
- 报告层：`secscan/reporting/*.py`
- 治理层：`secscan/governance/*.py`
- 工程与集成层：`Makefile`、GitHub Actions、README、tests、artifacts

主数据对象为 `Finding`，贯穿 SAST/Secrets/DAST、报告、策略门禁、治理同步全流程。

---

## 1. 工程与配置文件

### `.github/workflows/security-scan.yml`
职责：CI 自动化与 SDLC 集成入口。

结构说明：
- 触发器：`push`、`pull_request`
- 权限：`security-events: write`（用于上传 SARIF）
- 关键步骤：
  - checkout
  - setup-python 3.11
  - 运行 SAST/Secrets（SARIF + JSON）
  - 合并 `sast.json` + `secrets.json` 为 `findings.json`
  - 执行 `policy` 门禁（高危/严重即失败）
  - 上传两个 SARIF 文件

作用：将本地扫描能力嵌入 PR 流程，保证“提交即扫描”。

### `.gitignore`
职责：过滤运行时与编译缓存。

结构说明：
- 忽略 `.venv/`
- 忽略 `__pycache__/`
- 忽略 `*.pyc`

### `Makefile`
职责：本地开发与验证的一键入口。

结构说明：
- `setup`：创建虚拟环境并升级 pip
- `scan`：
  - 运行 SAST 和 Secrets（允许存在漏洞继续产物生成）
  - 合并 findings
  - 生成 HTML + summary
  - 应用 baseline
  - 同步 governance DB
- `gate`：仅执行策略门禁（失败返回非 0）
- `test`：`unittest discover`
- `run-demo`：启动 Flask 演示应用
- `artifacts`：仅针对 `demo_app` 生成 SARIF

设计意图：把“产物生成”和“策略失败”拆开，便于调试与演示。

### `pyproject.toml`
职责：Python 项目元数据与打包入口。

结构说明：
- `build-system`：setuptools + wheel
- `project`：名称 `secscan`、版本 `0.1.0`、Python 要求 `>=3.11`
- `project.scripts`：`secscan = secscan.cli:main`
- `tool.setuptools.packages`：明确声明包路径

说明：当前本地流程主要通过 `python -m secscan.cli` 调用。

### `policy.yml`
职责：策略即代码，定义门禁规则。

结构说明：
- `max_severity: medium`（当前 CLI 仅读取 `fail_on_severities`）
- `fail_on_severities: [high, critical]`

### `findings_db.json`
职责：治理数据库（JSON 版）。

结构说明：
- 根键：`items`
- 每条记录键：finding 指纹（sha256）
- 每条记录字段：`id`、`title`、`severity`、`file`、`line_start`、`status`、`owner`、`first_seen`、`last_seen`

当前状态：文件较大，因为历史扫描曾包含对 `findings_db.json` 自身的 secrets 扫描结果。

---

## 2. 包入口与通用模型

### `secscan/__init__.py`
职责：包版本导出。

结构说明：
- `__version__ = "0.1.0"`
- `__all__ = ["__version__"]`

### `secscan/models.py`
职责：统一 finding 数据模型。

结构说明：
- `@dataclass(frozen=True) class Finding`
- 字段覆盖：ID、标题、描述、风险等级、置信度、定位信息、代码片段、OWASP 类别、修复建议
- `to_dict()`：序列化为字典

意义：将规则输出规范化，减少下游 reporting/governance 的耦合。

### `secscan/utils.py`
职责：跨模块基础工具。

结构说明：
- 严重度等级映射：`SEVERITY_ORDER`
- `normalize_severity`：统一大小写
- `severity_at_least`：阈值比较
- `iter_files`：递归枚举 + exclude 过滤 + 排序
- `read_text`：容错读取文本
- `fingerprint`：finding 稳定标识
- `save_json`：有序、缩进输出 JSON
- `ensure_dir`：确保目录存在

设计点：排序与固定序列化保证“结果可复现”。

---

## 3. CLI 与流程编排

### `secscan/cli.py`
职责：统一命令入口、参数解析、子命令调度、退出码管理。

结构说明：
- 常量退出码：
  - `EXIT_OK = 0`
  - `EXIT_POLICY = 1`
  - `EXIT_ERROR = 2`
- 辅助函数：
  - `_parse_exclude`：逗号分隔转列表
  - `_load_findings`：加载 JSON findings
  - `_load_policy`：轻量 YAML 解析（支持键值和简单列表）
  - `_emit`：按 `json|sarif` 输出到 stdout 或文件
- 子命令实现：
  - `cmd_sast`
  - `cmd_secrets`
  - `cmd_report`
  - `cmd_baseline`
  - `cmd_policy`
  - `cmd_sync`
  - `cmd_dast`
- `build_parser()`：注册全部子命令与共用参数
- `main()`：统一异常处理，将 RuntimeError 映射为退出码 2

关键流程关系：
- `sast/secrets` -> 调用 scanners -> 过滤 severity -> 输出
- `report` -> 读 findings -> 生成 `report.html` + `summary.json`
- `baseline` -> 用 fingerprints 抑制已知项
- `policy` -> 读取策略并 gate
- `sync` -> 更新治理 DB
- `dast` -> 对目标 URL 做反射 XSS 与 SSRF 行为探测

DAST 设计：使用标准库 `urllib`，避免额外依赖。

---

## 4. 扫描执行层

### `secscan/scanners.py`
职责：组织扫描执行，遍历文件并调用具体规则。

结构说明：
- `RULES`：SAST 规则函数列表
- `_relative`：把绝对路径映射为 repo 相对路径
- `run_sast(path, exclude)`：
  - 仅处理 `.py`
  - `ast.parse` 失败则跳过
  - 对同一 AST 依次应用规则
  - 最终按 `(file, line_start, id)` 排序
- `run_secrets(path, exclude)`：
  - 跳过二进制后缀
  - 全文本扫描
  - 对 `(id, file, line, snippet)` 去重

设计重点：
- 规则无状态、可组合
- 统一排序保证输出稳定

---

## 5. 规则模块（`secscan/rules/`）

### `secscan/rules/__init__.py`
职责：集中导出规则函数。

结构说明：
- 导入并暴露 5 个 SAST 检测函数
- 便于 scanner 一处注册

### `secscan/rules/common.py`
职责：规则公共 AST 工具函数。

结构说明：
- `get_snippet`：按行截取代码片段
- `get_attr_chain`：把 AST 调用对象解析成 `module.attr.func` 字符串
- `node_contains_user_input`：识别常见用户输入源（`request.args/form/values/json`、`input()`）
- `is_string_build`：识别拼接、f-string、`format`

这是规则层“语义识别”的基础。

### `secscan/rules/sql_injection.py`
职责：SQL 注入启发式检测。

结构说明：
- 命中目标：`execute` / `executemany`
- 仅对动态字符串构造判定（f-string、拼接、format）
- SQL 关键词二次过滤（`select/insert/update/...`）降低误报
- 若检测到用户输入参与，提升为 `critical/high confidence`
- 输出 `SEC-SQLI-001`

### `secscan/rules/xss.py`
职责：反射型 XSS 与不安全动态模板检测。

结构说明：
- 分支一：`return` 返回值包含字符串构造 + 用户输入
- 分支二：`render_template_string(...)` 参数中有用户输入
- 输出：
  - `SEC-XSS-001`（反射型）
  - `SEC-XSS-002`（动态模板）

### `secscan/rules/ssrf.py`
职责：SSRF 行为检测。

结构说明：
- 目标函数：`requests.get/post/put/delete/head/request`
- 轻量 taint：先收集“由用户输入赋值”的变量名
- 调用时若 URL 参数直接或间接可控则命中
- 输出 `SEC-SSRF-001`

### `secscan/rules/insecure_deserialization.py`
职责：不安全反序列化检测。

结构说明：
- 命中 `pickle.loads/load` -> `SEC-DESER-001`（critical）
- 命中 `yaml.load` 且未显式 `yaml.SafeLoader` -> `SEC-DESER-002`

### `secscan/rules/command_injection.py`
职责：命令注入风险检测。

结构说明：
- 目标函数：`os.system/os.popen/subprocess.*`
- 关键信号：
  - `shell=True`
  - 字符串命令参数
  - 用户输入参与
- 严重度策略：`shell=True + user input` 提升为 critical
- 输出 `SEC-CMDI-001`

### `secscan/rules/secrets.py`
职责：硬编码敏感信息检测。

结构说明：
- `SECRET_PATTERNS`：
  - 通用 key/token/secret
  - password
  - AWS Access Key
  - GitHub PAT
- 高熵策略：
  - 正则抽取长字符串
  - Shannon entropy >= 3.8 判定疑似 secret
- 输出：
  - `SEC-SECRET-001/002/003/004`
  - `SEC-SECRET-ENTROPY`

注意：entropy 规则偏启发式，误报会高于明确规则。

---

## 6. 报告模块（`secscan/reporting/`）

### `secscan/reporting/sarif.py`
职责：将 findings 转为 SARIF 2.1.0。

结构说明：
- `RULE_MAP`：内部规则 ID -> SARIF rule 名称
- `SARIF_LEVEL`：severity 到 `note/warning/error` 映射
- `to_sarif(findings)`：
  - 聚合 `tool.driver.rules`
  - 生成 `results`（ruleId、level、message、location）
  - 输出符合 GitHub Code Scanning 可消费的结构

### `secscan/reporting/html.py`
职责：生成人可读 HTML 汇总报告。

结构说明：
- 统计 severity 分布
- 构造 findings 表格行
- 使用 `html.escape` 防止展示层注入
- 内联简洁 CSS，单文件可直接打开

输出文件：`artifacts/report.html`。

---

## 7. 治理模块（`secscan/governance/`）

### `secscan/governance/__init__.py`
职责：导出治理同步函数。

### `secscan/governance/sync.py`
职责：对 findings 与 DB 做增量同步。

结构说明：
- 输入：当前 findings + 历史 db
- 过程：
  - 对每条 finding 计算 fingerprint
  - 已存在条目：更新 `last_seen`，`FIXED` 回归 `OPEN`
  - 新条目：创建并置 `OPEN`
  - 历史 `OPEN` 若本次未出现：置 `FIXED`
- 输出：更新后的 DB 对象

业务语义：支持“漏洞生命周期”追踪，而不只是“瞬时扫描结果”。

---

## 8. 演示应用与依赖

### `demo_app/app.py`
职责：故意包含漏洞的 Flask 演示服务，用于验证规则与报告链路。

结构说明：
- `/health`：健康检查
- `/user`：f-string SQL（SQLi）
- `/search`：反射返回 HTML（XSS）
- `/proxy`：请求用户 URL（SSRF）
- `/deserialize`：`pickle.loads`（不安全反序列化）
- `/yaml`：`yaml.load` 无 SafeLoader
- `/run`：`subprocess(..., shell=True)` + `os.system`（命令注入）
- 文件级别硬编码 token/password（Secrets）

### `demo_app/requirements.txt`
职责：演示应用运行依赖声明。

结构说明：
- `flask`
- `requests`
- `PyYAML`

说明：扫描器本体已尽量减少运行时依赖。

---

## 9. 测试文件

### `tests/test_rules.py`
职责：规则核心能力单测。

结构说明：
- 使用 `tempfile` 动态创建最小漏洞样本
- 覆盖检测：
  - SQLi
  - SSRF
  - Command Injection
  - Insecure Deserialization
  - Secrets
- 断言方式：扫描结果中存在对应规则 ID

### `tests/test_sarif.py`
职责：SARIF 序列化结构测试。

结构说明：
- 构造最小 findings 样本
- 断言 `version == 2.1.0`
- 断言结果 `ruleId` 正确

---

## 10. 文档文件

### `README.md`
职责：英文主文档。

结构说明：
- Quickstart
- CLI 命令
- 规则与治理说明
- CI 门禁说明
- 新增规则指南
- 示例产物
- Resume bullets

### `README.zh-CN.md`
职责：中文主文档，对齐英文版能力说明。

结构说明：
- 与英文版对应的中文化使用与设计说明

---

## 11. 产物文件（`artifacts/`）

以下文件为扫描执行后的示例输出，会随扫描范围与时间变化。

### `artifacts/baseline.json`
职责：基线抑制配置。

结构说明：
- `fingerprints: []`（当前为空）

### `artifacts/sast.json`
职责：SAST 原始 findings。

结构说明：
- 根键：`findings`
- 当前条数：`5`
- 每条字段：`id/title/description/severity/confidence/file/line_start/line_end/code_snippet/owasp_category/remediation`

### `artifacts/secrets.json`
职责：Secrets 扫描 findings。

结构说明：
- 根键：`findings`
- 当前条数：`69`
- 字段结构与 `sast.json` 相同

### `artifacts/findings.json`
职责：合并后的总 findings（SAST + Secrets）。

结构说明：
- 根键：`findings`
- 当前条数：`74`

### `artifacts/findings.filtered.json`
职责：应用 baseline 后的 findings。

结构说明：
- 根键：`findings`
- 当前条数：`74`（因为 baseline 为空）

### `artifacts/summary.json`
职责：报告摘要统计。

结构说明：
- `total`
- `by_severity`（critical/high/medium/low）

### `artifacts/report.html`
职责：可视化摘要报告。

结构说明：
- 顶部统计卡片（总数 + 各级别）
- 表格列：ID / Severity / OWASP / Location / Title
- 当前示例显示 74 条 findings

### `artifacts/sast.sarif`
职责：SAST SARIF 上报文件。

结构说明：
- `version: 2.1.0`
- `runs[0].tool.driver.rules`
- `runs[0].results`
- 当前：`results=5, rules=4`

### `artifacts/secrets.sarif`
职责：Secrets SARIF 上报文件。

结构说明：
- 与 `sast.sarif` 同构
- 当前：`results=4, rules=4`（面向 demo_app 产物）

---

## 12. 关键调用链（从命令到结果）

以 `make scan` 为例：
- `Makefile` 调用 `python -m secscan.cli sast/secrets`
- `cli.py` 调用 `scanners.py`
- `scanners.py` 对每个文件调用 `rules/*.py`
- findings 回到 `cli.py` 输出 JSON
- 合并后再调用：
  - `report` -> `reporting/html.py` + `summary.json`
  - `baseline` -> `utils.fingerprint`
  - `sync` -> `governance/sync.py`

以 CI 为例：
- GitHub Actions 调用同样的 CLI 命令
- 再执行 `policy` 判定是否阻断
- 上传 SARIF 到 Code Scanning

---

## 13. 现状与可优化点（代码结构视角）

- `cli.py` 目前包含较多子命令逻辑，可进一步拆分为 `commands/` 子模块。
- `_load_policy` 为轻量解析器，若需要复杂 YAML（嵌套/类型）建议恢复 `PyYAML`。
- `policy.yml` 中 `max_severity` 尚未参与执行逻辑，可补齐规则一致性。
- `findings_db.json` 建议默认加入扫描排除，减少“数据库自扫描”噪声。
- 规则层可引入更系统的 taint 传播，降低 SSRF/命令注入漏报和误报。

