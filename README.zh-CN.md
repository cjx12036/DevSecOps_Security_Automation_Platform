# DevSecOps 安全自动化平台（原型）

一个实用的 Python 3.11+ 安全自动化原型，面向 SDLC 集成，覆盖 OWASP Top 10 典型检测、CI 策略门禁与治理追踪。

## 功能概览
- 自动化 SAST + Secrets 扫描（`secscan` CLI）
- 可选轻量 DAST（反射型 XSS、SSRF 代理行为）
- 多格式输出：JSON、SARIF（GitHub Code Scanning）、HTML
- 治理状态追踪：`OPEN`、`FIXED`、`ACCEPTED_RISK`

## 快速开始
```bash
make setup
make scan
```

说明：`make scan` 总是生成报告产物；本地策略门禁请执行：
```bash
make gate
```

启动演示应用：
```bash
make run-demo
```

## CLI 命令
```bash
python -m secscan.cli sast --path <repo> [--format json|sarif] [--severity-threshold low|medium|high|critical] [--exclude ".venv,dist,build,node_modules"]
python -m secscan.cli secrets --path <repo> [--format json|sarif] [--severity-threshold low|medium|high|critical] [--exclude ".venv,dist,build,node_modules"]
python -m secscan.cli report --input <json> --out <dir>
python -m secscan.cli baseline --input <json> --baseline <file>
python -m secscan.cli policy --input <json> --policy <yaml>
python -m secscan.cli sync --input <json> --db findings_db.json
python -m secscan.cli dast --url http://localhost:5000 [--format json|sarif]
```

## 检测规则（OWASP Top 10 对齐）
已实现规则：
- SQL Injection：检测 `execute`/`executemany` 中字符串拼接、f-string、format 等动态 SQL
- XSS：检测用户输入直接拼接到 HTML 返回或动态模板渲染
- SSRF：检测用户可控 URL 直接发起外联请求（无明显 allowlist）
- 硬编码敏感信息：关键字正则（token/password/key）+ 高熵字符串启发式
- 不安全反序列化：`pickle.loads`、`yaml.load`（未使用 `SafeLoader`）
- 命令注入：`os.system`、`subprocess.*` 中 `shell=True` 或不安全字符串命令

每条发现都包含：
- `id`, `title`, `description`
- `severity`, `confidence`
- `file`, `line_start`, `line_end`, `code_snippet`
- `owasp_category`, `remediation`

## 治理追踪
执行 `sync` 将当前扫描结果写入/更新 `findings_db.json`：
- 新发现：标记 `OPEN`
- 旧 `OPEN` 未再出现：标记 `FIXED`
- `ACCEPTED_RISK` 保留
- 同时维护 `first_seen`、`last_seen`、可选 `owner`

## Baseline 与策略门禁
- `baseline`：基于 finding 指纹进行抑制（已知风险白名单）
- `policy`：按 `policy.yml` 强制门禁（默认拦截 high/critical）
- 退出码约定：
  - `0`：无策略违规
  - `1`：存在策略违规
  - `2`：运行时/配置错误

## CI 集成（GitHub Actions）
工作流文件：`.github/workflows/security-scan.yml`
- 触发：`push`、`pull_request`
- 执行：`sast` + `secrets`
- 上传：SARIF 到 GitHub Code Scanning
- 门禁：合并 JSON 后执行策略检查，高/严重漏洞使流水线失败

## 如何新增规则
1. 在 `secscan/rules/` 新增规则模块，返回 `list[Finding]`
2. 在 `secscan/rules/__init__.py` 与 `secscan/scanners.py` 注册
3. 在 `tests/` 增加检测与边界单测
4. 如需 SARIF 命名映射，补充 `secscan/reporting/sarif.py`

## 示例产物
扫描产物可通过 `make scan` 本地生成到 `artifacts/`（该目录已加入 git 忽略）：
- `artifacts/findings.json`
- `artifacts/report.html`
- `artifacts/sast.sarif`
- `artifacts/secrets.sarif`

