# SPEAR CLI Reference

> **Version**: 0.1.0
> **Runtime**: Node.js 22+
> **Binary**: `spear` (or `node apps/cli/bin/run.js`)

## Commands Overview

| Command | Description | Network | Cost |
|---------|-------------|---------|------|
| `scan` | Static security scan | No | $0 |
| `test` | Run attack test modules | No | $0 |
| `audit` | Full audit + HTML report + CVSS score | No | $0 |
| `attack` | Live attack against remote target | **Yes** | $0~$0.50 |
| `fuzz` | Prompt injection fuzzing | Configurable | $0 |
| `report` | Generate report from DB | No | $0 |
| `init` | Initialize project | No | $0 |
| `config get` | Read config value | No | $0 |
| `config set` | Write config value | No | $0 |
| `config list` | Show all config | No | $0 |

---

## `spear scan`

Run a security scan against a target directory.

```bash
spear scan [target]
```

### Arguments

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `target` | No | `.` | Target directory to scan |

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--module` | `-m` | string[] | all | Specific module(s) to run |
| `--mode` | | `safe\|aggressive` | safe | Scan mode |
| `--output` | `-f` | `text\|sarif\|json` | text | Output format |
| `--output-file` | `-o` | string | | Write report to file |
| `--git-depth` | | integer | 1000 | Git commits to scan (0=HEAD, -1=unlimited) |
| `--verbose` | `-v` | boolean | false | Verbose logging |
| `--rules-dir` | | string | | Custom rules directory |

### Pipeline

1. Load config (`.spearrc.yaml` + CLI overrides)
2. Initialize SQLite DB (`.spear/spear.db`)
3. Load YAML rules
4. Run scan pipeline (Aho-Corasick -> Regex -> Entropy)
5. Collect findings, persist to DB
6. Generate report (text/SARIF/JSON)

### Examples

```bash
# Scan current directory
spear scan

# Scan specific project
spear scan ./my-project

# Aggressive mode with SARIF output
spear scan --mode aggressive --output sarif

# Single module, JSON output to file
spear scan --module secret-scanner --output json -o report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical/high findings |
| 1 | Critical or high findings detected |
| 2 | Scan failed |

---

## `spear attack`

Run live attack modules against a target URL. Sends actual HTTP requests.

```bash
spear attack <target>
```

### Arguments

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `target` | **Yes** | | Target URL or MCP server command |

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--module` | `-m` | string | all | Attack module to run |
| `--api-key` | | string | | API key for authenticated endpoints |
| `--timeout` | | integer | 30000 | Request timeout (ms) |
| `--max-requests` | | integer | 100 | Maximum requests to send |
| `--verbose` | `-v` | boolean | false | Verbose logging |
| `--source-dir` | | string | `.` | Source directory for hybrid mode |
| `--header` | `-H` | string[] | | Custom headers (`"Key: Value"`) |

### Available Modules

| Module Name | Plugin | What It Does |
|-------------|--------|-------------|
| `prompt-inject` | Spear-23 | Prompt injection via HTTP, WebSocket, or relay chain |
| `mcp-live` | Spear-24 | MCP server tool poisoning test |
| `endpoint-prober` | Spear-25 | Cloud discovery, OpenAPI, auth bypass, vector DB, debug scan |
| `all` | All | Run all live attack modules |

### Module Name Mapping

CLI에서 사용하는 이름과 내부 플러그인 ID 매핑:

| CLI `--module` | Internal Plugin ID |
|----------------|--------------------|
| `prompt-inject` | `live-prompt-inject` |
| `mcp-live` | `mcp-live-test` |
| `endpoint-prober` | `endpoint-prober` |

### Examples

```bash
# Prompt injection on OpenAI-compatible endpoint
spear attack https://api.openai.com/v1/chat/completions \
  --module prompt-inject \
  --api-key sk-...

# MCP server live test
spear attack https://mcp.example.com --module mcp-live

# Endpoint probing with source code analysis
spear attack https://myapp-abc123-uc.a.run.app \
  --module endpoint-prober \
  --source-dir ./myapp \
  --max-requests 200

# WebSocket attack
spear attack wss://relay-server.com/stream \
  --module prompt-inject \
  --max-requests 5

# Relay chain attack with custom headers
spear attack https://relay-server.com \
  --module prompt-inject \
  --header "X-Relay-Phone:+821012345678" \
  --header "X-Relay-Mode:text_to_voice" \
  --max-requests 5

# All modules at once
spear attack https://target.com --source-dir ./repo -v
```

### Transport Auto-Detection (Spear-23)

`--module prompt-inject` 사용 시, 타겟 URL과 헤더에 따라 자동으로 전송 방식을 결정:

| Condition | Transport | Method |
|-----------|-----------|--------|
| `wss://` or `ws://` URL | WebSocket | Direct WS connection |
| `X-Relay-Phone` header or `/relay/` in URL | Relay Chain | REST -> WS bridge |
| Otherwise | HTTP | Direct POST to endpoint |

### Endpoint Prober Phases (Spear-25)

`--module endpoint-prober` 실행 시 6단계 스캔:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Source Analysis | 소스 코드에서 라우트 정의 추출 |
| 2 | Cloud Discovery | Cloud Run 서비스 브루트포스 |
| 3a | OpenAPI Scan | Swagger/OpenAPI 스펙 자동 발견 |
| 3b | AI Infra Scan | MLflow, Qdrant, Chroma 등 AI 인프라 스캔 |
| 3c | Debug Scan | `/actuator`, `/.env`, `/debug/pprof` 등 |
| 4 | Auth Probe | 엔드포인트별 인증 우회 테스트 |

---

## `spear audit`

Full security audit. Runs scan + calculates CVSS score + generates HTML report.

```bash
spear audit [target]
```

### Arguments

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `target` | No | `.` | Target directory to audit |

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--module` | `-m` | string[] | all | Specific module(s) to run |
| `--mode` | | `safe\|aggressive` | safe | Scan mode |
| `--output-file` | `-o` | string | `.spear/report.html` | HTML report output path |
| `--verbose` | `-v` | boolean | false | Verbose logging |
| `--rules-dir` | | string | | Custom rules directory |

### Output

- Terminal: 보안 등급 (A~F), 점수 (/100), 모듈별 패널티 브레이크다운
- File: HTML 리포트 (`.spear/report.html`)

### Security Grade

| Grade | Score Range |
|-------|------------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

### Examples

```bash
# Audit current directory
spear audit

# Audit with custom report path
spear audit ./my-project --output-file ./custom-report.html

# Aggressive mode
spear audit --mode aggressive
```

---

## `spear test`

Run AI/MCP static attack test modules. Uses the plugin registry to load all 22 attack modules.

```bash
spear test
```

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--module` | `-m` | string | all | Specific attack module |
| `--mode` | | `safe\|aggressive` | safe | Test mode |
| `--verbose` | `-v` | boolean | false | Verbose logging |
| `--rules-dir` | | string | | Custom rules directory |
| `--target` | `-t` | string | `.` | Target directory |

### Available Modules (Static)

| Module ID | Name |
|-----------|------|
| `secret-scanner` | Spear-01: Secret Scanner |
| `git-miner` | Spear-02: Git Miner |
| `env-exfil` | Spear-03: Env Exfiltrator |
| `mcp-poisoner` | Spear-04: MCP Poisoner |
| `dep-confusion` | Spear-05: Dependency Confusion |
| `prompt-injector` | Spear-06: Prompt Injector |
| `supply-chain` | Spear-08: Supply Chain |
| `agent-manipulator` | Spear-10: Agent Manipulator |
| `cicd-exploiter` | Spear-11: CI/CD Exploiter |
| `container-audit` | Spear-12: Container Audit |
| `cloud-credential` | Spear-13: Cloud Credential |
| `ssrf-tester` | Spear-14: SSRF Tester |
| `ide-audit` | Spear-15: IDE Audit |
| `webhook-scanner` | Spear-16: Webhook Scanner |
| `llm-exploiter` | Spear-17: LLM Exploiter |
| `tls-recon` | Spear-18: TLS Recon |
| `social-eng` | Spear-19: Social Engineer |
| `distillation` | Spear-21: Distillation |
| `infra-intel` | Spear-22: Infra Intel |

### Examples

```bash
# Run all modules
spear test

# Single module
spear test --module secret-scanner

# Aggressive mode with git history scan
spear test --module git-miner --mode aggressive

# Scan different directory
spear test --target ./other-project
```

---

## `spear fuzz`

Prompt injection fuzzing with multiple payload sets.

```bash
spear fuzz
```

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--module` | `-m` | string | `prompt-injector` | Fuzzing module |
| `--payloads` | `-p` | string | `all` | Payload sets (comma-separated) |
| `--mode` | | `safe\|aggressive` | safe | Fuzz mode |
| `--verbose` | `-v` | boolean | false | Verbose logging |
| `--target` | `-t` | string | `.` | Target directory or endpoint |
| `--iterations` | `-n` | integer | 1 | Iterations per payload |

### Payload Sets

| Set | Description |
|-----|-------------|
| `houyi` | Houyi prompt injection payloads |
| `aishellJack` | AiShell Jack adversarial payloads |
| `all` | All payload sets combined |

### Output

- Finding 별 실시간 출력
- MITRE ATT&CK Kill Chain Coverage 테이블
- Severity 별 카운트 요약

### Examples

```bash
# All payloads, dry-run
spear fuzz

# Houyi payloads only
spear fuzz --payloads houyi

# Multiple sets, aggressive mode
spear fuzz --payloads houyi,aishellJack --mode aggressive

# Multiple iterations
spear fuzz --payloads all -n 5
```

---

## `spear report`

Generate a report from a previously completed scan stored in the DB.

```bash
spear report
```

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | `sarif\|json` | json | Output format |
| `--scan-id` | `-s` | string | (most recent) | Scan ID |
| `--output` | `-o` | string | stdout | Write to file |
| `--verbose` | `-v` | boolean | false | Verbose logging |

### Examples

```bash
# JSON report to stdout (most recent scan)
spear report

# SARIF format to file
spear report --format sarif -o results.sarif.json

# Specific scan ID
spear report --scan-id scan_abc123 --format json -o report.json
```

---

## `spear init`

Initialize SPEAR in a project directory. Creates config files. Idempotent.

```bash
spear init [directory]
```

### Arguments

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `directory` | No | `.` | Target directory |

### Created Files

| File | Description |
|------|-------------|
| `.spear/` | Local DB and cache directory |
| `.spearignore` | File ignore patterns (gitignore syntax) |
| `.spearrc.yaml` | Configuration file |

### Examples

```bash
# Initialize current directory
spear init

# Initialize specific path
spear init /path/to/project
```

---

## `spear config`

Configuration management subcommands.

### `spear config get <key>`

Read a single configuration value.

```bash
spear config get mode
spear config get gitDepth
spear config get outputFormat
```

### `spear config set <key> <value>`

Write a configuration value to `.spearrc.yaml`.

```bash
spear config set mode aggressive
spear config set gitDepth 500
spear config set verbose true
spear config set outputFormat sarif
```

### `spear config list`

Display all effective configuration values.

```bash
spear config list
```

### Valid Configuration Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `safe\|aggressive` | `safe` | Scan mode |
| `verifyLimit` | integer | 100 | Max secrets to live-verify |
| `maxWorkers` | integer | 0 (auto) | Worker threads |
| `gitDepth` | integer | 1000 | Git commits to scan |
| `outputFormat` | `text\|json\|sarif` | `text` | Output format |
| `dbPath` | string | `.spear/spear.db` | Database path |
| `rulesDir` | string | (empty) | Custom rules directory |
| `verbose` | boolean | `false` | Verbose logging |

---

## Scan Modes

| Mode | Network | Description |
|------|---------|-------------|
| `safe` | No | Read-only analysis. No network calls, no live verification. |
| `aggressive` | Yes | Enables live secret verification, network probing. |

`attack` 명령은 항상 `aggressive` 모드로 강제 실행된다.

---

## Data Storage

모든 스캔 결과는 SQLite DB에 저장된다:

| Table | Description |
|-------|-------------|
| `scans` | 스캔 기록 (ID, target, mode, status, severity counts, duration) |
| `findings` | 개별 발견 항목 (rule ID, severity, file, line, CVSS, MITRE, remediation) |
| `audit_log` | 감사 로그 (이벤트 타입, timestamp) |

DB 경로: `.spear/spear.db` (설정으로 변경 가능)

---

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| `text` | `--output text` | Terminal-friendly colored output with severity icons |
| `json` | `--output json` | Machine-readable JSON with full metadata |
| `sarif` | `--output sarif` | SARIF 2.1.0 format (GitHub, VS Code compatible) |
| `html` | `audit` only | HTML report with security score and charts |

---

## Typical Workflows

### 1. Static Analysis (CI/CD)

```bash
spear init
spear scan --output sarif -o results.sarif.json
# Exit code 1 if critical/high findings -> fail pipeline
```

### 2. Full Security Audit

```bash
spear init
spear audit
open .spear/report.html
```

### 3. Live Penetration Test

```bash
# Step 1: Static analysis first
spear scan ./target-repo

# Step 2: Endpoint discovery + auth probing
spear attack https://target.run.app \
  --module endpoint-prober \
  --source-dir ./target-repo \
  --max-requests 200

# Step 3: Prompt injection on discovered LLM endpoint
spear attack https://target.run.app/v1/chat/completions \
  --module prompt-inject \
  --api-key sk-... \
  --max-requests 10
```

### 4. Relay Chain Attack

```bash
spear attack https://relay-server.com \
  --module prompt-inject \
  --header "X-Relay-Phone:+821012345678" \
  --header "X-Relay-Mode:text_to_voice" \
  --max-requests 5
```
