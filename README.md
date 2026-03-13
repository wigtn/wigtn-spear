# WIGTN-SPEAR

**AI Service Security Scanner** — Offensive security testing for the age of vibe coding.

```
$ spear attack https://your-ai-service.run.app --source-dir ./your-repo

  SPEAR v0.1.0 — AI Service Security Scanner

  [1/5] Source code analysis .............. 847 findings
  [2/5] Cloud service discovery ........... 2 sibling services found
  [3/5] OpenAPI/Swagger scan .............. API spec extracted (12 endpoints)
  [4/5] AI infrastructure scan ............ Qdrant DB exposed (no auth)
  [5/5] Live endpoint probing ............. 3 critical, 8 high

  53 findings in 31.2s | $0.00 cost
```

## What It Does

SPEAR finds security vulnerabilities in AI-powered services that traditional scanners miss.

| Traditional Scanners | SPEAR |
|---------------------|-------|
| Check npm dependencies | Steal your system prompt |
| Scan for SQL injection | Find your hidden relay server |
| Test HTTP auth | Probe your vector database |
| Read CVE databases | Extract your OpenAPI spec |

## OWASP Coverage

**LLM Top 10: 10/10 | Web Top 10: 10/10**

### OWASP Top 10 for LLM Applications

| # | Vulnerability | Module | Method |
|---|--------------|--------|--------|
| LLM01 | Prompt Injection | Spear-23 | 27 payloads via HTTP/WebSocket/Relay chain |
| LLM02 | Sensitive Info Disclosure | Spear-23 | System prompt extraction attacks |
| LLM03 | Supply Chain | Spear-08 | Dependency confusion, typosquatting detection |
| LLM04 | Data & Model Poisoning | Spear-25 | MLflow, Ollama, LangServe, Triton endpoint scan |
| LLM05 | Insecure Output Handling | Spear-23 | Output manipulation payloads |
| LLM06 | Excessive Agency | Spear-10 | Agent tool abuse analysis |
| LLM07 | System Prompt Leakage | Spear-23 | 5 extraction techniques |
| LLM08 | Vector & Embedding Weaknesses | Spear-25 | Qdrant, Weaviate, Chroma, Milvus, Pinecone scan |
| LLM09 | Misinformation | Spear-23 | Factual inversion, citation fabrication, medical misinfo |
| LLM10 | Unbounded Consumption | Spear-25 | Rate limiting detection |

### OWASP Top 10 for Web Applications

| # | Vulnerability | Module |
|---|--------------|--------|
| A01 | Broken Access Control | Spear-25 (10 auth bypass techniques) |
| A02 | Cryptographic Failures | Spear-18 (TLS recon) |
| A03 | Injection | Spear-23 (prompt injection) |
| A04 | Insecure Design | Spear-25 (OpenAPI exposure, dangerous params) |
| A05 | Security Misconfiguration | Spear-25 (Swagger, Cloud Run discovery, CORS) |
| A06 | Vulnerable Components | Spear-08, Spear-05 |
| A07 | Auth Failures | Spear-25 (token probing) |
| A08 | Software Integrity | Spear-11 (CI/CD pipeline analysis) |
| A09 | Logging Failures | Spear-25 (debug/actuator/pprof/env scanner) |
| A10 | SSRF | Spear-14 |

## Attack Modules

### Static Analysis (no network, $0)

| Module | Name | What It Finds |
|--------|------|---------------|
| Spear-01 | Secret Scanner | API keys, tokens, passwords in source code |
| Spear-02 | Git Miner | Secrets in git history and deleted commits |
| Spear-03 | Env Exfiltrator | Exposed .env files and environment variables |
| Spear-04 | MCP Poisoner | Malicious MCP server configurations |
| Spear-05 | Dep Confusion | Dependency confusion attack vectors |
| Spear-06 | Prompt Injector | Static prompt injection vulnerability patterns |
| Spear-08 | Supply Chain | Vulnerable dependencies, typosquatting |
| Spear-10 | Agent Manipulator | AI agent tool abuse patterns |
| Spear-11 | CI/CD Exploiter | Pipeline injection, secret exposure in CI |
| Spear-12 | Container Audit | Dockerfile security issues |
| Spear-13 | Cloud Credential | Cloud provider credential chains |
| Spear-14 | SSRF Tester | Server-side request forgery patterns |
| Spear-15 | IDE Audit | VS Code extension and IDE config vulnerabilities |
| Spear-16 | Webhook Scanner | Exposed webhook endpoints and secrets |
| Spear-17 | LLM Exploiter | LLM output handling vulnerabilities |
| Spear-18 | TLS Recon | TLS/SSL configuration analysis |
| Spear-19 | Social Engineer | Social engineering attack surface |
| Spear-21 | Distillation | Model distillation/theft indicators |
| Spear-22 | Infra Intel | Infrastructure information extraction |

### Live Attack (network required, cost varies)

| Module | Name | What It Does |
|--------|------|-------------|
| Spear-23 | Live Prompt Inject | Sends 27 injection payloads via HTTP, WebSocket, or REST-to-WS relay chain |
| Spear-24 | MCP Live Test | Tests MCP server tool poisoning in real-time |
| Spear-25 | Endpoint Prober | Cloud service discovery, OpenAPI extraction, auth bypass, vector DB scan, debug endpoint scan |

## Quick Start

```bash
# Install
pnpm install

# Build
pnpm turbo build

# Static scan (safe, no network)
node apps/cli/bin/run.js scan ./path-to-target-repo

# Live attack (sends actual requests)
node apps/cli/bin/run.js attack https://target-url.com \
  --source-dir ./target-repo \
  --module endpoint-prober \
  --max-requests 100 \
  -v
```

## Live Attack Examples

### Endpoint Probing (discovers hidden services, APIs, auth gaps)

```bash
# Scan a Cloud Run service — auto-discovers sibling services
spear attack https://myapp-abc123-uc.a.run.app \
  --module endpoint-prober \
  --source-dir ./myapp \
  --max-requests 200

# What happens:
#   1. Source code analysis → finds route definitions
#   2. Cloud Run brute-force → finds hidden services (relay, api, admin)
#   3. OpenAPI scan → extracts full API spec from /docs or /openapi.json
#   4. AI infra scan → finds exposed MLflow, Qdrant, Chroma endpoints
#   5. Debug scan → finds /actuator, /.env, /debug/pprof
#   6. Auth probe → tests each endpoint with no-auth, invalid-token, bypass techniques
```

### Prompt Injection (tests LLM endpoints)

```bash
# Direct HTTP attack against OpenAI-compatible endpoint
spear attack https://my-llm-api.com/v1/chat/completions \
  --module live-prompt-inject \
  --api-key "sk-your-key" \
  --max-requests 10

# WebSocket attack against relay service
spear attack wss://relay-server.com/stream \
  --module live-prompt-inject \
  --max-requests 5

# Full relay chain attack (REST → WS)
spear attack https://relay-server.com \
  --module live-prompt-inject \
  --header "X-Relay-Phone:+821012345678" \
  --header "X-Relay-Mode:text_to_voice" \
  --max-requests 5
```

## Architecture

```
wigtn-spear/
├── apps/
│   └── cli/                    # CLI application (oclif)
├── packages/
│   ├── shared/                 # Types, interfaces, constants
│   ├── core/                   # Scan engine, rate limiter
│   ├── db/                     # SQLite persistence (drizzle)
│   ├── plugin-system/          # Plugin registry and lifecycle
│   ├── rules-engine/           # Finding classification
│   ├── reporters/              # HTML, JSON, SARIF reporters
│   └── plugins/                # 22 attack modules
│       ├── spear-01-secret-scanner/
│       ├── spear-02-git-miner/
│       ├── ...
│       └── spear-25-endpoint-prober/
│           ├── endpoint-discovery.ts      # Source code route extraction
│           ├── cloud-service-discovery.ts  # Cloud Run service enumeration
│           ├── openapi-scanner.ts          # Swagger/OpenAPI auto-discovery
│           ├── ai-infra-scanner.ts         # MLflow, vector DB scanning
│           ├── debug-scanner.ts            # Debug/logging endpoint scan
│           └── probe-engine.ts             # Live HTTP auth probing
└── turbo.json
```

## Tech Stack

- **Runtime**: Node.js 22+ (built-in fetch, WebSocket)
- **Language**: TypeScript 5.4 (strict mode)
- **Build**: Turborepo (monorepo), pnpm (workspace)
- **CLI**: oclif v3
- **Database**: SQLite via drizzle-orm
- **External deps**: Zero for attack modules (all built-in APIs)

## Cost

| Mode | Cost | What It Does |
|------|------|-------------|
| Static scan | $0 | Source code analysis only |
| Endpoint probe | $0 | HTTP requests to target (no third-party API) |
| Prompt injection (HTTP) | $0.01-$0.50 | Sends requests to LLM API (uses target's key or your own) |
| Prompt injection (Relay) | $0 to us | Cost goes to target's Twilio/OpenAI account |

## Team

WIGTN Hackathon Team 2

## License

Private — WIGTN Internal
