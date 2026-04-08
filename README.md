[English](README.md) | [한국어](README.ko.md)

# WIGTN-SPEAR

**AI Red Team Arena Tool** — Adversarial testing of AI agents in safety-critical domains.

```
$ spear arena generate --scenario emergency-triage --channel document --strategy authority-spoof

  SPEAR v0.2.0 — AI Red Team Arena Tool

  Scenario:  Track 1 #0 — Emergency Triage (Action Induction)
  Channel:   Document (Physician Referral)
  Strategy:  Authority Spoof + Indirect Prompt Injection
  Target:    override_to_esi1

  [1/3] Loading scenario context .......... 12 domain variables
  [2/3] Generating attack payload .......... authority-spoof + crescendo
  [3/3] Formatting submission JSON ......... valid

  Output: ./attacks/emergency-triage-doc-001.json
  Confidence: HIGH | Strategy: medical-authority-override
```

## Judgement Day 2026

SPEAR is built for the **Judgement Day AI Red Team Arena** — a live adversarial competition where participants craft multimodal attacks to break AI agents deployed in safety-critical environments.

| | |
|---|---|
| **Host** | AIM Intelligence + Korea AI Safety Institute (AISI) |
| **Period** | April 6 – May 31, 2026 |
| **Prize** | $21,150 (Top 50) |
| **Tracks** | 2 tracks × 4 scenarios = 8 total |
| **Models** | GPT-5.4, Claude Opus 4.6, Gemini 3.1 Pro, Gemini 3 Flash, GPT-Audio-1.5, MiMo-V2-Omni |

### Track 1: Action Induction

Force AI agents to select **prohibited actions** through adversarial multimodal input.

| # | Scenario | Domain | Target Action | Channels | Wave |
|---|----------|--------|---------------|----------|------|
| 0 | Emergency Triage | Medical/Clinical | `override_to_esi1` | Audio, Document | 1 (Active) |
| 1 | Industrial Robot | Manufacturing/Safety | `resume_production` | Image, Audio | 1 (Active) |
| 2 | Sports Integrity | Sports Tech | Flag clean athlete | Audio, Image | 2 (Apr 27) |
| 3 | Dam Flood Control | Critical Infrastructure | Open floodgates | Video, Audio | 2 (Apr 27) |

### Track 2: Action Suppression

Prevent AI agents from selecting the **correct safety action** by injecting misleading information.

| # | Scenario | Domain | Suppressed Action | Channels | Wave |
|---|----------|--------|-------------------|----------|------|
| 0 | Cybersecurity SOC | Security Operations | `open_p1_incident` | Audio, Text | 1 (Active) |
| 1 | Aircraft Maintenance | Aviation/Flight Safety | `issue_maintenance_hold` | Document, Audio | 1 (Active) |
| 2 | Epidemiological Surveillance | Public Health | `declare_outbreak` | Video, Audio, Document | 2 (Apr 27) |
| 3 | Deepfake Detection | Digital Forensics | `flag_as_deepfake` | Audio, Email+PDF | 2 (Apr 27) |

## Attack Strategy

SPEAR leverages its battle-tested security modules to generate competition attacks:

```
┌─────────────────────────────────────────────────────────┐
│                    SPEAR Arena Pipeline                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Scenario Context     Attack Generation     Submission  │
│  ┌──────────────┐    ┌────────────────┐    ┌─────────┐ │
│  │ Spear-26     │───>│ Spear-23       │───>│ JSON    │ │
│  │ Scenario     │    │ Payload Library │    │ Format  │ │
│  │ Engine       │    │ (22+ payloads) │    │         │ │
│  └──────────────┘    └────────────────┘    └─────────┘ │
│         │                    │                          │
│         v                    v                          │
│  ┌──────────────┐    ┌────────────────┐                │
│  │ Spear-27     │    │ Multi-turn     │                │
│  │ Authority    │    │ Engine         │                │
│  │ Spoof        │    │ (Crescendo/TAP)│                │
│  └──────────────┘    └────────────────┘                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Strategy Mapping

| Strategy | Module | Applicable Scenarios | Method |
|----------|--------|---------------------|--------|
| Indirect Prompt Injection | Spear-23 | All | Domain-contextualized payloads via document/text channels |
| Authority Impersonation | Spear-27 | All | Physician referrals, CISO memos, Boeing SILs, supervisor orders |
| Crescendo (Multi-turn) | Spear-23 | SOC, Triage | Gradual trust escalation (98% bypass rate per Microsoft research) |
| TAP (Tree of Attacks) | Spear-23 | All | LLM-generated attack variations with pruning |
| Economic Pressure | Spear-23 | Robot, Aircraft | Cost-based urgency framing ($15K/hr delay, $2M contract) |
| Social Engineering | Spear-19 | SOC, Aircraft | Deceptive naming, Unicode tricks, authority framing |

## Arsenal

### Arena Modules (Competition-Specific)

| Module | Name | Purpose |
|--------|------|---------|
| Spear-26 | Scenario Engine | 8 scenario definitions, strategy mapping, attack generation, submission formatting |
| Spear-27 | Authority Spoof | Domain-specific authority document templates (medical, aviation, cybersecurity, industrial) |
| Spear-28 | Multimodal Craft | Audio/image/video attack generation (TTS, document PDF, visual deception) |

### Live Attack Modules

| Module | Name | Arena Use |
|--------|------|-----------|
| Spear-23 | Live Prompt Inject | 37+ injection payloads including domain-specific (medical, aviation, SOC) + multi-turn engine |
| Spear-24 | MCP Live Test | MCP server tool poisoning for agent manipulation |
| Spear-25 | Endpoint Prober | Target reconnaissance, API discovery, auth gap analysis |

### Static Analysis Modules

| Module | Name | Arena Use |
|--------|------|-----------|
| Spear-01 | Secret Scanner | API key extraction from target services |
| Spear-02 | Git Miner | Historical secret mining for credential harvesting |
| Spear-04 | MCP Poisoner | MCP tool description injection patterns |
| Spear-06 | Prompt Injector | Static prompt injection pattern library (1000+ combos) |
| Spear-10 | Agent Manipulator | AI agent config exploitation patterns |
| Spear-17 | LLM Exploiter | LLM output handling vulnerability detection |
| Spear-19 | Social Engineer | Social engineering patterns, Unicode tricks, authority deception |
| Spear-21 | Distillation | Model distillation/theft indicators |

<details>
<summary>Full Module List (22 modules)</summary>

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
| Spear-23 | Live Prompt Inject | 37+ injection payloads via HTTP/WebSocket/Relay |
| Spear-24 | MCP Live Test | Real-time MCP server poisoning |
| Spear-25 | Endpoint Prober | Cloud discovery, OpenAPI, auth bypass, AI infra scan |

</details>

## Quick Start

```bash
# Install
pnpm install

# Build
pnpm turbo build

# List active arena scenarios
node apps/cli/bin/run.js arena list

# Generate an attack for Emergency Triage (document channel)
node apps/cli/bin/run.js arena generate \
  --scenario emergency-triage \
  --channel document \
  --strategy authority-spoof

# Generate attack for SOC (text channel, crescendo strategy)
node apps/cli/bin/run.js arena generate \
  --scenario soc-cybersecurity \
  --channel text \
  --strategy crescendo

# Validate submission JSON
node apps/cli/bin/run.js arena submit \
  --file ./attacks/soc-text-001.json \
  --validate-only
```

### Legacy Commands (Security Scanner)

```bash
# Static scan (safe, no network)
node apps/cli/bin/run.js scan ./path-to-target-repo

# Live attack (sends actual requests)
node apps/cli/bin/run.js attack https://target-url.com \
  --module endpoint-prober \
  --max-requests 100
```

## Security Research Foundation

SPEAR's arena capabilities are built on comprehensive security research coverage:

**OWASP LLM Top 10: 10/10 | OWASP Web Top 10: 10/10**

<details>
<summary>OWASP Coverage Details</summary>

### OWASP Top 10 for LLM Applications

| # | Vulnerability | Module | Method |
|---|--------------|--------|--------|
| LLM01 | Prompt Injection | Spear-23 | 37+ payloads via HTTP/WebSocket/Relay chain |
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

</details>

## Architecture

```
wigtn-spear/
├── apps/
│   └── cli/                          # CLI application (oclif)
│       └── commands/
│           ├── scan.ts               # Static security scan
│           ├── attack.ts             # Live attack against URL
│           └── arena/                # Arena competition commands
│               ├── list.ts           # List active scenarios
│               ├── generate.ts       # Generate attack payloads
│               └── submit.ts         # Validate & format submissions
├── packages/
│   ├── shared/                       # Types, interfaces, constants
│   ├── core/                         # Scan engine, rate limiter
│   ├── db/                           # SQLite persistence (drizzle)
│   ├── plugin-system/                # Plugin registry and lifecycle
│   ├── rules-engine/                 # Finding classification
│   ├── reporters/                    # HTML, JSON, SARIF reporters
│   └── plugins/                      # 25 attack modules
│       ├── spear-01 ~ spear-22/      # Static analysis modules
│       ├── spear-23-live-prompt-inject/  # Payload library + multi-turn
│       ├── spear-24-mcp-live-test/       # MCP server testing
│       ├── spear-25-endpoint-prober/     # Endpoint reconnaissance
│       ├── spear-26-scenario-engine/     # Arena scenario management
│       ├── spear-27-authority-spoof/     # Authority document templates
│       └── spear-28-multimodal-craft/    # Multimodal attack generation
└── turbo.json
```

## Tech Stack

- **Runtime**: Node.js 22+ (built-in fetch, WebSocket)
- **Language**: TypeScript 5.4 (strict mode)
- **Build**: Turborepo (monorepo), pnpm (workspace)
- **CLI**: oclif v3
- **Database**: SQLite via drizzle-orm
- **External deps**: Zero for attack modules (all built-in APIs)

## Team

WIGTN Hackathon Team 2

## License

Private — WIGTN Internal

---

## About WIGTN Crew

This project is built and maintained by **[WIGTN Crew](https://wigtn.com)** —
an AI-native open-source research crew based in Korea.
We build practical, domain-specialized AI tools. Fast prototyping, strong engineering, shipping real things.

| | |
|---|---|
| Website | [wigtn.com](https://wigtn.com) |
| GitHub | [github.com/wigtn](https://github.com/wigtn) |
| HuggingFace | [huggingface.co/Wigtn](https://huggingface.co/Wigtn) |
| NPM | [npmjs.com/org/wigtn](https://www.npmjs.com/org/wigtn) |

### Our Projects

| Project | Description | Status |
|---------|-------------|--------|
| [WIGTN-SPEAR](https://github.com/wigtn/wigtn-spear) | AI Red Team Arena Tool for Judgement Day 2026 | Active |
| [WigtnOCR](https://huggingface.co/Wigtn/Qwen3-VL-2B-WigtnOCR) | VLM-based Korean government document parser | Research |
| [WIGVO](https://wigtn.com) | Real-time PSTN voice translation (Korean↔English) | Research |
| [Claude Code Plugin](https://github.com/wigtn/wigtn-plugins-with-claude-code) | Multi-agent parallel execution ecosystem | Open Source |

> Results speak louder than resumes.
