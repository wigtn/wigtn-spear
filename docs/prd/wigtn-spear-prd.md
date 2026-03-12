# WIGTN-SPEAR PRD

> **Version**: 1.0
> **Created**: 2026-03-13
> **Status**: Draft
> **Scale Grade**: Startup
> **Team**: WIGTN Hackathon Team 2
> **Research Base**: 30 Academic Papers, 20+ CVEs

---

## 1. Overview

### 1.1 Problem Statement

바이브 코딩 시대에 AI 코딩 도구(Cursor, Copilot, Claude Code)가 일상이 되면서 새로운 보안 위협이 급증하고 있다:

- AI 생성 코드의 **45%에 보안 취약점** 존재 (Veracode 2025)
- AI가 추천하는 패키지의 **~20%가 존재하지 않는 가짜** (USENIX Security 2025)
- 코딩 AI 방어 우회 성공률 **85%+** (arXiv SoK 2026)
- **모든 AI IDE(100%)**에서 취약점 발견 (IDEsaster 2025, 24 CVEs)
- MCP 에이전트 스킬의 **36%에서 프롬프트 인젝션** (Snyk 2026)

그러나 기존 보안 도구(TruffleHog, Semgrep, GitLeaks, Snyk)는 **수동적 방어자 시점**에서만 동작하며, AI 에이전트/MCP 공격면을 전혀 커버하지 못한다.

### 1.2 Goals

- **G1**: 실제 공격자 관점에서 개발 환경의 시크릿 탈취를 시뮬레이션하는 CLI 도구 제공
- **G2**: AI 에이전트/MCP 프로토콜 대상 공격 테스트를 세계 최초로 제품화
- **G3**: WIGTN-SHIELD(방어 도구)와 연동하여 Red Team/Blue Team 사이클 완성
- **G4**: SARIF 2.1.0 출력으로 GitHub/GitLab CI/CD에 즉시 통합 가능
- **G5**: 30편 논문 + 20+ CVE 기반의 학술적 근거를 갖춘 공격 모듈 제공

### 1.3 Non-Goals (Out of Scope)

- 실제 악성 코드 배포 또는 실제 시스템 침해 (시뮬레이션/테스트 전용)
- 네트워크 패킷 캡처/DPI (와이어샤크 영역)
- 바이너리 리버스 엔지니어링 (IDA Pro/Ghidra 영역)
- WAF/IDS 우회 기법 (네트워크 보안 도구 영역)
- 모바일 앱 보안 테스트 (MobSF 영역)

### 1.4 Scope

| 포함 | 제외 |
|------|------|
| 시크릿 탐지 + 라이브 검증 | 실제 시스템 침해 |
| Git 히스토리 전체 분석 | 바이너리 분석 |
| AI 에이전트/MCP 공격 테스트 | 네트워크 DPI |
| CI/CD 파이프라인 감사 | 물리적 보안 |
| 클라우드 크레덴셜 체인 분석 | 모바일 앱 보안 |
| 프롬프트 인젝션 퍼징 | 소셜 엔지니어링 실행 |
| SARIF/JSON/HTML 리포트 | 실시간 모니터링 (SHIELD 영역) |
| 웹 대시보드 (스캔 결과) | 실시간 트래픽 분석 |

---

## 2. User Stories

### 2.1 Primary Users

**User A: 보안 엔지니어 / Red Team**
As a security engineer, I want to simulate real-world attacks against our development environment so that I can identify vulnerabilities before attackers do.

**User B: DevSecOps 엔지니어**
As a DevSecOps engineer, I want to integrate attack simulation into our CI/CD pipeline so that every PR is tested for secret leakage and supply chain risks.

**User C: 바이브 코딩 개발자**
As a developer using AI coding tools, I want to verify that my AI-generated code and MCP configurations are not introducing security vulnerabilities so that I can code with confidence.

**User D: SHIELD 운영자**
As a WIGTN-SHIELD operator, I want to run SPEAR attacks against my SHIELD deployment so that I can validate detection coverage and identify gaps.

### 2.2 Acceptance Criteria (Gherkin)

```gherkin
Scenario: Secret Detection with Live Verification
  Given a project directory containing source code
  When I run `spear scan --module secret-scanner`
  Then all files are scanned for 800+ secret patterns
  And high-entropy strings are flagged
  And detected secrets are verified against their respective APIs
  And a SARIF report is generated with findings

Scenario: Git History Mining
  Given a git repository with commit history
  When I run `spear scan --module git-miner`
  Then all commits including dangling and unreachable commits are scanned
  And "oops commits" (commit → immediate delete) are flagged
  And previously deleted secrets are recovered and reported

Scenario: MCP Poisoning Test
  Given an AI coding tool with MCP server configuration
  When I run `spear test --module mcp-poisoner`
  Then a mock MCP server is created with injected tool descriptions
  And the AI agent's response to poisoned descriptions is monitored
  And Rug Pull (post-approval tool redefinition) is simulated
  And results are mapped to CVE-2025-54135 patterns

Scenario: Prompt Injection Fuzzing
  Given an AI agent accepting natural language input
  When I run `spear fuzz --module prompt-injector --payloads all`
  Then 314+ payload variants are tested (HouYi + AIShellJack)
  And attack success rate is calculated per MITRE ATT&CK technique
  And Promptware Kill Chain stage progression is tracked

Scenario: CI/CD Pipeline Audit
  Given a GitHub repository with Actions workflows
  When I run `spear audit --module cicd-pipeline`
  Then all workflow files are analyzed for expression injection
  And third-party actions are checked for SHA pinning
  And pull_request_target misuse is detected
  And OIDC federation misconfigurations are identified

Scenario: Safe Mode vs Aggressive Mode
  Given default CLI configuration
  When I run `spear scan` without --mode flag
  Then only passive scanning is performed (no API calls, no network probes)
  And when I run `spear scan --mode aggressive`
  Then a confirmation prompt is displayed before proceeding
  And active API verification and network scanning are enabled

Scenario: SHIELD Integration
  Given WIGTN-SHIELD is running and monitoring
  When I run `spear attack --target shield --scenario brute-force`
  Then the attack is simulated against the monitored environment
  And SHIELD's detection result is captured
  And a Gap Analysis report shows detected vs. missed attacks
  And a Security Score (A-F) is calculated

Scenario: Scan Interruption Recovery
  Given a scan is in progress on a large repository (> 10,000 files)
  When the scan is interrupted (Ctrl+C, process kill, system crash)
  Then the partial scan results collected so far are saved to DB with status "interrupted"
  And a resume token is generated
  And running `spear scan --resume <token>` continues from the last checkpoint
  And no data corruption occurs in the SQLite DB (WAL mode + graceful shutdown hook)

Scenario: Network Failure During Live Verification
  Given Aggressive Mode is active and live API verification is running
  When the network becomes unreachable during verification
  Then the current verification is marked as "network_error"
  And remaining verifications are queued with exponential backoff (1s, 2s, 4s, max 30s)
  And after 3 consecutive failures, verification is paused with a user prompt
  And already-collected scan results remain intact (verification is additive, not blocking)

Scenario: Corrupted Git Repository
  Given a git repository with corrupted objects or missing refs
  When I run `spear scan --module git-miner`
  Then `git fsck` is run first to detect corruption
  And corrupted objects are logged with specific error messages
  And the scan continues on accessible objects, skipping corrupted ones
  And the report includes a "data_quality" section noting skipped objects and coverage percentage

Scenario: Malformed Rule File
  Given the YAML rules directory contains a syntactically invalid rule file
  When the rules engine loads rules at startup
  Then the malformed rule is skipped with a warning log (not a fatal error)
  And all other valid rules are loaded normally
  And the warning includes file path, line number, and parse error description
  And `spear scan` proceeds with the valid rule set

Scenario: Worker Thread Crash
  Given a scan is running with multiple worker threads
  When one worker thread crashes (unhandled exception, OOM)
  Then the crashed worker's in-progress files are re-queued to other workers
  And the crash is logged with stack trace and file context
  And the scan continues if at least 1 worker remains healthy
  And if all workers crash, the scan fails gracefully with partial results saved
```

---

## 3. Functional Requirements

### 3.1 Core Engine

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-001 | Aho-Corasick 기반 키워드 프리필터링 엔진 구현 | P0 | - |
| FR-002 | Regex 패턴 매칭 엔진 (800+ 패턴, GitLeaks TOML 호환) | P0 | FR-001 |
| FR-003 | Shannon 엔트로피 분석 (임계값: 비시크릿 ~4.0, 시크릿 5.0-8.0) | P0 | FR-002 |
| FR-004 | 라이브 API 검증 엔진 (찾은 시크릿의 활성 여부 확인) | P0 | FR-003 |
| FR-005 | Worker Thread 기반 병렬 스캔 (CPU 코어 수 자동 감지) | P0 | FR-001 |
| FR-006 | AsyncGenerator 기반 스트리밍 결과 파이프라인 | P0 | FR-005 |
| FR-007 | 검증 Rate Limiter (서비스별 RPM/동시성 제한) | P0 | FR-004 |

### 3.2 Attack Modules - P0 (MVP)

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-010 | **Spear-01: Secret Scanner** - 프로젝트 전체 시크릿 패턴 스캔 + 라이브 검증 | P0 | FR-001~007 |
| FR-011 | **Spear-02: Git History Miner** - git reflog, fsck, dangling commit 분석 | P0 | FR-001~003 |
| FR-012 | **Spear-04: MCP Poisoning Tester** - Mock MCP 서버, tool description 인젝션, Rug Pull | P0 | - |
| FR-013 | **Spear-06: Prompt Injection Fuzzer** - 314+ 페이로드, 7단계 킬체인, MITRE 매핑 | P0 | - |
| FR-014 | **Spear-10: AI Agent Manipulation** - 설정 파일 인젝션 (.cursorrules, .claude/settings.json) | P0 | - |
| FR-015 | **Spear-11: CI/CD Pipeline Exploit** - GitHub Actions YAML 분석, SHA 핀닝 감사 | P0 | - |
| FR-016 | **Spear-13: Cloud Credential Chain** - AWS/GCP/Azure 크레덴셜 파일 + IMDS + IAM 체인 | P0 | FR-001~003 |
| FR-017 | **Spear-17: LLM Output Exploitation** - Slopsquatting 탐지, AI 백도어 패턴 | P0 | FR-001~003 |

### 3.3 Attack Modules - P1

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-020 | **Spear-03: Env Exfiltration** - /proc/pid/environ, 환경변수 열거 | P1 | FR-001 |
| FR-021 | **Spear-05: Dependency Confusion** - Private/public registry 혼란 + AI 할루시네이션 패키지 | P1 | - |
| FR-022 | **Spear-08: Supply Chain Analyzer** - install script 동적 분석, 행동 시퀀스 | P1 | - |
| FR-023 | **Spear-12: Container Security** - Docker 이미지 레이어 시크릿, Dockerfile 안티패턴 | P1 | FR-001 |
| FR-024 | **Spear-14: Network Recon & SSRF** - 로컬 서비스 디스커버리, DNS 리바인딩 | P1 | - |
| FR-025 | **Spear-15: IDE Extension Auditor** - VS Code/Cursor 확장 권한 + 악성 패턴 | P1 | FR-001 |
| FR-026 | **Spear-16: Webhook & API Scanner** - 웹훅 URL 발견, KeyHacks 170+ 서비스 | P1 | FR-004 |
| FR-027 | **Spear-19: Social Engineering Code** - 트로이 PR, 락파일 조작, 기여자 신뢰 점수 | P1 | - |

### 3.4 Attack Modules - P2

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-030 | **Spear-07: Clipboard/Memory** - 클립보드 시크릿, 프로세스 메모리 스캔 | P2 | - |
| FR-031 | **Spear-09: Browser Extension** - CRX 파싱, 권한 분석, 악성 DB | P2 | - |
| FR-032 | **Spear-18: Certificate & TLS** - CT 로그 정찰, TLS 설정 감사 | P2 | - |
| FR-033 | **Spear-20: Hardware Token** - FIDO2 다운그레이드, WebAuthn 설정 감사 | P2 | - |

### 3.5 CLI

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-040 | `spear init` - 프로젝트 초기 설정 + .spearignore 생성 | P0 | - |
| FR-041 | `spear scan [--module <name>]` - 모듈별/전체 스캔 실행 | P0 | FR-010~017 |
| FR-042 | `spear test [--module <name>]` - AI/MCP 공격 테스트 실행 | P0 | FR-012~014 |
| FR-043 | `spear fuzz [--module <name>]` - 프롬프트 인젝션 퍼징 | P0 | FR-013 |
| FR-044 | `spear audit [--module <name>]` - CI/CD/클라우드 감사 | P0 | FR-015~016 |
| FR-045 | `spear report [--format sarif\|json\|html\|csv]` - 리포트 생성 | P0 | FR-041~044 |
| FR-046 | `spear shield-test [--scenario <name>]` - SHIELD 연동 테스트 | P1 | FR-041~044 |
| FR-047 | `spear plugin install <package>` - 커뮤니티 플러그인 설치 | P1 | - |
| FR-048 | `spear config` - Safe/Aggressive 모드 설정 | P0 | - |
| FR-049 | `spear update-rules` - 탐지 룰 업데이트 | P1 | - |

### 3.6 Reporting

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-050 | SARIF 2.1.0 출력 (GitHub Code Scanning 호환) | P0 | - |
| FR-051 | JSON 출력 (기계 판독 가능) | P0 | - |
| FR-052 | HTML 리포트 (사람 판독 가능, 대시보드 미설치 시) | P1 | - |
| FR-053 | CSV 출력 (스프레드시트 분석용) | P2 | - |
| FR-054 | CVSS 기반 위험 점수 계산 | P0 | - |
| FR-055 | MITRE ATT&CK 매핑 (프롬프트 인젝션 모듈) | P0 | FR-013 |
| FR-056 | 시크릿 자동 마스킹 (출력 시 앞/뒤 4자만 표시) | P0 | - |
| FR-057 | Attack Chain 시각화 (어떤 경로로 탈취 가능한지) | P1 | - |
| FR-058 | Remediation Playbook 자동 생성 (취약점별 수정 가이드) | P1 | - |

### 3.7 Web Dashboard

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-060 | 스캔 결과 대시보드 (모듈별 취약점 수, 위험도 분포) | P1 | FR-050~051 |
| FR-061 | 스캔 히스토리 (시간별 추이, 개선 트래킹) | P1 | FR-060 |
| FR-062 | Attack Chain 시각화 (인터랙티브 그래프) | P1 | FR-057 |
| FR-063 | SHIELD 연동 대시보드 (탐지 성공/실패, Gap Analysis) | P2 | FR-046 |
| FR-064 | Security Score 대시보드 (A-F 등급, 카테고리별 점수) | P1 | FR-054 |

### 3.8 Safety & Guardrails

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-070 | Safe Mode 기본 활성화 (패시브 스캔만, API 호출/네트워크 없음) | P0 | - |
| FR-071 | Aggressive Mode 전환 시 3단계 안전 게이트 (아래 상세) | P0 | - |
| FR-072 | .spearignore 파일 지원 (.gitignore 형식) | P0 | - |
| FR-073 | 시크릿 절대 전체 로깅 금지 (디스크에 미마스킹 시크릿 기록 안 함) | P0 | - |
| FR-074 | 스캔 활동 감사 로그 (누가 언제 무엇을 스캔했는지) | P0 | - |
| FR-075 | 명시적 타겟 필수 (와일드카드 *.*, 0.0.0.0/0 금지) | P0 | - |
| FR-076 | 첫 실행 시 이용약관 동의 프롬프트 | P0 | - |
| FR-077 | 검증 Rate Limiting (API 키 검증 시 서비스별 속도 제한) | P0 | FR-007 |

#### FR-071 상세: Aggressive Mode 3단계 안전 게이트

Aggressive Mode 전환 시 다음 3단계를 순차 통과해야 활성화됩니다:

**Gate 1: Pre-flight Checklist**
```
┌─────────────────────────────────────────────────┐
│ ⚠️  Aggressive Mode Pre-flight Check            │
├─────────────────────────────────────────────────┤
│ [✓] 타겟 경로가 로컬 파일시스템인지 확인         │
│ [✓] .spearignore 파일 존재 확인                  │
│ [✓] 네트워크 접근 가능한 모듈 목록 표시           │
│ [✓] 예상 API 호출 횟수 계산 및 표시              │
│ [✓] Rate Limit 설정 확인                         │
│ [ ] 사용자 명시적 확인 (Y/N)                     │
└─────────────────────────────────────────────────┘
```

**Gate 2: Dry-run Mode**
```bash
spear scan --mode aggressive --dry-run  # 실제 API 호출 없이 어떤 시크릿이 검증 대상인지 미리 확인
```
- `--dry-run` 플래그 제공: 실제 네트워크 요청 없이 검증 대상 목록만 출력
- 사용자가 검증 대상을 확인한 후 실제 실행 여부 결정

**Gate 3: Verify-limit 플래그**
```bash
spear scan --mode aggressive --verify-limit 50  # 최대 50건만 라이브 검증
```
- `--verify-limit <N>`: 라이브 검증 최대 건수 제한 (기본값: 100)
- `--verify-services aws,github`: 특정 서비스만 검증 허용
- 한도 초과 시 나머지는 "unverified" 상태로 리포트에 포함

### 3.9 Legal & Compliance

| ID | Requirement | Priority | Dependencies |
|----|------------|----------|--------------|
| FR-080 | 이용약관(ToS) 필수 동의 - 자사 시스템에서만 사용 가능, 무단 사용 금지 명시 | P0 | FR-076 |
| FR-081 | 스캔 대상 소유권/권한 확인 프롬프트 (첫 스캔 시) | P0 | - |
| FR-082 | CFAA/한국 정보통신망법 준수 고지 + Disclaimer 내장 | P0 | - |
| FR-083 | 책임 한계 명시 (도구 오용 시 사용자 책임, MIT+Commons Clause 또는 BSL 라이선스) | P0 | - |
| FR-084 | Aggressive Mode에서 외부 API 호출 시 대상 서비스 ToS 준수 여부 경고 | P0 | FR-071 |

#### FR-080 상세: 이용약관(ToS) 구조

```
첫 실행 시:
┌─────────────────────────────────────────────────────────────┐
│ WIGTN-SPEAR - Terms of Service                               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│ 1. 이 도구는 보안 테스트 및 취약점 평가 목적으로만 사용해야    │
│    합니다.                                                    │
│ 2. 스캔 대상 시스템에 대한 정당한 권한이 있어야 합니다.       │
│ 3. 무단 시스템 침투, 데이터 탈취에 사용하는 것은 법적으로      │
│    금지됩니다.                                                │
│ 4. 사용자는 관할 지역의 컴퓨터 범죄 관련 법률을 준수해야      │
│    합니다 (CFAA, 정보통신망법 등).                             │
│ 5. 도구 오용으로 인한 모든 법적 책임은 사용자에게 있습니다.    │
│                                                               │
│ 전체 약관: https://github.com/wigtn/spear/blob/main/LICENSE   │
│                                                               │
│ 동의하시겠습니까? [Y/N]:                                       │
└─────────────────────────────────────────────────────────────┘

동의 정보 저장: ~/.config/wigtn-spear/tos-accepted.json
{
  "version": "1.0",
  "acceptedAt": "2026-03-13T10:00:00Z",
  "hash": "sha256(tos_content)"
}
```

#### FR-081 상세: 스캔 대상 권한 확인

```
첫 스캔 시:
┌─────────────────────────────────────────────────────────────┐
│ ⚠️  Authorization Verification                               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│ 스캔 대상: /path/to/project                                   │
│                                                               │
│ 다음을 확인해 주세요:                                         │
│ [  ] 이 시스템/코드베이스에 대한 보안 테스트 권한이 있습니다   │
│ [  ] 조직의 보안 테스트 정책에 따라 수행합니다                 │
│                                                               │
│ 확인 [Y/N]:                                                   │
└─────────────────────────────────────────────────────────────┘

확인 결과 감사 로그에 기록:
{
  "action": "authorization_confirmed",
  "target": "/path/to/project",
  "confirmedAt": "2026-03-13T10:00:00Z"
}
```

---

## 4. Non-Functional Requirements

### 4.0 Scale Grade

**선택: Startup (소규모 서비스)**

| 항목 | 값 |
|------|-----|
| 예상 팀 규모 | 2-5명 |
| 예상 사용자 | 수백~수천 명 (보안 엔지니어, DevSecOps) |
| 동시 스캔 | < 100 |
| 데이터량 | 1-10GB (스캔 결과) |
| 인프라 비용 | ~$100/월 |

### 4.1 Performance SLA

| 지표 | 목표값 | 측정 방법 |
|------|--------|----------|
| 소규모 프로젝트 스캔 (< 1000 파일) | < 30초 | CLI 실행~완료 |
| 중규모 프로젝트 스캔 (< 10,000 파일) | < 3분 | CLI 실행~완료 |
| Git 히스토리 스캔 (< 10,000 커밋) | < 5분 | CLI 실행~완료 |
| 시크릿 패턴 매칭 처리량 | > 10,000 파일/분 | Worker Thread 병렬 |
| API 검증 응답 시간 | < 5초/검증 | 네트워크 레이턴시 포함 |
| 대시보드 페이지 로드 | < 2초 (p95) | FCP 기준 |
| CLI 시작 시간 | < 200ms | oclif cold start |

### 4.2 Availability SLA

| 항목 | 값 |
|------|-----|
| CLI 도구 | 100% (로컬 실행, 서버 불필요) |
| 대시보드 | 99% (월 7.3시간 다운타임 허용) |
| 룰 업데이트 서버 | 99% |

### 4.3 Data Requirements

| 항목 | 값 |
|------|-----|
| 스캔 결과 DB | SQLite (로컬), 최대 1GB/프로젝트 |
| 탐지 룰 | YAML 파일, < 10MB |
| 월간 증가율 | 스캔당 ~1-10MB |
| 데이터 보존 | 로컬 저장, 사용자 관리 |
| 민감 데이터 | 마스킹된 시크릿만 저장 (전체 시크릿 절대 디스크 기록 안 함) |

### 4.4 Recovery

| 항목 | 값 |
|------|-----|
| RTO | 해당 없음 (CLI 도구, 재실행으로 복구) |
| RPO | 스캔 결과 DB 백업 시 0, 미백업 시 마지막 스캔까지 손실 |

### 4.5 Security

| 항목 | 요구사항 |
|------|----------|
| Authentication | 대시보드: 아래 상세 모델 참고, CLI: 없음 (로컬 도구) |
| Data Encryption | At rest: SQLite DB는 평문 (마스킹된 데이터만 저장), In transit: HTTPS (대시보드, 룰 업데이트) |
| Secret Handling | SecureSecret 클래스 기반 일관 처리 (Section 5.5 참고) |
| Audit Trail | 모든 스캔 활동 로깅 (시간, 모듈, 타겟, 결과 요약) |
| Sandboxing | Supply Chain Analyzer: isolated-vm으로 install script 분석 |
| Plugin Security | Trust Level 기반 권한 모델 (Section 5.4.1 참고) |

#### 4.5.1 Dashboard Authentication Model

대시보드는 두 가지 모드로 동작하며, 각 모드에 따라 인증 수준이 다릅니다:

**Mode 1: Localhost-only (기본값)**
```
spear dashboard                     # http://localhost:3000
```
- 바인딩: `127.0.0.1:3000` (외부 접근 불가)
- 인증: 없음 (로컬 머신에서만 접근 가능하므로 불필요)
- 사용 시나리오: 개인 개발자, 로컬 스캔 결과 확인

**Mode 2: Network Mode (명시적 활성화 필요)**
```
spear dashboard --host 0.0.0.0 --port 3000
```
- 바인딩: `0.0.0.0:3000` (네트워크 노출)
- 인증: **필수** (아래 플로우 자동 적용)
- 사용 시나리오: 팀 공유, CI/CD 서버에서 대시보드 호스팅

**Network Mode 인증 플로우:**

```
첫 Network Mode 실행 시:
┌─────────────────────────────────────────────────────────────┐
│ ⚠️  Dashboard is exposed to the network.                     │
│                                                               │
│ 보안을 위해 관리자 비밀번호를 설정해야 합니다.               │
│                                                               │
│ Password: ********                                            │
│ Confirm:  ********                                            │
│                                                               │
│ ✅ Password set. Dashboard running at http://0.0.0.0:3000    │
│ 📋 Access token: spear_tk_abc123... (API 접근용)              │
└─────────────────────────────────────────────────────────────┘
```

| 항목 | 스펙 |
|------|------|
| 비밀번호 저장 | bcrypt (cost factor 12) |
| 세션 | JWT (HS256, 24시간 유효, httpOnly cookie) |
| API 인증 | Bearer token (`spear_tk_` prefix, 256-bit random) |
| 비밀번호 정책 | 최소 8자 (Network Mode 필수, Localhost는 선택) |
| 실패 제한 | 5회 실패 → 15분 잠금 (brute-force 방지) |
| CORS | Localhost Mode: 비활성화, Network Mode: 명시적 origin만 허용 |
| 저장 위치 | `~/.config/wigtn-spear/dashboard-auth.json` |

**Network Mode 보호 장치:**
- `--host 0.0.0.0` 사용 시 비밀번호 미설정이면 기동 거부
- 환경변수 `SPEAR_DASHBOARD_PASSWORD`로 비대화식 설정 가능 (CI/CD용)
- `--no-auth` 플래그로 인증 우회 가능하나, 명시적 경고 출력 + 감사 로그 기록

### 4.6 Compatibility

| 항목 | 요구사항 |
|------|----------|
| Node.js | >= 20.x LTS |
| OS | macOS, Linux (Windows WSL2 지원) |
| Git | >= 2.30 |
| Package Manager | npm, pnpm, yarn |
| CI/CD | GitHub Actions, GitLab CI, Jenkins |
| SARIF | 2.1.0 (GitHub Code Scanning 호환) |

---

## 5. Technical Design

### 5.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        WIGTN-SPEAR                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐   ┌──────────────────────────────────────┐   │
│  │   CLI App     │   │          Web Dashboard               │   │
│  │   (oclif)     │   │    (Vite + React 19 + shadcn/ui)    │   │
│  └──────┬───────┘   └──────────────┬───────────────────────┘   │
│         │                           │                            │
│         └───────────┬───────────────┘                            │
│                     │                                            │
│         ┌───────────▼──────────────┐                            │
│         │      Core Engine          │                            │
│         │  ┌─────────────────────┐ │                            │
│         │  │ Scan Pipeline       │ │                            │
│         │  │                     │ │                            │
│         │  │ [Aho-Corasick]      │ │                            │
│         │  │      ↓              │ │                            │
│         │  │ [Regex Matching]    │ │                            │
│         │  │      ↓              │ │                            │
│         │  │ [Entropy Analysis]  │ │                            │
│         │  │      ↓              │ │                            │
│         │  │ [Live Verification] │ │                            │
│         │  │      ↓              │ │                            │
│         │  │ [SARIF Reporter]    │ │                            │
│         │  └─────────────────────┘ │                            │
│         │                          │                            │
│         │  ┌──────────────────┐   │                            │
│         │  │ Worker Pool      │   │                            │
│         │  │ (worker_threads) │   │                            │
│         │  └──────────────────┘   │                            │
│         └───────────┬──────────────┘                            │
│                     │                                            │
│         ┌───────────▼──────────────┐                            │
│         │     Plugin System         │                            │
│         │                          │                            │
│         │  ┌────────────────────┐  │                            │
│         │  │ Secret Detection   │  │                            │
│         │  │  #01 Scanner       │  │                            │
│         │  │  #02 Git Miner     │  │                            │
│         │  └────────────────────┘  │                            │
│         │  ┌────────────────────┐  │                            │
│         │  │ AI/Agent Attacks   │  │                            │
│         │  │  #04 MCP Poisoner  │  │                            │
│         │  │  #06 PI Fuzzer     │  │                            │
│         │  │  #10 Agent Manip   │  │                            │
│         │  │  #17 LLM Exploit   │  │                            │
│         │  └────────────────────┘  │                            │
│         │  ┌────────────────────┐  │                            │
│         │  │ Infrastructure     │  │                            │
│         │  │  #11 CI/CD         │  │                            │
│         │  │  #13 Cloud Cred    │  │                            │
│         │  │  ... (20 modules)  │  │                            │
│         │  └────────────────────┘  │                            │
│         └───────────┬──────────────┘                            │
│                     │                                            │
│         ┌───────────▼──────────────┐                            │
│         │      Data Layer          │                            │
│         │  SQLite (better-sqlite3) │                            │
│         │  + Drizzle ORM           │                            │
│         └──────────────────────────┘                            │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Rules Engine (YAML)                                      │   │
│  │  ├── secrets/    (800+ patterns, GitLeaks compatible)     │   │
│  │  ├── vulns/      (AI/MCP vulnerability patterns)          │   │
│  │  └── misconfig/  (CI/CD, cloud, IDE misconfigurations)    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 API Specification

#### CLI Commands (Primary Interface)

```bash
# 초기 설정
spear init                                    # 프로젝트 설정 + .spearignore
spear config set mode safe|aggressive         # 모드 설정

# 스캔 (시크릿 탐지)
spear scan                                    # 전체 스캔 (Safe Mode)
spear scan --module secret-scanner            # 특정 모듈
spear scan --module git-miner                 # Git 히스토리
spear scan --mode aggressive                  # 라이브 검증 포함

# 테스트 (AI/MCP 공격)
spear test --module mcp-poisoner              # MCP 포이즈닝
spear test --module agent-manipulator         # AI 에이전트 조작

# 퍼징 (프롬프트 인젝션)
spear fuzz --module prompt-injector           # 프롬프트 인젝션
spear fuzz --payloads houyi,aishellJack       # 특정 페이로드 세트

# 감사 (인프라)
spear audit --module cicd-pipeline            # CI/CD 파이프라인
spear audit --module cloud-creds              # 클라우드 크레덴셜

# 리포트
spear report --format sarif                   # SARIF 출력
spear report --format html --output report/   # HTML 리포트

# SHIELD 연동
spear shield-test --scenario all              # 전체 공격 시나리오
spear shield-test --scenario brute-force      # 특정 시나리오

# 플러그인
spear plugin install @wigtn/spear-plugin-xxx  # 플러그인 설치
spear plugin list                             # 설치된 플러그인

# 룰 업데이트
spear update-rules                            # 최신 룰 다운로드
```

#### REST API (Dashboard Backend)

##### `GET /api/v1/scans`

**Description**: 스캔 히스토리 목록 조회

**Authentication**: Optional (로컬 대시보드)

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| page | number | No | 페이지 번호 (default: 1) |
| limit | number | No | 페이지 크기 (default: 20, max: 100) |
| module | string | No | 모듈 필터 |
| severity | string | No | 심각도 필터 (critical\|high\|medium\|low) |

**Response 200 OK**:
```json
{
  "success": true,
  "data": {
    "scans": [
      {
        "id": "scan_abc123",
        "module": "secret-scanner",
        "target": "/path/to/project",
        "mode": "safe",
        "status": "completed",
        "findings": {
          "critical": 2,
          "high": 5,
          "medium": 12,
          "low": 3,
          "info": 8
        },
        "duration": 45200,
        "startedAt": "2026-03-13T10:00:00Z",
        "completedAt": "2026-03-13T10:00:45Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 150,
      "totalPages": 8
    }
  }
}
```

---

##### `GET /api/v1/scans/:id`

**Description**: 스캔 상세 결과 조회

**Response 200 OK**:
```json
{
  "success": true,
  "data": {
    "id": "scan_abc123",
    "module": "secret-scanner",
    "findings": [
      {
        "id": "finding_001",
        "ruleId": "aws-access-key",
        "severity": "critical",
        "file": "src/config.ts",
        "line": 42,
        "column": 15,
        "secret": "AKIA****XXXX",
        "verified": true,
        "verifiedAt": "2026-03-13T10:00:30Z",
        "cvss": 9.1,
        "mitre": ["T1552.001"],
        "remediation": "Remove the hardcoded AWS access key and use environment variables or AWS IAM roles instead."
      }
    ],
    "attackChain": [
      {
        "step": 1,
        "technique": "Secret Discovery",
        "finding": "finding_001",
        "description": "AWS access key found in source code"
      },
      {
        "step": 2,
        "technique": "Cloud Credential Access",
        "description": "Key grants S3 read/write access to production bucket"
      }
    ],
    "securityScore": {
      "grade": "D",
      "score": 35,
      "breakdown": {
        "secretManagement": 20,
        "supplyChain": 50,
        "aiSecurity": 40,
        "infrastructure": 30
      }
    }
  }
}
```

---

##### `GET /api/v1/scans/:id/sarif`

**Description**: 스캔 결과를 SARIF 2.1.0 포맷으로 다운로드

**Response 200 OK**:
```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "wigtn-spear",
        "version": "1.0.0",
        "informationUri": "https://github.com/wigtn/spear",
        "rules": [
          {
            "id": "SPEAR-S001",
            "name": "aws-access-key",
            "shortDescription": { "text": "AWS Access Key Exposure" },
            "fullDescription": { "text": "An active AWS access key was found in the source code." },
            "help": { "text": "Remove the key and rotate credentials immediately." },
            "properties": {
              "security-severity": "9.1",
              "tags": ["secret", "aws", "cloud"]
            }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "SPEAR-S001",
        "level": "error",
        "message": { "text": "Active AWS access key found" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "src/config.ts" },
            "region": { "startLine": 42, "startColumn": 15 }
          }
        }],
        "partialFingerprints": {
          "primaryLocationLineHash": "abc123def456"
        }
      }
    ]
  }]
}
```

---

##### `POST /api/v1/scans`

**Description**: 대시보드에서 새 스캔 시작

**Request Body**:
```json
{
  "module": "string (required) - 모듈명 또는 'all'",
  "target": "string (required) - 스캔 대상 경로",
  "mode": "string (optional) - 'safe' | 'aggressive', default: 'safe'",
  "options": {
    "gitDepth": "number (optional) - Git 히스토리 깊이, default: 100 (safe) / -1 (aggressive)",
    "verifySecrets": "boolean (optional) - 시크릿 라이브 검증, default: false (safe) / true (aggressive)",
    "outputFormat": "string (optional) - 'sarif' | 'json' | 'html', default: 'json'"
  }
}
```

**Response 202 Accepted**:
```json
{
  "success": true,
  "data": {
    "scanId": "scan_xyz789",
    "status": "running",
    "estimatedDuration": 45000
  }
}
```

---

##### `GET /api/v1/stats/overview`

**Description**: 대시보드 전체 통계

**Response 200 OK**:
```json
{
  "success": true,
  "data": {
    "totalScans": 150,
    "totalFindings": 342,
    "criticalFindings": 12,
    "securityScore": {
      "current": "C",
      "trend": "improving",
      "history": [
        { "date": "2026-03-01", "grade": "F", "score": 15 },
        { "date": "2026-03-07", "grade": "D", "score": 35 },
        { "date": "2026-03-13", "grade": "C", "score": 52 }
      ]
    },
    "topVulnerabilities": [
      { "ruleId": "SPEAR-S001", "count": 15, "severity": "critical" },
      { "ruleId": "SPEAR-A003", "count": 8, "severity": "high" }
    ],
    "moduleBreakdown": {
      "secret-scanner": { "findings": 120, "lastRun": "2026-03-13T10:00:00Z" },
      "git-miner": { "findings": 45, "lastRun": "2026-03-13T09:30:00Z" },
      "mcp-poisoner": { "findings": 3, "lastRun": "2026-03-12T15:00:00Z" }
    }
  }
}
```

---

##### `GET /api/v1/shield/integration`

**Description**: SHIELD 연동 테스트 결과

**Response 200 OK**:
```json
{
  "success": true,
  "data": {
    "lastTest": "2026-03-13T10:00:00Z",
    "scenarios": [
      {
        "name": "brute-force-login",
        "attack": "5000 login attempts in 1 minute",
        "shieldDetected": true,
        "detectionTime": 12500,
        "shieldAgent": "IDS Agent",
        "confidence": 0.97
      },
      {
        "name": "mcp-tool-poisoning",
        "attack": "Injected tool description with data exfiltration payload",
        "shieldDetected": false,
        "gap": "No MCP monitoring agent configured"
      }
    ],
    "gapAnalysis": {
      "detected": 8,
      "missed": 3,
      "coverage": 72.7,
      "criticalGaps": ["MCP poisoning", "Prompt injection", "Slopsquatting"]
    },
    "securityScore": {
      "grade": "C",
      "score": 72.7
    }
  }
}
```

**Error Response Format** (모든 API 공통):
```json
{
  "success": false,
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "Scan with ID 'scan_invalid' not found",
    "details": []
  },
  "meta": {
    "timestamp": "2026-03-13T10:00:00Z"
  }
}
```

**Error Codes**:
| Status | Code | Description |
|--------|------|-------------|
| 400 | INVALID_INPUT | 잘못된 요청 파라미터 |
| 404 | SCAN_NOT_FOUND | 스캔 ID 없음 |
| 409 | SCAN_ALREADY_RUNNING | 동일 타겟 스캔 진행 중 |
| 422 | INVALID_MODULE | 존재하지 않는 모듈명 |
| 500 | INTERNAL_ERROR | 서버 내부 오류 |

### 5.3 Database Schema

```sql
-- 스캔 실행 기록
CREATE TABLE scans (
  id TEXT PRIMARY KEY,              -- scan_abc123
  module TEXT NOT NULL,             -- 'secret-scanner', 'git-miner', ...
  target TEXT NOT NULL,             -- 스캔 대상 경로
  mode TEXT NOT NULL DEFAULT 'safe', -- 'safe' | 'aggressive'
  status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'running' | 'completed' | 'failed'
  findings_critical INTEGER DEFAULT 0,
  findings_high INTEGER DEFAULT 0,
  findings_medium INTEGER DEFAULT 0,
  findings_low INTEGER DEFAULT 0,
  findings_info INTEGER DEFAULT 0,
  duration_ms INTEGER,              -- 스캔 소요 시간
  security_score INTEGER,           -- 0-100
  security_grade TEXT,              -- A-F
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 개별 발견 사항
CREATE TABLE findings (
  id TEXT PRIMARY KEY,              -- finding_001
  scan_id TEXT NOT NULL REFERENCES scans(id),
  rule_id TEXT NOT NULL,            -- SPEAR-S001
  severity TEXT NOT NULL,           -- 'critical' | 'high' | 'medium' | 'low' | 'info'
  file_path TEXT,                   -- 파일 경로
  line_number INTEGER,
  column_number INTEGER,
  secret_masked TEXT,               -- AKIA****XXXX (마스킹됨, 전체 시크릿 절대 저장 안 함)
  verified INTEGER DEFAULT 0,      -- 라이브 검증 여부
  verified_at TEXT,
  cvss REAL,                        -- CVSS 점수
  mitre_techniques TEXT,            -- JSON array: ["T1552.001"]
  remediation TEXT,                 -- 수정 가이드
  metadata TEXT,                    -- JSON: 모듈별 추가 데이터
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 공격 체인
CREATE TABLE attack_chains (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id),
  chain_data TEXT NOT NULL,         -- JSON: 공격 경로 단계별 데이터
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 탐지 룰
CREATE TABLE rules (
  id TEXT PRIMARY KEY,              -- SPEAR-S001
  category TEXT NOT NULL,           -- 'secret' | 'vulnerability' | 'misconfiguration'
  name TEXT NOT NULL,
  description TEXT,
  pattern TEXT,                     -- regex 패턴
  severity TEXT NOT NULL,
  tags TEXT,                        -- JSON array
  references TEXT,                  -- JSON array: CVE, CWE 링크
  enabled INTEGER DEFAULT 1,
  version TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- SHIELD 연동 결과
CREATE TABLE shield_tests (
  id TEXT PRIMARY KEY,
  scenario TEXT NOT NULL,
  attack_description TEXT,
  shield_detected INTEGER,          -- 0 | 1
  detection_time_ms INTEGER,
  shield_agent TEXT,                -- 탐지한 SHIELD 에이전트
  confidence REAL,
  gap_description TEXT,             -- 미탐지 시 원인
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 감사 로그
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,             -- 'scan_started' | 'scan_completed' | 'report_generated'
  module TEXT,
  target TEXT,
  mode TEXT,
  result_summary TEXT,              -- JSON: 요약 데이터
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 인덱스
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_rule_id ON findings(rule_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_module ON scans(module);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
```

### 5.4 Plugin Interface

```typescript
/**
 * WIGTN-SPEAR Plugin Interface
 * 모든 공격 모듈은 이 인터페이스를 구현합니다.
 */
interface SpearPlugin {
  metadata: {
    id: string;                     // 'secret-scanner'
    name: string;                   // 'Secret Scanner'
    version: string;                // '1.0.0'
    author: string;                 // 'WIGTN Team'
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    tags: string[];                 // ['secret', 'detection']
    references: string[];           // ['CVE-2025-xxxxx', 'CWE-798']
    safeMode: boolean;              // Safe Mode에서 실행 가능 여부
    requiresNetwork: boolean;       // 네트워크 접근 필요 여부
    supportedPlatforms: ('darwin' | 'linux' | 'win32')[];
    permissions: PluginPermission[]; // 요구 권한 목록 (아래 상세)
    trustLevel: 'builtin' | 'verified' | 'community' | 'untrusted';
  };

  // 라이프사이클
  setup?(context: PluginContext): Promise<void>;
  scan(target: ScanTarget): AsyncGenerator<Finding>;
  teardown?(context: PluginContext): Promise<void>;

  // 선택적: 라이브 검증
  verify?(finding: Finding): Promise<VerificationResult>;
}

interface PluginContext {
  mode: 'safe' | 'aggressive';
  workDir: string;
  config: SpearConfig;
  logger: Logger;
  db: Database;
  rateLimiter: RateLimiter;
  permissions: GrantedPermissions;  // 런타임에 부여된 권한
}

interface ScanTarget {
  path: string;                     // 스캔 대상 경로
  gitRepo?: boolean;                // Git 레포 여부
  include?: string[];               // glob 패턴
  exclude?: string[];               // .spearignore + 추가 제외
}

interface Finding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  file?: string;
  line?: number;
  column?: number;
  secretMasked?: string;            // 마스킹된 시크릿 (SecureSecret.mask() 결과)
  cvss?: number;
  mitreTechniques?: string[];
  remediation?: string;
  metadata?: Record<string, unknown>;
}

interface VerificationResult {
  verified: boolean;
  active: boolean;                  // 시크릿이 아직 유효한지
  service?: string;                 // 'aws', 'github', 'slack', ...
  permissions?: string[];           // 해당 키의 권한 목록
  verifiedAt: string;
}
```

#### 5.4.1 Plugin Security Model

플러그인 시스템은 최소 권한 원칙(Principle of Least Privilege)을 따릅니다.

**Permission 타입:**

```typescript
type PluginPermission =
  | 'fs:read'           // 파일시스템 읽기 (스캔 대상 경로 내)
  | 'fs:read-global'    // 파일시스템 읽기 (전체, 클라우드 크레덴셜 등)
  | 'git:read'          // Git 리포지토리 읽기
  | 'net:outbound'      // 외부 네트워크 요청 (라이브 검증)
  | 'net:listen'        // 로컬 서버 바인딩 (MCP Mock 서버)
  | 'process:read'      // 프로세스 정보 읽기 (환경변수, /proc)
  | 'exec:child'        // 자식 프로세스 실행 (git, docker CLI)
  | 'db:write';         // 결과 DB 쓰기

interface GrantedPermissions {
  has(perm: PluginPermission): boolean;
  assert(perm: PluginPermission): void;  // 없으면 PermissionDeniedError throw
}
```

**Trust Level 계층:**

| Level | 설명 | 권한 범위 | 설치 방법 |
|-------|------|----------|----------|
| `builtin` | WIGTN 팀 개발 공식 모듈 (Spear-01~20) | 모든 권한 | 번들 포함 |
| `verified` | 서명 검증 통과한 서드파티 플러그인 | metadata.permissions에 선언된 권한만 | `spear plugin install` + 서명 확인 |
| `community` | 미검증 커뮤니티 플러그인 | fs:read, git:read, db:write만 | `spear plugin install --allow-unverified` |
| `untrusted` | 서명 없음 또는 변조 감지 | 실행 불가 (차단) | - |

**서명 검증:**

```yaml
# 플러그인 패키지 내 spear-plugin.yaml
signature:
  algorithm: Ed25519
  publicKey: "wigtn-spear-plugin-signing-key-v1"
  digest: "sha256:abc123..."         # 플러그인 코드 해시
  signedAt: "2026-03-13T10:00:00Z"
  signedBy: "plugin-author@example.com"
```

- builtin 모듈: 빌드 시 WIGTN 팀 키로 서명, 무조건 신뢰
- verified 모듈: npm publish 시 저자 키로 서명 → `spear plugin install` 시 공개키 검증
- community 모듈: 서명 없어도 설치 가능하나 `--allow-unverified` 필수 + 제한된 권한만 부여
- 변조 감지 시 (`digest` 불일치): 즉시 차단 + 경고 로그

**런타임 샌드박싱:**

- 모든 플러그인은 별도 Worker Thread에서 실행 (메인 스레드 격리)
- `net:outbound` 권한 없는 플러그인의 네트워크 요청은 Worker 레벨에서 차단
- `exec:child` 권한 없는 플러그인의 child_process 호출은 차단
- Supply Chain Analyzer (Spear-08)는 추가로 `isolated-vm` 샌드박스 내에서 실행
- 플러그인 실행 시간 제한: 기본 5분 (타임아웃 시 Worker 강제 종료)

### 5.5 Secret Masking Algorithm (SecureSecret)

시크릿 마스킹은 단일 구현체 `SecureSecret` 클래스를 통해 일관 처리합니다.

```typescript
/**
 * SecureSecret: 시크릿 값의 안전한 핸들링
 *
 * 원칙:
 * 1. 원본 시크릿은 메모리에서만 존재, 디스크에 절대 기록 안 함
 * 2. 마스킹은 비가역적 (마스킹된 값에서 원본 복원 불가)
 * 3. GC 이전 메모리 제로화 (best-effort)
 */
class SecureSecret {
  private buffer: Buffer;  // 원본 값 (메모리만)

  constructor(raw: string) {
    this.buffer = Buffer.from(raw, 'utf-8');
  }

  /**
   * 마스킹 알고리즘:
   * - length >= 8: 앞 4자 + '****' + 뒤 4자
   *   예: "AKIAIOSFODNN7EXAMPLE" → "AKIA****MPLE"
   *
   * - 4 <= length < 8: 앞 2자 + '****'
   *   예: "abc123" → "ab****"
   *
   * - length < 4: '****' (전체 마스킹)
   *   예: "key" → "****"
   */
  mask(): string {
    const str = this.buffer.toString('utf-8');
    const len = str.length;
    if (len >= 8) return str.slice(0, 4) + '****' + str.slice(-4);
    if (len >= 4) return str.slice(0, 2) + '****';
    return '****';
  }

  /**
   * 라이브 검증 시에만 원본 사용 (메모리 내)
   * 검증 완료 후 즉시 dispose() 호출 필수
   */
  unsafeRawForVerification(): string {
    return this.buffer.toString('utf-8');
  }

  /**
   * 메모리 제로화 (best-effort)
   * Buffer.fill(0)으로 원본 데이터 덮어쓰기
   * V8 GC 특성상 100% 보장은 불가하나, 메모리 스캔 공격면 최소화
   */
  dispose(): void {
    this.buffer.fill(0);
  }

  // toString, toJSON, inspect 모두 마스킹된 값 반환
  toString(): string { return this.mask(); }
  toJSON(): string { return this.mask(); }
  [Symbol.for('nodejs.util.inspect.custom')](): string { return `SecureSecret(${this.mask()})`; }
}
```

**마스킹 적용 지점:**

| 지점 | 동작 |
|------|------|
| Finding 생성 시 | `finding.secretMasked = secret.mask()` (원본 미저장) |
| DB 저장 시 | `findings.secret_masked` 컬럼에 마스킹 값만 INSERT |
| SARIF 출력 시 | `result.message.text`에 마스킹 값 사용 |
| CLI stdout | 마스킹 값 출력 |
| 로그 파일 | 마스킹 값만 기록 |
| 라이브 검증 중 | `unsafeRawForVerification()` 사용 → 검증 완료 후 `dispose()` |
| 감사 로그 | 시크릿 값 자체는 기록하지 않음 (ruleId, file, line만 기록) |

**불변식 (Invariant):**
- 디스크에 기록되는 모든 데이터에서 `unsafeRawForVerification()` 결과가 존재하면 버그
- CI에서 정적 분석으로 `unsafeRawForVerification` 호출 후 `dispose()` 미호출 패턴 검출

### 5.6 Rules Format (YAML)

```yaml
# rules/secrets/aws-access-key.yaml
id: SPEAR-S001
name: AWS Access Key
description: Detects AWS access key IDs in source code
category: secret
severity: critical
tags: [aws, cloud, credential]
references:
  - https://cwe.mitre.org/data/definitions/798.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
mitre:
  - T1552.001  # Unsecured Credentials: Credentials In Files

# 탐지 규칙
detection:
  # 1단계: 키워드 프리필터 (Aho-Corasick)
  keywords:
    - AKIA
    - ASIA

  # 2단계: 정규식 매칭
  pattern: '(?:AKIA|ASIA)[0-9A-Z]{16}'

  # 3단계: 엔트로피 (선택)
  entropy:
    enabled: false  # AWS 키는 고정 형식이므로 엔트로피 불필요

# 검증 (Aggressive Mode)
verification:
  enabled: true
  method: aws-sts-get-caller-identity
  rateLimit:
    rpm: 10
    concurrent: 2

# 허용 목록
allowlist:
  patterns:
    - 'AKIAIOSFODNN7EXAMPLE'  # AWS 문서 예제 키
    - '(?i)example|test|dummy|fake|placeholder'
  paths:
    - '**/test/**'
    - '**/mock/**'
    - '**/*.test.*'
```

---

## 6. Implementation Phases

### Phase 1: Core Engine + MVP Modules (4주)

- [ ] 프로젝트 스캐폴딩 (Turborepo + oclif + Vite)
- [ ] Core Engine: Aho-Corasick + Regex + Entropy 파이프라인
- [ ] Worker Thread 병렬 처리
- [ ] Plugin Interface 구현
- [ ] YAML Rules Engine
- [ ] **Spear-01: Secret Scanner** (800+ 패턴)
- [ ] **Spear-02: Git History Miner** (reflog, fsck, dangling)
- [ ] SARIF 2.1.0 + JSON 리포터
- [ ] Safe Mode / Aggressive Mode 분기
- [ ] CLI 기본 명령어 (init, scan, report, config)
- [ ] SQLite DB + Drizzle ORM 스키마

**Deliverable**: `npm install -g wigtn-spear` 실행 가능, 시크릿 스캔 + Git 히스토리 분석 동작

### Phase 2: AI/MCP Attack Modules (3주)

- [ ] **Spear-04: MCP Poisoning Tester** (Mock 서버, Rug Pull)
- [ ] **Spear-06: Prompt Injection Fuzzer** (314+ 페이로드)
- [ ] **Spear-10: AI Agent Manipulation** (설정 파일 인젝션)
- [ ] **Spear-17: LLM Output Exploitation** (Slopsquatting)
- [ ] MITRE ATT&CK 매핑 통합
- [ ] Promptware Kill Chain 단계 추적
- [ ] 라이브 API 검증 엔진 + Rate Limiter

**Deliverable**: AI/MCP 공격 테스트 전체 동작, 프롬프트 인젝션 퍼징 가능

### Phase 3: Infrastructure Modules + Dashboard (3주)

- [ ] **Spear-11: CI/CD Pipeline Exploit** (GitHub Actions 분석)
- [ ] **Spear-13: Cloud Credential Chain** (AWS/GCP/Azure)
- [ ] Web Dashboard (Vite + React 19 + shadcn/ui)
- [ ] 대시보드 API (REST)
- [ ] Security Score 계산 (A-F)
- [ ] Attack Chain 시각화
- [ ] HTML 리포트 생성
- [ ] Remediation Playbook 자동 생성

**Deliverable**: 인프라 모듈 동작, 웹 대시보드 접근 가능

### Phase 4: P1 Modules + SHIELD Integration (2주)

- [ ] P1 모듈 8개 구현
- [ ] SHIELD 연동 테스트 프레임워크
- [ ] Gap Analysis 리포트
- [ ] 플러그인 마켓플레이스 기반
- [ ] `spear update-rules` 자동 업데이트
- [ ] E2E 테스트

**Deliverable**: 전체 20개 모듈 중 16개 동작, SHIELD 연동 가능

### Phase 5: P2 Modules + Production Polish (추후)

- [ ] P2 모듈 4개 구현
- [ ] 성능 최적화
- [ ] npm 패키지 퍼블리시
- [ ] 문서 사이트
- [ ] CI/CD GitHub Action (`wigtn/spear-action@v1`)

**Deliverable**: 프로덕션 릴리즈 v1.0.0

---

## 7. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| 시크릿 탐지율 (True Positive) | > 95% | 알려진 시크릿 벤치마크 대비 |
| 오탐률 (False Positive) | < 10% | 수동 검증 샘플링 |
| 스캔 속도 (10K 파일) | < 3분 | CI/CD 벤치마크 |
| Git 히스토리 복원율 | > 90% | dangling commit 벤치마크 |
| 프롬프트 인젝션 페이로드 수 | 314+ | AIShellJack 기준 |
| MCP 포이즈닝 탐지 시나리오 | 10+ | CVE 기반 재현 |
| SARIF 호환성 | 100% | GitHub Code Scanning 업로드 성공 |
| CLI 시작 시간 | < 200ms | oclif cold start |
| npm 패키지 다운로드 | 1,000+/월 (6개월 내) | npm stats |
| SHIELD 연동 테스트 시나리오 | 15+ | Red/Blue Team 시나리오 |

---

## 8. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|:-----------:|:------:|------------|
| 라이브 검증 시 API 차단 | High | Medium | Rate Limiter + 검증 캐시 + 지수 백오프 + --verify-limit 플래그 |
| 오탐으로 인한 사용자 피로 | Medium | High | 엔트로피 임계값 튜닝 + allowlist |
| AI IDE CVE 패치로 재현 불가 | Medium | Low | 버전별 테스트 + 새 CVE 지속 추적 |
| 법적 이슈 (공격 도구 오용) | Low | Critical | ToS 필수 동의(FR-080) + 권한 확인(FR-081) + CFAA/정보통신망법 고지(FR-082) + Safe Mode 기본 + 감사 로그 |
| npm 패키지 자체 공급망 공격 | Low | Critical | Sigstore 서명 + 2FA + GitHub Actions 퍼블리시 |
| 대규모 레포 스캔 중 crash/interrupt | Medium | Medium | WAL 모드 SQLite + resume token + graceful shutdown hook + Worker 재큐잉 |
| 악성 서드파티 플러그인 | Medium | High | Ed25519 서명 검증 + Trust Level 계층 + 권한 샌드박싱 + Worker 격리 |
| 시크릿 메모리 잔류 | Low | High | SecureSecret.dispose() + Buffer.fill(0) + 검증 후 즉시 해제 + CI 정적 분석 |
| Dashboard 네트워크 노출 | Low | High | Localhost 기본 + Network Mode 시 bcrypt 인증 필수 + JWT + 실패 잠금 |

---

## 9. Academic References

본 PRD의 공격 모듈은 다음 30편의 논문/연구에 근거합니다.
전체 상세 분석은 `docs/research/wigtn-spear-research.md`를 참고하세요.

### AI/LLM 에이전트 보안 (9편)
1. Greshake et al. "Indirect Prompt Injection" (AISec'23) - arXiv:2302.12173
2. Liu et al. "HouYi: Prompt Injection Framework" - arXiv:2306.05499
3. Schneier et al. "Promptware Kill Chain" (2026) - arXiv:2601.09625
4. Zou et al. "PoisonedRAG" (USENIX Security 2025) - arXiv:2402.07867
5. Shafran et al. "Machine Against the RAG" (USENIX Security 2025) - arXiv:2406.05870
6. "SoK: Prompt Injection on Agentic Coding Assistants" - arXiv:2601.17548
7. "Your AI, My Shell: AIShellJack" - arXiv:2509.22040
8. Marzouk "IDEsaster: AI IDE Vulnerability Class" (24 CVEs)
9. Errico et al. "Securing MCP" - arXiv:2511.20920

### 공급망 보안 (6편)
10. Spracklen et al. "Package Hallucinations / Slopsquatting" (USENIX 2025) - arXiv:2406.10279
11. Birsan "Dependency Confusion" (35 organizations)
12. "TypoSmart" - arXiv:2502.20528
13. "Cerebro: Malicious Package Detection" (ACM TOSEM) - arXiv:2309.02637
14. Valsorda "Supply Chain Compromise Survey" (2025)
15. OWASP Top 10:2025 A03: Software Supply Chain Failures

### 시크릿/키 탈취 (4편)
16. Microsoft "Whisper Leak: LLM Side-Channel" (2025)
17. Varonis "Cookie-Bite: MFA Bypass" (2025)
18. Truffle Security "12,000 Live API Keys in Training Data"
19. "TLS Key Material Extraction from Memory" (DFRWS 2024)

### 개발 환경 공격 (4편)
20. Lin et al. "UntrustIDE" (NDSS 2024 Distinguished Paper)
21. Git RCE via Submodule Hooks (CVE-2024-32002, CVE-2025-48384)
22. Unit 42 "GitHub Actions Supply Chain Attack" (CVE-2025-30066)
23. AI IDE Extension Namespace Hijacking (2025)

### 신흥 공격 벡터 (7편)
24. Nassi et al. "Morris II AI Worm" (Cornell Tech) - arXiv:2403.02817
25. Hubinger et al. "Sleeper Agents" (Anthropic) - arXiv:2401.05566
26. Anthropic "Constant-Sample Poisoning" - arXiv:2510.07192
27. "Poisoned LLMs in Security Automation" - arXiv:2511.02600
28. "AI Agent Data Exfiltration via Web Search" - arXiv:2510.09093
29. "HERCULE: Python Supply Chain Malware" (ICSE 2025)
30. Anthropic "First AI-Orchestrated Cyber Espionage" (2025)

---

## 10. Glossary

| 용어 | 설명 |
|------|------|
| **SPEAR** | Security Penetration & Exploitation Attack Runner |
| **SHIELD** | WIGTN의 방어(Blue Team) 제품 |
| **MCP** | Model Context Protocol - AI 도구의 외부 서비스 연결 프로토콜 |
| **Slopsquatting** | AI가 할루시네이션으로 추천하는 존재하지 않는 패키지명을 공격자가 선점 등록 |
| **Promptware** | 프롬프트 인젝션을 통해 실행되는 자연어 기반 "멀웨어" |
| **Kill Chain** | 사이버 공격의 단계별 진행 모델 |
| **Rug Pull** | MCP 서버가 사용자 승인 후 tool description을 악의적으로 변경 |
| **Dangling Commit** | Git에서 어떤 브랜치/태그도 참조하지 않는 고아 커밋 |
| **SARIF** | Static Analysis Results Interchange Format - 정적 분석 결과 표준 포맷 |
| **Entropy** | Shannon 엔트로피 - 문자열의 무작위성 측정 (높을수록 시크릿일 가능성) |
| **Aho-Corasick** | 다중 패턴 동시 검색 알고리즘 (키워드 프리필터링용) |
