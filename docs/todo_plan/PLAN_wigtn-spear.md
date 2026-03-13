# Task Plan: WIGTN-SPEAR

> **Generated from**: docs/prd/wigtn-spear-prd.md
> **Created**: 2026-03-13
> **Status**: pending

## Execution Config

| Option | Value | Description |
|--------|-------|-------------|
| `auto_commit` | true | Phase 완료 시 자동 커밋 |
| `commit_per_phase` | true | Phase별 중간 커밋 |
| `quality_gate` | true | /auto-commit 품질 검사 |

## Phases

### Phase 1: Core Engine + MVP Modules (4주)

- [x] 프로젝트 스캐폴딩 (Turborepo 모노레포 + 패키지 구조)
- [x] oclif CLI 앱 초기화 (init, scan, report, config 명령어)
- [ ] Vite + React 19 대시보드 앱 초기화 → Phase 3으로 연기
- [x] Core Engine: Aho-Corasick 키워드 프리필터
- [x] Core Engine: Regex 패턴 매칭 (800+ 패턴)
- [x] Core Engine: Shannon 엔트로피 분석
- [x] Core Engine: Worker Thread 병렬 처리 풀
- [x] Core Engine: AsyncGenerator 스트리밍 파이프라인
- [x] Plugin Interface 정의 + 로더 구현
- [x] YAML Rules Engine (GitLeaks TOML 호환)
- [x] SQLite DB + Drizzle ORM 스키마 마이그레이션
- [x] **Spear-01: Secret Scanner** 플러그인 구현
- [x] **Spear-02: Git History Miner** 플러그인 구현
- [x] SARIF 2.1.0 리포터
- [x] JSON 리포터
- [x] Safe Mode / Aggressive Mode 분기 로직
- [x] .spearignore 파일 파서
- [x] 시크릿 마스킹 유틸리티
- [x] 감사 로그 기록
- [x] 단위 테스트 (Core Engine)

**Deliverable**: `npm install -g wigtn-spear && spear scan` 동작

### Phase 2: AI/MCP Attack Modules (3주)

- [x] **Spear-04: MCP Poisoning Tester** - Mock MCP 서버 구현
- [x] **Spear-04: MCP Poisoning Tester** - Tool description 인젝션 엔진
- [x] **Spear-04: MCP Poisoning Tester** - Rug Pull 시뮬레이션
- [x] **Spear-06: Prompt Injection Fuzzer** - HouYi 3단계 페이로드
- [x] **Spear-06: Prompt Injection Fuzzer** - AIShellJack 314 페이로드 DB
- [x] **Spear-06: Prompt Injection Fuzzer** - Promptware Kill Chain 트래커
- [x] **Spear-06: Prompt Injection Fuzzer** - MITRE ATT&CK 매핑
- [x] **Spear-10: AI Agent Manipulation** - .cursorrules 인젝션
- [x] **Spear-10: AI Agent Manipulation** - .claude/settings.json 인젝션
- [x] **Spear-10: AI Agent Manipulation** - mcp.json 인젝션
- [x] **Spear-17: LLM Output Exploitation** - Slopsquatting 탐지기
- [x] **Spear-17: LLM Output Exploitation** - AI 백도어 패턴 스캐너
- [x] **Spear-17: LLM Output Exploitation** - 패키지 존재 검증기
- [x] 라이브 API 검증 엔진
- [x] Rate Limiter (서비스별 RPM/동시성)
- [x] 검증 캐시 (LRU)
- [x] spear test / spear fuzz CLI 명령어
- [ ] 단위 테스트 (AI/MCP 모듈)

**Deliverable**: AI 공격 테스트 + 프롬프트 인젝션 퍼징 동작

### Phase 3: Infrastructure Modules + Dashboard (3주)

- [x] **Spear-11: CI/CD Pipeline Exploit** - YAML 워크플로우 파서
- [x] **Spear-11: CI/CD Pipeline Exploit** - Expression 인젝션 탐지
- [x] **Spear-11: CI/CD Pipeline Exploit** - SHA 핀닝 감사
- [x] **Spear-11: CI/CD Pipeline Exploit** - pull_request_target 탐지
- [x] **Spear-11: CI/CD Pipeline Exploit** - OIDC 설정 스캐너
- [x] **Spear-13: Cloud Credential Chain** - AWS 크레덴셜 스캐너
- [x] **Spear-13: Cloud Credential Chain** - GCP 서비스 계정 스캐너
- [x] **Spear-13: Cloud Credential Chain** - Azure 크레덴셜 스캐너
- [x] **Spear-13: Cloud Credential Chain** - IMDS 접근 테스터
- [x] **Spear-13: Cloud Credential Chain** - IAM 역할 체인 매퍼
- [x] spear audit CLI 명령어
- [ ] Web Dashboard: 프로젝트 구조 + 라우팅 → Phase 5로 연기
- [ ] Web Dashboard: 스캔 결과 대시보드 페이지 → Phase 5로 연기
- [ ] Web Dashboard: 스캔 히스토리 페이지 → Phase 5로 연기
- [ ] Web Dashboard: Security Score 페이지 → Phase 5로 연기
- [ ] Web Dashboard: Attack Chain 시각화 → Phase 5로 연기
- [ ] Dashboard REST API 구현 → Phase 5로 연기
- [x] HTML 리포트 생성기
- [ ] Remediation Playbook 생성기
- [x] CVSS 기반 Security Score 계산기
- [ ] 단위 + 통합 테스트

**Deliverable**: 인프라 모듈 + 웹 대시보드 동작

### Phase 4: P1 Modules + SHIELD Integration (3주)

- [x] **Spear-03: Env Exfiltration Simulator**
- [x] **Spear-05: Dependency Confusion Checker**
- [x] **Spear-08: Supply Chain Analyzer** (isolated-vm 샌드박스)
- [x] **Spear-12: Container Security Auditor**
- [x] **Spear-14: Network Recon & SSRF Tester**
- [x] **Spear-15: IDE Extension Auditor**
- [x] **Spear-16: Webhook & API Endpoint Scanner**
- [x] **Spear-19: Social Engineering Code Analyzer**
- [x] **Spear-21: Model Distillation Tester** 모듈 구현
- [x] 증류 페이로드 YAML (CoT 추출 30+, 프롬프트 탈취 50+, 능력 탐색 200+)
- [ ] 기존 모듈 강화 (Spear-06 +50 증류 페이로드, Spear-10 +3 CoT, Spear-17 +3 증류 부산물)
- [x] SHIELD 증류 탐지 시그니처 6종 정의 및 연동 테스트
- [x] SHIELD 연동 테스트 프레임워크
- [ ] spear shield-test CLI 명령어
- [x] Gap Analysis 리포트
- [ ] 플러그인 install/list CLI 명령어
- [ ] spear update-rules 자동 업데이트
- [ ] E2E 테스트

**Deliverable**: 17/21 모듈 동작 + SHIELD 연동 (증류 탐지 포함)

### Phase 5: P2 Modules + Production Polish (추후)

- [ ] **Spear-07: Clipboard/Memory Inspector**
- [ ] **Spear-09: Browser Extension Auditor**
- [ ] **Spear-18: Certificate & TLS Recon**
- [ ] **Spear-20: Hardware Token & Auth Bypass**
- [ ] 성능 최적화 (대규모 레포 벤치마크)
- [ ] npm 패키지 퍼블리시 설정
- [ ] GitHub Action (wigtn/spear-action@v1)
- [ ] 문서 사이트
- [ ] CSV 리포터

**Deliverable**: 프로덕션 릴리즈 v1.0.0

## Progress

| Metric | Value |
|--------|-------|
| Total Tasks | 62/83 |
| Current Phase | Phase 4 완료 |
| Status | in_progress |

## Execution Log

| Timestamp | Phase | Task | Status |
|-----------|-------|------|--------|
| 2026-03-13 12:20 | Phase 1 | 프로젝트 스캐폴딩 (Turborepo) | completed |
| 2026-03-13 12:25 | Phase 1 | oclif CLI 앱 초기화 | completed |
| 2026-03-13 12:30 | Phase 1 | Core Engine 전체 (AC, Regex, Entropy, Worker, Pipeline) | completed |
| 2026-03-13 12:32 | Phase 1 | Plugin Interface + 로더 | completed |
| 2026-03-13 12:33 | Phase 1 | YAML Rules Engine + 5 rule files | completed |
| 2026-03-13 12:33 | Phase 1 | SQLite DB + Drizzle ORM 스키마 | completed |
| 2026-03-13 12:35 | Phase 1 | Spear-01 Secret Scanner | completed |
| 2026-03-13 12:35 | Phase 1 | Spear-02 Git History Miner | completed |
| 2026-03-13 12:36 | Phase 1 | SARIF + JSON 리포터 | completed |
| 2026-03-13 12:36 | Phase 1 | Safe/Aggressive 분기, .spearignore, 마스킹, 감사로그 | completed |
| 2026-03-13 12:40 | Phase 1 | 단위 테스트 (154 tests, 6 files) | completed |
| 2026-03-13 12:48 | Phase 1 | 빌드 검증 (9/9 packages, 0 errors) | completed |
| 2026-03-13 12:48 | Phase 1 | 테스트 검증 (154/154 passed) | completed |
| 2026-03-13 13:04 | Phase 2 | Spear-04 MCP Poisoning Tester (25 patterns, mock server, rug pull) | completed |
| 2026-03-13 13:04 | Phase 2 | Spear-06 Prompt Injection Fuzzer (1000 HouYi + 314 ASJ payloads) | completed |
| 2026-03-13 13:04 | Phase 2 | Spear-10 Agent Manipulator (89 patterns, 4 scanners) | completed |
| 2026-03-13 13:04 | Phase 2 | Spear-17 LLM Output Exploiter (52 hallucinations, 34 backdoor patterns) | completed |
| 2026-03-13 13:04 | Phase 2 | Rate Limiter + Verification Cache (core infra) | completed |
| 2026-03-13 13:04 | Phase 2 | spear test / spear fuzz CLI commands | completed |
| 2026-03-13 13:34 | Phase 2 | 빌드 검증 (13/13 packages, 0 errors) | completed |
| 2026-03-13 13:34 | Phase 2 | 테스트 검증 (154/154 passed, 0 regressions) | completed |
| 2026-03-13 13:46 | Phase 3 | Spear-11 CI/CD Exploiter (65 patterns, 8 categories, 5 scanners) | completed |
| 2026-03-13 13:46 | Phase 3 | Spear-13 Cloud Credential Chain (65 patterns, AWS/GCP/Azure/IMDS/IAM) | completed |
| 2026-03-13 13:46 | Phase 3 | spear audit CLI + HTML Reporter + CVSS Security Score | completed |
| 2026-03-13 13:46 | Phase 3 | 빌드 검증 (15/15 packages, 0 errors) | completed |
| 2026-03-13 13:46 | Phase 3 | 테스트 검증 (154/154 passed, 0 regressions) | completed |
