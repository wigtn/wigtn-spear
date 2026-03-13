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

- [ ] 프로젝트 스캐폴딩 (Turborepo 모노레포 + 패키지 구조)
- [ ] oclif CLI 앱 초기화 (init, scan, report, config 명령어)
- [ ] Vite + React 19 대시보드 앱 초기화
- [ ] Core Engine: Aho-Corasick 키워드 프리필터
- [ ] Core Engine: Regex 패턴 매칭 (800+ 패턴)
- [ ] Core Engine: Shannon 엔트로피 분석
- [ ] Core Engine: Worker Thread 병렬 처리 풀
- [ ] Core Engine: AsyncGenerator 스트리밍 파이프라인
- [ ] Plugin Interface 정의 + 로더 구현
- [ ] YAML Rules Engine (GitLeaks TOML 호환)
- [ ] SQLite DB + Drizzle ORM 스키마 마이그레이션
- [ ] **Spear-01: Secret Scanner** 플러그인 구현
- [ ] **Spear-02: Git History Miner** 플러그인 구현
- [ ] SARIF 2.1.0 리포터
- [ ] JSON 리포터
- [ ] Safe Mode / Aggressive Mode 분기 로직
- [ ] .spearignore 파일 파서
- [ ] 시크릿 마스킹 유틸리티
- [ ] 감사 로그 기록
- [ ] 단위 테스트 (Core Engine)

**Deliverable**: `npm install -g wigtn-spear && spear scan` 동작

### Phase 2: AI/MCP Attack Modules (3주)

- [ ] **Spear-04: MCP Poisoning Tester** - Mock MCP 서버 구현
- [ ] **Spear-04: MCP Poisoning Tester** - Tool description 인젝션 엔진
- [ ] **Spear-04: MCP Poisoning Tester** - Rug Pull 시뮬레이션
- [ ] **Spear-06: Prompt Injection Fuzzer** - HouYi 3단계 페이로드
- [ ] **Spear-06: Prompt Injection Fuzzer** - AIShellJack 314 페이로드 DB
- [ ] **Spear-06: Prompt Injection Fuzzer** - Promptware Kill Chain 트래커
- [ ] **Spear-06: Prompt Injection Fuzzer** - MITRE ATT&CK 매핑
- [ ] **Spear-10: AI Agent Manipulation** - .cursorrules 인젝션
- [ ] **Spear-10: AI Agent Manipulation** - .claude/settings.json 인젝션
- [ ] **Spear-10: AI Agent Manipulation** - mcp.json 인젝션
- [ ] **Spear-17: LLM Output Exploitation** - Slopsquatting 탐지기
- [ ] **Spear-17: LLM Output Exploitation** - AI 백도어 패턴 스캐너
- [ ] **Spear-17: LLM Output Exploitation** - 패키지 존재 검증기
- [ ] 라이브 API 검증 엔진
- [ ] Rate Limiter (서비스별 RPM/동시성)
- [ ] 검증 캐시 (LRU)
- [ ] spear test / spear fuzz CLI 명령어
- [ ] 단위 테스트 (AI/MCP 모듈)

**Deliverable**: AI 공격 테스트 + 프롬프트 인젝션 퍼징 동작

### Phase 3: Infrastructure Modules + Dashboard (3주)

- [ ] **Spear-11: CI/CD Pipeline Exploit** - YAML 워크플로우 파서
- [ ] **Spear-11: CI/CD Pipeline Exploit** - Expression 인젝션 탐지
- [ ] **Spear-11: CI/CD Pipeline Exploit** - SHA 핀닝 감사
- [ ] **Spear-11: CI/CD Pipeline Exploit** - pull_request_target 탐지
- [ ] **Spear-11: CI/CD Pipeline Exploit** - OIDC 설정 스캐너
- [ ] **Spear-13: Cloud Credential Chain** - AWS 크레덴셜 스캐너
- [ ] **Spear-13: Cloud Credential Chain** - GCP 서비스 계정 스캐너
- [ ] **Spear-13: Cloud Credential Chain** - Azure 크레덴셜 스캐너
- [ ] **Spear-13: Cloud Credential Chain** - IMDS 접근 테스터
- [ ] **Spear-13: Cloud Credential Chain** - IAM 역할 체인 매퍼
- [ ] spear audit CLI 명령어
- [ ] Web Dashboard: 프로젝트 구조 + 라우팅
- [ ] Web Dashboard: 스캔 결과 대시보드 페이지
- [ ] Web Dashboard: 스캔 히스토리 페이지
- [ ] Web Dashboard: Security Score 페이지
- [ ] Web Dashboard: Attack Chain 시각화
- [ ] Dashboard REST API 구현
- [ ] HTML 리포트 생성기
- [ ] Remediation Playbook 생성기
- [ ] CVSS 기반 Security Score 계산기
- [ ] 단위 + 통합 테스트

**Deliverable**: 인프라 모듈 + 웹 대시보드 동작

### Phase 4: P1 Modules + SHIELD Integration (3주)

- [ ] **Spear-03: Env Exfiltration Simulator**
- [ ] **Spear-05: Dependency Confusion Checker**
- [ ] **Spear-08: Supply Chain Analyzer** (isolated-vm 샌드박스)
- [ ] **Spear-12: Container Security Auditor**
- [ ] **Spear-14: Network Recon & SSRF Tester**
- [ ] **Spear-15: IDE Extension Auditor**
- [ ] **Spear-16: Webhook & API Endpoint Scanner**
- [ ] **Spear-19: Social Engineering Code Analyzer**
- [ ] **Spear-21: Model Distillation Tester** 모듈 구현
- [ ] 증류 페이로드 YAML (CoT 추출 30+, 프롬프트 탈취 50+, 능력 탐색 200+)
- [ ] 기존 모듈 강화 (Spear-06 +50 증류 페이로드, Spear-10 +3 CoT, Spear-17 +3 증류 부산물)
- [ ] SHIELD 증류 탐지 시그니처 6종 정의 및 연동 테스트
- [ ] SHIELD 연동 테스트 프레임워크
- [ ] spear shield-test CLI 명령어
- [ ] Gap Analysis 리포트
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
| Total Tasks | 0/83 |
| Current Phase | - |
| Status | pending |

## Execution Log

| Timestamp | Phase | Task | Status |
|-----------|-------|------|--------|
| - | - | - | - |
