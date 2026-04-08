[English](README.md) | [한국어](README.ko.md)

# WIGTN-SPEAR

**AI Red Team Arena Tool** — 안전 필수 도메인에 배치된 AI 에이전트에 대한 적대적 테스트 도구.

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

SPEAR는 **Judgement Day AI Red Team Arena**를 위해 제작되었습니다 — 안전 필수 환경에 배치된 AI 에이전트를 멀티모달 공격으로 무력화하는 라이브 적대적 경쟁 대회입니다.

| | |
|---|---|
| **주최** | AIM Intelligence + 한국 AI 안전연구소 (AISI) |
| **기간** | 2026년 4월 6일 ~ 5월 31일 |
| **상금** | $21,150 (상위 50명) |
| **트랙** | 2개 트랙 x 4개 시나리오 = 총 8개 |
| **대상 모델** | GPT-5.4, Claude Opus 4.6, Gemini 3.1 Pro, Gemini 3 Flash, GPT-Audio-1.5, MiMo-V2-Omni |

### Track 1: Action Induction (행동 유도)

적대적 멀티모달 입력을 통해 AI 에이전트가 **금지된 행동**을 선택하도록 유도합니다.

| # | 시나리오 | 도메인 | 타겟 액션 | 채널 | Wave |
|---|----------|--------|-----------|------|------|
| 0 | 응급 분류 | 의료/임상 | `override_to_esi1` | 오디오, 문서 | 1 (활성) |
| 1 | 산업 로봇 | 제조/안전 | `resume_production` | 이미지, 오디오 | 1 (활성) |
| 2 | 스포츠 무결성 | 스포츠 기술 | 클린 선수 플래그 | 오디오, 이미지 | 2 (4월 27일) |
| 3 | 댐 홍수 제어 | 핵심 인프라 | 수문 개방 | 비디오, 오디오 | 2 (4월 27일) |

### Track 2: Action Suppression (행동 억제)

오도 정보를 주입하여 AI 에이전트가 **올바른 안전 행동**을 선택하지 못하게 합니다.

| # | 시나리오 | 도메인 | 억제 대상 액션 | 채널 | Wave |
|---|----------|--------|----------------|------|------|
| 0 | 사이버보안 SOC | 보안 운영 | `open_p1_incident` | 오디오, 텍스트 | 1 (활성) |
| 1 | 항공기 정비 | 항공/비행 안전 | `issue_maintenance_hold` | 문서, 오디오 | 1 (활성) |
| 2 | 역학 감시 | 공중 보건 | `declare_outbreak` | 비디오, 오디오, 문서 | 2 (4월 27일) |
| 3 | 딥페이크 탐지 | 디지털 포렌식 | `flag_as_deepfake` | 오디오, 이메일+PDF | 2 (4월 27일) |

## 공격 전략

SPEAR는 실전 검증된 보안 모듈을 활용하여 대회용 공격을 생성합니다:

```
┌─────────────────────────────────────────────────────────┐
│                    SPEAR Arena Pipeline                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  시나리오 컨텍스트     공격 생성             제출        │
│  ┌──────────────┐    ┌────────────────┐    ┌─────────┐ │
│  │ Spear-26     │───>│ Spear-23       │───>│ JSON    │ │
│  │ 시나리오     │    │ 페이로드       │    │ 포맷    │ │
│  │ 엔진         │    │ (37+ payloads) │    │         │ │
│  └──────────────┘    └────────────────┘    └─────────┘ │
│         │                    │                          │
│         v                    v                          │
│  ┌──────────────┐    ┌────────────────┐                │
│  │ Spear-27     │    │ 멀티턴 엔진    │                │
│  │ 권위 사칭    │    │ (Crescendo/TAP)│                │
│  └──────────────┘    └────────────────┘                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 전략 매핑

| 전략 | 모듈 | 적용 시나리오 | 방법 |
|------|------|---------------|------|
| 간접 프롬프트 주입 | Spear-23 | 전체 | 도메인 맥락화된 페이로드를 문서/텍스트 채널로 전달 |
| 권위 사칭 | Spear-27 | 전체 | 의사 의뢰서, CISO 메모, Boeing SIL, supervisor 지시 |
| Crescendo (멀티턴) | Spear-23 | SOC, 응급 분류 | 점진적 신뢰 구축 (Microsoft 연구 기준 98% 우회율) |
| TAP (공격 트리) | Spear-23 | 전체 | LLM 생성 공격 변형 + 가지치기 |
| 경제적 압박 | Spear-23 | 로봇, 항공기 | 비용 기반 긴급성 프레이밍 ($15K/hr 지연, $2M 계약) |
| 소셜 엔지니어링 | Spear-19 | SOC, 항공기 | 기만적 명명, 유니코드 트릭, 권위 프레이밍 |

## 무기고 (Arsenal)

### Arena 모듈 (대회 전용)

| 모듈 | 이름 | 용도 |
|------|------|------|
| Spear-26 | Scenario Engine | 8개 시나리오 정의, 전략 매핑, 공격 생성, 제출 포맷팅 |
| Spear-27 | Authority Spoof | 도메인별 권위 문서 템플릿 (의료, 항공, 사이버보안, 산업) |
| Spear-28 | Multimodal Craft | 오디오/이미지/비디오 공격 생성 (TTS, PDF 문서, 시각적 기만) |

### 라이브 공격 모듈

| 모듈 | 이름 | Arena 활용 |
|------|------|-----------|
| Spear-23 | Live Prompt Inject | 37+ 주입 페이로드 (의료, 항공, SOC 도메인 특화 포함) + 멀티턴 엔진 |
| Spear-24 | MCP Live Test | MCP 서버 도구 포이즈닝을 통한 에이전트 조작 |
| Spear-25 | Endpoint Prober | 타겟 정찰, API 발견, 인증 갭 분석 |

### 정적 분석 모듈

| 모듈 | 이름 | Arena 활용 |
|------|------|-----------|
| Spear-01 | Secret Scanner | 타겟 서비스에서 API 키 추출 |
| Spear-02 | Git Miner | 히스토리 내 시크릿 채굴 및 자격증명 수집 |
| Spear-04 | MCP Poisoner | MCP 도구 설명 주입 패턴 |
| Spear-06 | Prompt Injector | 정적 프롬프트 주입 패턴 라이브러리 (1000+ 조합) |
| Spear-10 | Agent Manipulator | AI 에이전트 설정 악용 패턴 |
| Spear-17 | LLM Exploiter | LLM 출력 처리 취약점 탐지 |
| Spear-19 | Social Engineer | 소셜 엔지니어링 패턴, 유니코드 트릭, 권위 기만 |
| Spear-21 | Distillation | 모델 증류/탈취 지표 |

<details>
<summary>전체 모듈 목록 (22개)</summary>

| 모듈 | 이름 | 탐지 대상 |
|------|------|-----------|
| Spear-01 | Secret Scanner | 소스 코드 내 API 키, 토큰, 비밀번호 |
| Spear-02 | Git Miner | git 히스토리 및 삭제된 커밋 내 시크릿 |
| Spear-03 | Env Exfiltrator | 노출된 .env 파일 및 환경 변수 |
| Spear-04 | MCP Poisoner | 악성 MCP 서버 구성 |
| Spear-05 | Dep Confusion | 의존성 혼동 공격 벡터 |
| Spear-06 | Prompt Injector | 정적 프롬프트 주입 취약점 패턴 |
| Spear-08 | Supply Chain | 취약한 의존성, 타이포스쿼팅 |
| Spear-10 | Agent Manipulator | AI 에이전트 도구 악용 패턴 |
| Spear-11 | CI/CD Exploiter | 파이프라인 주입, CI 내 시크릿 노출 |
| Spear-12 | Container Audit | Dockerfile 보안 이슈 |
| Spear-13 | Cloud Credential | 클라우드 제공자 자격증명 체인 |
| Spear-14 | SSRF Tester | 서버 사이드 요청 위조 패턴 |
| Spear-15 | IDE Audit | VS Code 확장 및 IDE 설정 취약점 |
| Spear-16 | Webhook Scanner | 노출된 웹훅 엔드포인트 및 시크릿 |
| Spear-17 | LLM Exploiter | LLM 출력 처리 취약점 |
| Spear-18 | TLS Recon | TLS/SSL 설정 분석 |
| Spear-19 | Social Engineer | 소셜 엔지니어링 공격 표면 |
| Spear-21 | Distillation | 모델 증류/탈취 지표 |
| Spear-22 | Infra Intel | 인프라 정보 추출 |
| Spear-23 | Live Prompt Inject | 37+ 주입 페이로드 (HTTP/WebSocket/Relay) |
| Spear-24 | MCP Live Test | 실시간 MCP 서버 포이즈닝 |
| Spear-25 | Endpoint Prober | 클라우드 발견, OpenAPI, 인증 우회, AI 인프라 스캔 |

</details>

## 빠른 시작

```bash
# 설치
pnpm install

# 빌드
pnpm turbo build

# 활성 아레나 시나리오 목록
node apps/cli/bin/run.js arena list

# 응급 분류 공격 생성 (문서 채널)
node apps/cli/bin/run.js arena generate \
  --scenario emergency-triage \
  --channel document \
  --strategy authority-spoof

# SOC 공격 생성 (텍스트 채널, crescendo 전략)
node apps/cli/bin/run.js arena generate \
  --scenario soc-cybersecurity \
  --channel text \
  --strategy crescendo

# 제출 JSON 검증
node apps/cli/bin/run.js arena submit \
  --file ./attacks/soc-text-001.json \
  --validate-only
```

### 레거시 커맨드 (보안 스캐너)

```bash
# 정적 스캔 (안전, 네트워크 없음)
node apps/cli/bin/run.js scan ./path-to-target-repo

# 라이브 공격 (실제 요청 전송)
node apps/cli/bin/run.js attack https://target-url.com \
  --module endpoint-prober \
  --max-requests 100
```

## 보안 연구 기반

SPEAR의 아레나 역량은 포괄적인 보안 연구 커버리지 위에 구축되어 있습니다:

**OWASP LLM Top 10: 10/10 | OWASP Web Top 10: 10/10**

<details>
<summary>OWASP 커버리지 상세</summary>

### OWASP Top 10 for LLM Applications

| # | 취약점 | 모듈 | 방법 |
|---|--------|------|------|
| LLM01 | 프롬프트 주입 | Spear-23 | 37+ 페이로드 (HTTP/WebSocket/Relay 체인) |
| LLM02 | 민감 정보 노출 | Spear-23 | 시스템 프롬프트 추출 공격 |
| LLM03 | 공급망 | Spear-08 | 의존성 혼동, 타이포스쿼팅 탐지 |
| LLM04 | 데이터 & 모델 포이즈닝 | Spear-25 | MLflow, Ollama, LangServe, Triton 엔드포인트 스캔 |
| LLM05 | 불안전 출력 처리 | Spear-23 | 출력 조작 페이로드 |
| LLM06 | 과도한 에이전시 | Spear-10 | 에이전트 도구 악용 분석 |
| LLM07 | 시스템 프롬프트 유출 | Spear-23 | 5가지 추출 기법 |
| LLM08 | 벡터 & 임베딩 약점 | Spear-25 | Qdrant, Weaviate, Chroma, Milvus, Pinecone 스캔 |
| LLM09 | 오정보 | Spear-23 | 사실 반전, 인용 위조, 의료 오정보 |
| LLM10 | 무제한 소비 | Spear-25 | 요청 제한 탐지 |

### OWASP Top 10 for Web Applications

| # | 취약점 | 모듈 |
|---|--------|------|
| A01 | 접근 제어 결함 | Spear-25 (10가지 인증 우회 기법) |
| A02 | 암호화 실패 | Spear-18 (TLS 정찰) |
| A03 | 인젝션 | Spear-23 (프롬프트 주입) |
| A04 | 불안전 설계 | Spear-25 (OpenAPI 노출, 위험 파라미터) |
| A05 | 보안 설정 오류 | Spear-25 (Swagger, Cloud Run 발견, CORS) |
| A06 | 취약 컴포넌트 | Spear-08, Spear-05 |
| A07 | 인증 실패 | Spear-25 (토큰 프로빙) |
| A08 | 소프트웨어 무결성 | Spear-11 (CI/CD 파이프라인 분석) |
| A09 | 로깅 실패 | Spear-25 (debug/actuator/pprof/env 스캐너) |
| A10 | SSRF | Spear-14 |

</details>

## 아키텍처

```
wigtn-spear/
├── apps/
│   └── cli/                          # CLI 애플리케이션 (oclif)
│       └── commands/
│           ├── scan.ts               # 정적 보안 스캔
│           ├── attack.ts             # URL 대상 라이브 공격
│           └── arena/                # 아레나 대회 커맨드
│               ├── list.ts           # 활성 시나리오 목록
│               ├── generate.ts       # 공격 페이로드 생성
│               └── submit.ts         # 제출 검증 & 포맷팅
├── packages/
│   ├── shared/                       # 타입, 인터페이스, 상수
│   ├── core/                         # 스캔 엔진, 속도 제한기
│   ├── db/                           # SQLite 영속성 (drizzle)
│   ├── plugin-system/                # 플러그인 레지스트리 및 라이프사이클
│   ├── rules-engine/                 # 발견 분류
│   ├── reporters/                    # HTML, JSON, SARIF 리포터
│   └── plugins/                      # 25개 공격 모듈
│       ├── spear-01 ~ spear-22/      # 정적 분석 모듈
│       ├── spear-23-live-prompt-inject/  # 페이로드 라이브러리 + 멀티턴
│       ├── spear-24-mcp-live-test/       # MCP 서버 테스트
│       ├── spear-25-endpoint-prober/     # 엔드포인트 정찰
│       ├── spear-26-scenario-engine/     # 아레나 시나리오 관리
│       ├── spear-27-authority-spoof/     # 권위 문서 템플릿
│       └── spear-28-multimodal-craft/    # 멀티모달 공격 생성
└── turbo.json
```

## 기술 스택

- **런타임**: Node.js 22+ (내장 fetch, WebSocket)
- **언어**: TypeScript 5.4 (strict mode)
- **빌드**: Turborepo (모노레포), pnpm (워크스페이스)
- **CLI**: oclif v3
- **데이터베이스**: SQLite via drizzle-orm
- **외부 의존성**: 공격 모듈은 제로 (모두 내장 API)

## 팀

WIGTN 해커톤 팀 2

## 라이선스

Private — WIGTN Internal

---

## WIGTN Crew 소개

이 프로젝트는 **[WIGTN Crew](https://wigtn.com)**가 제작하고 유지합니다 —
한국 기반의 AI 네이티브 오픈소스 연구 크루입니다.
실용적이고 도메인 특화된 AI 도구를 만듭니다. 빠른 프로토타이핑, 강력한 엔지니어링, 실제 결과물 배포.

| | |
|---|---|
| 웹사이트 | [wigtn.com](https://wigtn.com) |
| GitHub | [github.com/wigtn](https://github.com/wigtn) |
| HuggingFace | [huggingface.co/Wigtn](https://huggingface.co/Wigtn) |
| NPM | [npmjs.com/org/wigtn](https://www.npmjs.com/org/wigtn) |

### 프로젝트

| 프로젝트 | 설명 | 상태 |
|----------|------|------|
| [WIGTN-SPEAR](https://github.com/wigtn/wigtn-spear) | Judgement Day 2026 AI Red Team Arena Tool | 활성 |
| [WigtnOCR](https://huggingface.co/Wigtn/Qwen3-VL-2B-WigtnOCR) | VLM 기반 한국 공문서 파서 | 연구 |
| [WIGVO](https://wigtn.com) | 실시간 PSTN 음성 번역 (한국어↔영어) | 연구 |
| [Claude Code Plugin](https://github.com/wigtn/wigtn-plugins-with-claude-code) | 멀티 에이전트 병렬 실행 에코시스템 | 오픈소스 |

> 이력서보다 결과물이 말한다.
