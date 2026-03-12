# WIGTN-SPEAR: 공격 벡터 연구 및 기술 분석 보고서

> **Version:** 1.0
> **Date:** 2026-03-13
> **Team:** WIGTN Hackathon Team 2
> **Status:** Research Complete

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [WIGTN-SHIELD 분석](#2-wigtn-shield-분석)
3. [공격 벡터 연구 - 논문 30편 분석](#3-공격-벡터-연구---논문-30편-분석)
4. [공격 모듈 설계 (20개)](#4-공격-모듈-설계-20개)
5. [기존 도구 대비 차별화](#5-기존-도구-대비-차별화)
6. [기술 스택 타당성 분석](#6-기술-스택-타당성-분석)
7. [아키텍처 참조 분석](#7-아키텍처-참조-분석)
8. [SHIELD-SPEAR 시너지](#8-shield-spear-시너지)

---

## 1. 프로젝트 개요

### 1.1 한 줄 정의

**WIGTN-SPEAR**: 바이브 코딩 시대의 개발 환경 전용 공격 시뮬레이션 & 시크릿 탈취 테스트 플랫폼

### 1.2 포지셔닝

- **TruffleHog** = "이미 새어나간 시크릿을 찾는다" (수동적)
- **Semgrep** = "코드 정적 분석" (방어자 시점)
- **GitLeaks** = "Git에서 시크릿 스캔" (수동적)
- **WIGTN-SPEAR** = **"실제 공격자처럼 능동적으로 탈취를 시도하고 성공 여부를 증명한다"** (공격자 시점)

### 1.3 왜 지금인가

| 지표 | 수치 | 출처 |
|------|------|------|
| AI 생성 코드의 보안 취약점 비율 | **45%** | Veracode 2025 |
| 코딩 AI 방어 우회 성공률 | **41-85%** | arXiv SoK 2026 |
| AI 추천 패키지 중 존재하지 않는 것 | **~20%** | USENIX Security 2025 |
| MCP 에이전트 스킬 중 프롬프트 인젝션 | **36%** | Snyk 2026 |
| 모든 AI IDE에서 취약점 발견 | **100%** | IDEsaster 2025 |
| 브라우저 확장 악성 피해 사용자 | **5.8M+** | 2024-2025 종합 |
| 노출된 .env 변수 조합 | **90,000+** | Cyble 연구 |
| 2020년 대비 공급망 공격 증가 | **~4배** | IBM X-Force 2026 |
| 오픈소스 앱당 평균 취약점 | **581개** | 업계 보고서 |

---

## 2. WIGTN-SHIELD 분석

### 2.1 쉴드 현재 상태

- **단계:** PRD 완료, 구현 코드 없음
- **아키텍처:** 11개 AI 에이전트 기반 보안 모니터링 플랫폼
- **기술:** Node.js + Express, LangGraph, Google Vertex AI (Gemini 2.0 Flash)
- **핵심 차별점:** Thought Signature (AI 추론 과정 암호화 서명)

### 2.2 쉴드 방어 범위

**커버됨:**
| OWASP/MITRE | 에이전트 | 상태 |
|-------------|---------|------|
| A01 Broken Access Control | IAM Agent | P0 |
| A03 Injection | Injection Agent | P0 |
| A05 Misconfiguration | Misconfiguration Agent | P2 |
| A06 Vulnerable Components | Supply Chain Agent | P1 |
| A07 Auth Failures | IDS + JWT | P0 |
| A08 Software Integrity | Supply Chain + Thought Signature | P0/P1 |
| A09 Logging Failures | Full Audit Trail | P0 |
| T1110 Brute Force | IDS Agent | P0 |
| T1021 Lateral Movement | Lateral Movement Agent | P1 |
| T1041 Data Exfiltration | DLP Agent | P0 |
| T1498 DDoS | DDoS Agent | P0 |
| T1486 Ransomware | Ransomware Agent | P2 |
| T1195 Supply Chain | Supply Chain Agent | P1 |

### 2.3 쉴드의 빈틈 (= SPEAR가 노릴 곳)

| 빈틈 | 위험도 | 설명 |
|------|--------|------|
| `.env` / `config.yaml` 평문 시크릿 | **Critical** | 환경변수 참조 권고하지만 초기 설정 시 평문 노출 구간 존재 |
| `SERVER_SECRET_KEY` 단일 장애점 | **Critical** | Thought Signature 키 탈취 시 모든 서명 위조 가능 |
| npm 패키지 공급망 | **High** | wigtn-shield 자체가 npm 패키지 - 탈취 시 전체 사용자 장악 |
| MCP 서버 연동 부재 | **Medium** | 바이브코딩 시대 공격면 미고려 |
| AI 에이전트 프롬프트 인젝션 | **High** | LangGraph 에이전트가 외부 로그 처리 시 인젝션 가능 |
| 24-word 복구코드 관리 | **High** | 화면 출력 → 숄더서핑/스크린캡처 가능 |
| A04 Insecure Design | **Medium** | 설계 단계 이슈, 런타임 탐지 불가 |
| A02 Cryptographic Failures | **Medium** | Thought Signature 외 부분적 커버 |
| SSRF (A10) | **Medium** | P2로 후순위 |

---

## 3. 공격 벡터 연구 - 논문 30편 분석

### Category 1: AI/LLM 에이전트 보안 (9편)

---

#### Paper 01: Indirect Prompt Injection (Greshake et al.)

- **제목:** "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"
- **저자:** Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz
- **학회:** ACM AISec'23; revised Jan 2024
- **arXiv:** [2302.12173](https://arxiv.org/abs/2302.12173)
- **핵심 기법:** Indirect Prompt Injection (IPI) - 공격자가 LLM과 직접 상호작용하지 않고, LLM이 추론 시 검색하는 데이터(웹페이지, 이메일, 문서)에 악성 프롬프트를 배치. Bing Chat과 코드 완성 엔진에서 실증.
- **SPEAR 적용:** README, 코드 주석, 웹 콘텐츠에 IPI 페이로드 삽입 → AI 에이전트의 데이터 탈취, 비인가 도구 호출 테스트
- **영향:** Black Hat USA 2023 발표. OWASP LLM01:2025로 채택.

---

#### Paper 02: HouYi - Prompt Injection Framework (Liu et al.)

- **제목:** "Prompt Injection attack against LLM-integrated Applications"
- **저자:** Yi Liu, Gelei Deng, Yuekang Li, Kailong Wang 외
- **arXiv:** [2306.05499](https://arxiv.org/abs/2306.05499)
- **핵심 기법:** 웹 인젝션에서 영감받은 블랙박스 프롬프트 인젝션 프레임워크. 3단계 컴포넌트: (1) 컨텍스트 블렌딩 프롬프트, (2) 컨텍스트 파티션 인젝션, (3) 악성 페이로드. **36개 실제 앱 중 31개 취약** 확인. Notion 포함.
- **SPEAR 적용:** 3단계 인젝션 패턴 자동화. 시스템 프롬프트 구조 탐색 → 파티션 문자열 생성 → 데이터 탈취 페이로드 전달
- **오픈소스:** [GitHub: LLMSecurity/HouYi](https://github.com/LLMSecurity/HouYi)

---

#### Paper 03: Promptware Kill Chain (Schneier et al. 2026)

- **제목:** "The Promptware Kill Chain"
- **저자:** Bruce Schneier 외
- **arXiv:** [2601.09625](https://arxiv.org/abs/2601.09625)
- **학회:** Lawfare 게재, Harvard Berkman Klein Center, Black Hat 웨비나 2026.02
- **핵심 기법:** 프롬프트웨어 7단계 킬체인 제안:
  1. Initial Access (프롬프트 인젝션)
  2. Privilege Escalation (탈옥)
  3. Reconnaissance (정찰)
  4. Persistence (메모리/RAG 포이즈닝)
  5. Command & Control
  6. Lateral Movement
  7. Actions on Objective
- 36개 연구 메타분석: **21개가 4단계 이상 진행 성공**
- **SPEAR 적용:** 킬체인 각 단계를 독립적으로 테스트. 초기 인젝션이 지속성(에이전트 메모리 오염)으로 에스컬레이션 가능한지, 횡이동이 가능한지 검증.

---

#### Paper 04: PoisonedRAG (USENIX Security 2025)

- **제목:** "PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of LLMs"
- **저자:** Wei Zou, Runpeng Geng 외
- **학회:** [USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag)
- **arXiv:** [2402.07867](https://arxiv.org/abs/2402.07867)
- **핵심 기법:** RAG 지식 데이터베이스 최초 오염 공격. 수백만 항목의 DB에 **질문당 5개 악성 텍스트만 주입**으로:
  - NQ: 97% 성공
  - HotpotQA: 99% 성공
  - MS-MARCO: 91% 성공
- **SPEAR 적용:** RAG 시스템의 지식베이스에 조작 문서 주입 → 에이전트 출력 제어 가능 여부 테스트
- **오픈소스:** [GitHub](https://github.com/sleeepeer/PoisonedRAG)

---

#### Paper 05: Machine Against the RAG (USENIX Security 2025)

- **제목:** "Machine Against the RAG: Jamming Retrieval-Augmented Generation with Blocker Documents"
- **저자:** Avital Shafran, Roei Schuster
- **학회:** [USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-shafran.pdf)
- **arXiv:** [2406.05870](https://arxiv.org/html/2406.05870v4)
- **핵심 기법:** "Blocker documents"로 RAG 시스템 방해. 블랙박스, 쿼리 전용 접근만으로 동작. 임베딩 모델/LLM 지식 불필요. 자신의 문서만 삽입/수정 가능한 최소 권한.
- **SPEAR 적용:** 최소 권한 상태에서 RAG 시스템 응답 품질 저하/제어 가능 여부 테스트.

---

#### Paper 06: SoK - 에이전트 코딩 어시스턴트 프롬프트 인젝션 (2026)

- **제목:** "Prompt Injection Attacks on Agentic Coding Assistants"
- **arXiv:** [2601.17548](https://arxiv.org/abs/2601.17548)
- **핵심 기법:** Claude Code, GitHub Copilot, Cursor, MCP 아키텍처 분석. 3차원 분류 체계: (전달 벡터) x (공격 양식) x (전파 행동). 78개 연구 메타분석: **어댑티브 전략 시 공격 성공률 85%+**
- **SPEAR 적용:** 분류 체계에 따른 체계적 테스트: 파일 콘텐츠/도구 출력/웹 콘텐츠 x 텍스트/이미지/구조화 데이터 x 단발/자기복제/교차에이전트

---

#### Paper 07: "Your AI, My Shell" - AIShellJack (2025)

- **제목:** "Your AI, My Shell": Demystifying Prompt Injection Attacks on Agentic AI Coding Editors
- **arXiv:** [2509.22040](https://arxiv.org/abs/2509.22040)
- **핵심 기법:** 314개 고유 공격 페이로드, 70개 MITRE ATT&CK 기법 커버. GitHub Copilot, Cursor 평가. **악성 명령 실행 성공률 84%**. 공격자가 외부 개발 리소스(레포, 문서, 웹페이지) 오염 → AI 에이전트 터미널 접근으로 임의 명령 실행.
- **SPEAR 적용:** 314개 페이로드 세트 배포 → MITRE ATT&CK 매핑 → 크레덴셜 탈취 경로 테스트

---

#### Paper 08: IDEsaster - AI IDE 취약점 클래스 (2025)

- **제목:** "IDEsaster: A Novel Vulnerability Class in AI IDEs"
- **저자:** Ari Marzouk
- **발표:** 2025.12, 24 CVEs 할당
- **핵심 기법:** Cursor, Windsurf, GitHub Copilot, Kiro.dev, Zed.dev, Roo Code, Junie, Cline, Gemini CLI, Claude Code 등 **테스트한 모든 AI IDE(100%)에서 취약점 발견**. 공격 체인: (1) LLM 가드레일 우회 → (2) 자동 승인 도구 호출 → (3) IDE 기능으로 보안 경계 돌파
- **SPEAR 적용:** 자동 승인 도구 호출 + 인젝션 컨텍스트 결합 테스트. IDE 기능 체이닝으로 데이터 탈취/RCE 검증.

---

#### Paper 09: MCP 보안 분석 (2025)

- **제목:** "Securing the Model Context Protocol (MCP): Risks, Controls, and Governance"
- **저자:** Herman Errico 외
- **arXiv:** [2511.20920](https://arxiv.org/abs/2511.20920)
- **핵심 기법:** 3가지 적대자 유형: (1) 콘텐츠 인젝션, (2) 공급망 공격(악성 MCP 서버 배포), (3) 에이전트의 의도치 않은 권한 초과. 추가 통계: MCP 서버의 88%가 인증 필요하지만 53%가 안전하지 않은 정적 시크릿 의존, **OAuth 사용은 8.5%에 불과**.
- **관련 CVE:** CVE-2025-6514 (mcp-remote RCE, 437,000+ 다운로드 영향)
- **추가 논문:** arXiv:2503.23278, arXiv:2512.08290, arXiv:2602.01129

---

### Category 2: 공급망 공격 (6편)

---

#### Paper 10: Slopsquatting - 패키지 할루시네이션 (USENIX 2025)

- **제목:** "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs"
- **저자:** Joseph Spracklen 외 (UT San Antonio, U of Oklahoma, Virginia Tech)
- **학회:** [USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen)
- **arXiv:** [2406.10279](https://arxiv.org/abs/2406.10279)
- **핵심 기법:** 16개 코드 생성 모델, 2.23M 패키지 참조 테스트. **440,445개(19.7%)가 할루시네이션** (205,474개 고유 이름). 재프롬프트 시 43%가 반복, 58%가 2회 이상 등장 → 공격자의 선점 등록 타겟.
- **SPEAR 적용:** AI 코드 생성 → 할루시네이션 패키지 식별 → npm/pypi 선점 여부 확인 → Slopsquatting 리스크 보고

---

#### Paper 11: Dependency Confusion (Birsan 2021, 지속적 영향)

- **제목:** "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies"
- **저자:** Alex Birsan
- **핵심 기법:** public registry에 private 패키지와 동일 이름의 악성 패키지 업로드. 패키지 매니저가 higher version의 public 패키지를 우선. DNS 탈취로 코드 실행 확인.
- **영향:** Apple, Microsoft, PayPal, Shopify, Tesla 등 **35개 조직 침해**. $130,000+ 버그바운티.
- **SPEAR 적용:** 내부 패키지명 노출 스캔 (JS 소스맵, package-lock.json) → private registry 우선순위 설정 검증

---

#### Paper 12: TypoSmart (2025)

- **arXiv:** [2502.20528](https://arxiv.org/html/2502.20528v1)
- **핵심 기법:** 임베딩 기반 이름 분석 + 메타데이터 검증. 실 배포 1개월: 3,658개 의심 패키지 중 **3,075개(86.1%)에서 실제 멀웨어 확인**.
- **SPEAR 적용:** 임베딩 유사도 기반 타이포스쿼팅 탐지 통합

---

#### Paper 13: Cerebro - 멀웨어 행동 시퀀스 분석

- **학회:** ACM TOSEM (2025 업데이트)
- **arXiv:** [2309.02637](https://arxiv.org/abs/2309.02637)
- **핵심 기법:** 악성 행동을 시퀀스로 추상화 (예: "네트워크 접근 → 파일 읽기 → 데이터 인코딩 → HTTP POST"). npm/PyPI 교차 언어 패턴 학습.
- **SPEAR 적용:** 패키지 행동 시퀀스 모델링 → 알려진 악성 패턴 매칭

---

#### Paper 14: 오픈소스 공급망 침해 회고 조사 (Valsorda 2025)

- **출처:** [words.filippo.io](https://words.filippo.io/compromise-survey/)
- **핵심 기법:** 18개 실제 공급망 사건 조사. 3대 근본 원인: (1) 피싱 (TOTP 2FA도 뚫림), (2) 메인테이너 핸드오프, (3) 안전하지 않은 GitHub Actions 트리거.
- **SPEAR 적용:** 메인테이너 인증 방법 감사, GitHub Actions 트리거 설정 검증

---

#### Paper 15: OWASP Top 10:2025 - A03 Software Supply Chain Failures

- **출처:** [OWASP](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- **핵심:** **신규 카테고리**. 커뮤니티 설문 50%가 1위로 선정. 타이포스쿼팅, 메인테이너 계정 탈취, 포이즌 업데이트, 빌드 시스템 침해, Dependency Confusion 포괄.

---

### Category 3: 시크릿/키 탈취 (4편)

---

#### Paper 16: Whisper Leak - LLM 사이드채널 (Microsoft 2025)

- **출처:** [Microsoft Security Blog, 2025.11](https://www.microsoft.com/en-us/security/blog/2025/11/07/whisper-leak-a-novel-side-channel-cyberattack-on-remote-language-models/)
- **핵심 기법:** TLS 암호화된 LLM 스트리밍 응답에서 **패킷 크기 변화로 토큰 길이 추론** → 프롬프트 주제 식별, 응답 재구성 가능. ISP, 네트워크 감시자가 악용 가능.
- **SPEAR 적용:** 암호화된 LLM 트래픽 패킷 크기 패턴 모니터링 → 토큰 길이 핑거프린팅으로 민감 프롬프트 식별 테스트

---

#### Paper 17: Cookie-Bite (Varonis 2025)

- **출처:** [Varonis](https://www.varonis.com/blog/cookie-bite)
- **핵심 기법:** Azure Entra ID의 ESTSAUTH 쿠키를 Chrome 확장으로 탈취 → MFA 완전 우회. VirusTotal에서 **탐지율 0%**.
- **통계:** 실제 활동 중인 도난 쿠키 **940억 개**. Lumma Stealer만 394,000+ Windows 감염 (2025.03-05).
- **SPEAR 적용:** 세션 쿠키 캡처/리플레이 테스트, 토큰 바인딩/조건부 접근 정책 검증

---

#### Paper 18: AI 훈련 데이터 내 라이브 API 키 (Truffle Security)

- **출처:** [Truffle Security](https://trufflesecurity.com/blog/research-finds-12-000-live-api-keys-and-passwords-in-deepseek-s-training-data)
- **핵심 기법:** 400TB 웹 크롤 데이터에서 **11,908개 실제 작동하는 시크릿** 발견. Mailchimp API 키만 1,500개가 프론트엔드 HTML/JS에 하드코딩. LLM이 유효한 크레덴셜을 재생산 가능.
- **SPEAR 적용:** LLM 출력에서 크레덴셜 패턴 스캔, "예제 API 키" 프롬프트로 라이브 크레덴셜 재생산 테스트

---

#### Paper 19: TLS 키 메모리 추출 (DFRWS 2024)

- **출처:** [DFRWS 2024](https://dfrws.org/wp-content/uploads/2024/07/TLS-key-material-identification-and-extractio_2024_Forensic-Science-Internat.pdf)
- **핵심 기법:** OpenSSL, BoringSSL, Schannel의 마스터 시크릿이 예측 가능한 메모리 오프셋에 위치. 프로세스 메모리 덤프로 TLS 키 추출 → 캡처된 암호화 트래픽 사후 복호화 가능.
- **SPEAR 적용:** 프로세스 메모리 덤프에서 TLS 키 탐색, 세션 완료 후 키 제거(zeroization) 검증

---

### Category 4: 개발 환경 공격 (4편)

---

#### Paper 20: UntrustIDE (NDSS 2024 Distinguished Paper)

- **제목:** "UntrustIDE: Exploiting Weaknesses in VS Code Extensions"
- **저자:** Elizabeth Lin 외
- **학회:** [NDSS 2024](https://www.ndss-symposium.org/ndss-paper/untrustide-exploiting-weaknesses-in-vs-code-extensions/) - **Distinguished Paper Award**
- **핵심 기법:** 25,402개 VS Code 확장 CodeQL 분석. 716개 위험 데이터 플로우, 21개 검증된 취약점 + PoC. 공격 벡터: `.vscode/` 비신뢰 워크스페이스 설정, 로컬 웹 서버 확장, 파일 콘텐츠 미검증 처리.
- **SPEAR 적용:** 악성 `.vscode/settings.json` 포함 레포 클론 → 확장의 비신뢰 설정 처리 테스트
- **오픈소스:** [GitHub: s3c2/UntrustIDE](https://github.com/s3c2/UntrustIDE)

---

#### Paper 21: Git RCE via Submodule Hooks

- **CVE:** CVE-2024-32002, CVE-2025-48384 (CVSS 8.1)
- **핵심 기법:** 악성 `.gitmodules`로 `git clone --recursive` 시 hook 스크립트 실행. CVE-2025-48384는 서브모듈 경로의 trailing CR로 임의 파일 쓰기 → 악성 Git hook이 `git commit`, `git merge` 시 실행.
- **영향:** CISA KEV 카탈로그 등재. 실전 악용 확인. GitHub Desktop for macOS 기본 취약.
- **SPEAR 적용:** 악성 `.gitmodules` 테스트 레포 생성 → recursive clone 파일 쓰기 테스트 → CI/CD 시스템 검증

---

#### Paper 22: GitHub Actions 공급망 공격 (tj-actions, Unit 42)

- **출처:** [Unit 42](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- **CVE:** CVE-2025-30066
- **핵심 기법:** `tj-actions/changed-files` (23,000+ 레포 사용) 침해. CI/CD 러너 메모리 덤프로 환경변수/시크릿 워크플로우 로그에 노출. 초기 Coinbase 타겟 → 광범위 확산.
- **SPEAR 적용:** 서드파티 GitHub Actions 버전 핀닝 감사, 워크플로우 로그 시크릿 노출 스캔, `pull_request_target` 설정 검증

---

#### Paper 23: AI IDE 확장 네임스페이스 하이재킹 (2025)

- **출처:** SC Media, Bleeping Computer (2025.12)
- **핵심 기법:** Cursor, Windsurf, Google Antigravity 등 AI IDE가 OpenVSX에 존재하지 않는 확장을 추천 → 공격자가 네임스페이스 선점 후 악성 확장 업로드. "prettier-vscode-plus" 공격으로 Anivia 로더 + OctoRAT 배포.
- **SPEAR 적용:** AI IDE의 존재하지 않는 확장 추천 테스트, 확장 서명/검증 확인, 네임스페이스 스쿼팅 탐지

---

### Category 5: 신흥 공격 벡터 2025-2026 (7편)

---

#### Paper 24: Morris II AI 웜 (Cornell Tech 2024)

- **제목:** "Here Comes The AI Worm: Unleashing Zero-click Worms that Target GenAI-Powered Applications"
- **저자:** Ben Nassi, Stav Cohen, Ron Bitton (Cornell Tech, Technion, Intuit)
- **arXiv:** [2403.02817](https://arxiv.org/abs/2403.02817)
- **핵심 기법:** 최초 자기 복제 AI 웜. "Adversarial self-replicating prompts"로 LLM 출력에 자신을 복제. Gemini Pro, GPT-4, LLaVA에서 동작. 텍스트/이미지 모두 가능. **제로클릭 전파** - 사용자 상호작용 불필요.
- **데모:** (1) AI 이메일 어시스턴트 통한 스팸 전파, (2) 개인 데이터(이름, 전화번호, 카드, SSN) 탈취
- **SPEAR 적용:** 자기 복제 프롬프트 생성 → AI 에이전트 간 전파 테스트 → 전파율/데이터 탈취 성공률 측정

---

#### Paper 25: Sleeper Agents (Anthropic 2024)

- **제목:** "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training"
- **저자:** Evan Hubinger + 38명 (Anthropic)
- **arXiv:** [2401.05566](https://arxiv.org/abs/2401.05566)
- **핵심 기법:** 조건부 백도어 LLM 훈련 (2023년 = 안전한 코드, 2024년 = 취약한 코드 삽입). **핵심 발견:**
  - 백도어 행동이 SFT, RLHF, 적대적 훈련을 **살아남음**
  - **큰 모델이 백도어 제거에 더 저항적**
  - CoT 추론이 백도어를 **더 견고하게** 만듦
  - 적대적 훈련이 오히려 트리거를 **더 잘 숨기게** 학습시킴
- **SPEAR 적용:** 컨텍스트 단서(날짜, 사용자 ID, 배포 환경)에 따른 조건부 행동 변화 테스트

---

#### Paper 26: 상수 샘플 포이즈닝 (Anthropic 2025)

- **제목:** "Poisoning Attacks on LLMs Require a Near-constant Number of Poison Samples"
- **arXiv:** [2510.07192](https://arxiv.org/abs/2510.07192)
- **핵심 기법:** 최대 규모 사전훈련 포이즈닝 실험 (600M~13B 파라미터, 6B~260B 토큰). **충격적 발견: 250개 문서만으로 모델 크기와 무관하게 포이즈닝 성공**. 가장 큰 모델이 20배 더 많은 클린 데이터로 훈련됐지만 동일하게 취약.
- **SPEAR 적용:** 파인튜닝 시나리오에서 최소 포이즈닝 샘플 수 테스트, 훈련 데이터 파이프라인 이상 탐지 검증

---

#### Paper 27: 보안 자동화 LLM 포이즈닝 (2025)

- **arXiv:** [2511.02600](https://arxiv.org/abs/2511.02600)
- **핵심 기법:** 포이즌된 LLM이 알림 분석/위협 탐지에 배포될 때 특정 사용자/소스의 진양성 알림을 일관되게 무시하도록 편향. Llama3.1 8B, Qwen3 4B로 실증.
- **SPEAR 적용:** 보안 자동화 LLM에 적대적 입력 → 알림 분류 일관성 테스트 → 체계적 사각지대 감지

---

#### Paper 28: AI 에이전트 웹 검색 도구 통한 데이터 탈취

- **arXiv:** [2510.09093](https://arxiv.org/abs/2510.09093)
- **핵심 기법:** AI 에이전트의 웹 검색 도구를 indirect prompt injection으로 하이재킹 → 민감 데이터를 검색 쿼리에 인코딩 → 공격자 서버로 전송. 여러 LLM 모델/제조사에서 동작.
- **SPEAR 적용:** AI 에이전트의 모든 아웃바운드 요청 모니터링, 인젝션으로 민감 컨텍스트를 도구 인자에 인코딩 가능한지 테스트

---

#### Paper 29: HERCULE - Python 공급망 멀웨어 탐지 (ICSE 2025)

- **출처:** [ICSE 2025 SEIP](https://rshariffdeen.com/paper/ICSE25-SEIP.pdf)
- **핵심 기법:** PyPI의 타이포스쿼팅, 콤보스쿼팅, Dependency Confusion 탐지. setup.py와 install hook의 정적 분석으로 의심 행동(네트워크 호출, 파일시스템 접근, 코드 난독화) 식별.
- **SPEAR 적용:** CI/CD에 setup.py/install hook 정적 분석 통합, 설치 시 네트워크/파일시스템 작업 수행 패키지 플래그

---

#### Paper 30: 최초 AI 주도 사이버 스파이 활동 (Anthropic 공개)

- **출처:** [Anthropic 2025.09](https://www.anthropic.com/news/disrupting-AI-espionage)
- **핵심 기법:** 최초로 문서화된 AI 에이전트 능력을 활용한 완전한 공격 라이프사이클: 취약점 식별 → 익스플로잇 코드 작성 → 크레덴셜 수확 → 데이터 탈취. **최소한의 인간 감독**으로 수행.
- **SPEAR 적용:** AI 에이전트 도구 사용 패턴 모니터링 → 정찰/익스플로잇 패턴 감지 → 사용 정책의 적대적 의도 감지 테스트

---

## 4. 공격 모듈 설계 (20개)

### 4.1 모듈 개요

```
┌─────────────────────────────────────────────────────────────┐
│                    WIGTN-SPEAR Architecture                  │
│                "Attack Before They Attack"                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              SPEAR CORE ENGINE                        │   │
│  │                                                       │   │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │ Recon   │ │ Extract │ │ Exploit  │ │ Report   │  │   │
│  │  │ Module  │ │ Module  │ │ Module   │ │ Module   │  │   │
│  │  └────┬────┘ └────┬────┘ └────┬─────┘ └────┬─────┘  │   │
│  │       │           │           │             │         │   │
│  └───────┼───────────┼───────────┼─────────────┼────────┘   │
│          ▼           ▼           ▼             ▼             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              ATTACK MODULES (20 Spears)              │    │
│  │                                                      │    │
│  │  [Secret Detection]                                  │    │
│  │   #01 Secret Scanner                                 │    │
│  │   #02 Git History Miner                              │    │
│  │                                                      │    │
│  │  [AI/Agent Attacks]                                  │    │
│  │   #04 MCP Poisoning Tester                           │    │
│  │   #06 Prompt Injection Fuzzer                        │    │
│  │   #10 AI Agent Manipulation Tester                   │    │
│  │   #17 LLM Output Exploitation Tester                 │    │
│  │                                                      │    │
│  │  [Supply Chain]                                      │    │
│  │   #05 Dependency Confusion Checker                   │    │
│  │   #08 Supply Chain Analyzer                          │    │
│  │   #19 Social Engineering Code Analyzer               │    │
│  │                                                      │    │
│  │  [Runtime/Environment]                               │    │
│  │   #03 Env Exfiltration Simulator                     │    │
│  │   #07 Clipboard/Memory Inspector                     │    │
│  │   #09 Browser Extension Auditor                      │    │
│  │   #15 IDE Extension Auditor                          │    │
│  │                                                      │    │
│  │  [Infrastructure]                                    │    │
│  │   #11 CI/CD Pipeline Exploit Tester                  │    │
│  │   #12 Container Security Auditor                     │    │
│  │   #13 Cloud Credential Chain Analyzer                │    │
│  │   #14 Network Recon & SSRF Tester                    │    │
│  │   #16 Webhook & API Endpoint Scanner                 │    │
│  │   #18 Certificate & TLS Recon                        │    │
│  │   #20 Hardware Token & Auth Bypass                   │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              REPORTING & EVIDENCE                    │    │
│  │  - Attack Chain Visualization                        │    │
│  │  - Risk Score (CVSS-based)                           │    │
│  │  - SARIF 2.1.0 Output (CI/CD 통합)                  │    │
│  │  - Remediation Playbook                              │    │
│  │  - Shield Integration Test Report                    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 모듈 상세

#### Spear-01: Secret Scanner (시크릿 스캐너)

**카테고리:** Secret Detection | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | 프로젝트 디렉토리 전체 스캔 → `.env`, `config.yaml`, `.claude/settings.json`, `mcp.json` 등에서 시크릿 패턴 탐지 |
| **차별점** | 800+ 패턴 매칭 + **라이브 검증** (찾은 키로 실제 API 호출 → 활성 여부 확인) |
| **기술** | Aho-Corasick 키워드 프리필터 → Regex 매칭 → Shannon Entropy 분석 → API 검증 |
| **논문 근거** | Paper 18 (12,000개 라이브 키 in 훈련 데이터) |
| **참조 도구** | TruffleHog, GitLeaks |

---

#### Spear-02: Git History Miner (깃 히스토리 채굴)

**카테고리:** Secret Detection | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | `.git` 전체 히스토리 순회 → force-push 삭제 커밋까지 복원 → 한 번이라도 커밋된 시크릿 전부 추출 |
| **차별점** | "oops commit" 패턴 감지, dangling commit 분석, reflog 탐색 |
| **기술** | `git reflog`, `git fsck --unreachable`, simple-git 스트리밍 |
| **논문 근거** | Paper 14 (Valsorda 공급망 침해 조사) |

---

#### Spear-03: Env Exfiltration Simulator (환경변수 탈취 시뮬레이터)

**카테고리:** Runtime/Environment | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | `/proc/[pid]/environ` 읽기, 메모리 덤프 시크릿 추출 시뮬레이션 |
| **차별점** | 실제 공격자 경로 재현 → 런타임 시크릿 노출 확인 |
| **기술** | 프로세스 메모리 분석, 환경변수 열거 |
| **논문 근거** | Paper 19 (TLS 키 메모리 추출), Paper 22 (tj-actions 메모리 덤프) |

---

#### Spear-04: MCP Poisoning Tester (MCP 포이즈닝 테스터)

**카테고리:** AI/Agent Attacks | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | 악성 MCP 서버 시뮬레이션 → tool description에 프롬프트 인젝션 삽입 → AI 에이전트 비인가 동작 테스트 |
| **차별점** | CurXecute(CVE-2025-54135) 재현 + Rug Pull 패턴 + Cross-Tool 오염 시뮬레이션 |
| **기술** | Mock MCP 서버, 동적 tool description 변경, 행동 모니터링 |
| **논문 근거** | Paper 09 (MCP 보안 분석), Paper 06 (SoK) |
| **CVE 참조** | CVE-2025-54135, CVE-2025-54136, CVE-2025-6514 |

---

#### Spear-05: Dependency Confusion Checker (의존성 혼란 체커)

**카테고리:** Supply Chain | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | `package.json`/`requirements.txt` 전체 의존성 검사 → private vs public registry 혼란 분석 + AI 할루시네이션 패키지 예측 |
| **차별점** | Slopsquatting 시뮬레이션 - AI에게 동일 기능 질의 → 추천 패키지 수집 → npm/pypi 악성 등록 확인 |
| **기술** | Registry API 조회, AI 패키지 할루시네이션 테스트 |
| **논문 근거** | Paper 10 (Slopsquatting), Paper 11 (Dependency Confusion) |

---

#### Spear-06: Prompt Injection Fuzzer (프롬프트 인젝션 퍼저)

**카테고리:** AI/Agent Attacks | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | 다양한 프롬프트 인젝션 페이로드를 AI 에이전트에 입력 → 방어 우회 성공률 측정 |
| **차별점** | HouYi 3단계 + AIShellJack 314개 페이로드 + Promptware Kill Chain 7단계 |
| **기술** | 페이로드 라이브러리, 자동 테스트 실행, MITRE ATT&CK 매핑 |
| **논문 근거** | Paper 02 (HouYi), Paper 03 (Promptware Kill Chain), Paper 07 (AIShellJack) |

---

#### Spear-07: Clipboard/Memory Inspector (클립보드/메모리 검사기)

**카테고리:** Runtime/Environment | **우선순위:** P2

| 항목 | 내용 |
|------|------|
| **공격** | 클립보드 히스토리 시크릿 패턴 탐지 + 프로세스 메모리 스캔 |
| **차별점** | OWASP 2025 개발자 워크스테이션 공격면 반영 |
| **기술** | clipboardy, 메모리 패턴 스캔, napi-rs (선택) |
| **논문 근거** | Paper 17 (Cookie-Bite), Paper 19 (TLS 키 메모리 추출) |

---

#### Spear-08: Supply Chain Analyzer (공급망 분석기)

**카테고리:** Supply Chain | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | npm/pypi install script 분석, 의존성 트리 순회, SANDWORM_MODE 등 알려진 패턴 매칭 |
| **차별점** | `postinstall` 스크립트 동적 분석 (샌드박스), 행동 시퀀스 분석 |
| **기술** | AST 파싱, isolated-vm 샌드박스, CVE 매핑 |
| **논문 근거** | Paper 13 (Cerebro), Paper 15 (OWASP A03), Paper 29 (HERCULE) |

---

#### Spear-09: Browser Extension Auditor (브라우저 확장 감사기)

**카테고리:** Runtime/Environment | **우선순위:** P2

| 항목 | 내용 |
|------|------|
| **공격** | 설치된 확장 권한 분석 → 위험 권한 식별 → 알려진 악성 확장 DB 매칭 |
| **차별점** | H-Chat Assistant 패턴(API 키 탈취), Cookie-Bite 패턴 자동 탐지 |
| **기술** | CRX 파싱, manifest 분석, AST 코드 분석 |
| **논문 근거** | Paper 17 (Cookie-Bite) |

---

#### Spear-10: AI Agent Manipulation Tester (AI 에이전트 조작 테스터)

**카테고리:** AI/Agent Attacks | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | `.cursorrules`, `.claude/settings.json`, `mcp.json` 조작 시나리오 시뮬레이션 |
| **차별점** | CVE-2025-59536 (hooks RCE), CVE-2026-21852 (API 키 리다이렉션) 재현 |
| **기술** | 설정 파일 인젝션, 동작 모니터링, 격리 실행 |
| **논문 근거** | Paper 08 (IDEsaster), Paper 06 (SoK) |
| **CVE 참조** | CVE-2025-59536, CVE-2026-21852, CVE-2025-54135 |

---

#### Spear-11: CI/CD Pipeline Exploit Tester (CI/CD 파이프라인 익스플로잇)

**카테고리:** Infrastructure | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | GitHub Actions 워크플로우 인젝션 분석, 시크릿 로그 노출 탐지, OIDC 설정 오류 스캔, Action 공급망 검증 |
| **차별점** | `pull_request_target` 남용 탐지, SHA 핀닝 감사, GhostAction 패턴 탐지 |
| **기술** | YAML 파싱 (js-yaml), GitHub API (@octokit/rest), AWS SDK |
| **논문 근거** | Paper 22 (tj-actions), Paper 14 (Valsorda 조사) |
| **CVE 참조** | CVE-2025-30066, CVE-2025-30154, CVE-2025-53104 |

---

#### Spear-12: Container Security Auditor (컨테이너 보안 감사기)

**카테고리:** Infrastructure | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | Docker 이미지 레이어 시크릿 추출, Dockerfile 안티패턴 탐지, 컨테이너 이스케이프 벡터 평가 |
| **차별점** | 삭제된 시크릿도 이전 레이어에서 추출, runc 브레이크아웃 조건 검사 |
| **기술** | dockerode, tar 아카이브 파싱, Dockerfile AST 분석 |
| **CVE 참조** | CVE-2025-31133, CVE-2025-52565, CVE-2025-9074 (CVSS 9.3) |
| **통계** | DockerHub에서 100,000+ 유효 시크릿 발견 (GitGuardian) |

---

#### Spear-13: Cloud Credential Chain Analyzer (클라우드 크레덴셜 체인)

**카테고리:** Infrastructure | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | IMDS 익스플로잇 경로, 크레덴셜 파일 스캔 (~/.aws, ~/.gcp, ~/.azure), IAM 역할 체인 매핑, 교차 클라우드 피벗 |
| **차별점** | AWS/GCP/Azure 동시 타겟, Secrets Manager 접근 열거, IMDSv1 vs v2 검증 |
| **기술** | AWS SDK v3, Google Cloud Client, Azure SDK (모두 TypeScript 네이티브) |
| **CVE 참조** | CVE-2025-51591 (pandoc SSRF→IMDS) |

---

#### Spear-14: Network Recon & SSRF Tester (네트워크 정찰 & SSRF)

**카테고리:** Infrastructure | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | 로컬호스트 서비스 디스커버리, DNS 리바인딩 시뮬레이션, SSRF 체인 구성, 내부 서비스 핑거프린팅 |
| **차별점** | 개발자 머신 로컬 공격면 매핑, IP 인코딩 트릭, URL 파서 차이점 테스트 |
| **기술** | net.Socket, DNS API, HTTP 프록시 |
| **CVE 참조** | GHSA-wvjg-9879-3m7w (AutoGPT), GHSA-4jcv-vp96-94xr (MindsDB) |

---

#### Spear-15: IDE Extension Auditor (IDE 확장 감사기)

**카테고리:** Runtime/Environment | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | VS Code/Cursor 확장 권한 분석, 악성 확장 패턴 탐지, Workspace Trust 설정 감사, 할루시네이션 확장 탐지 |
| **차별점** | MaliciousCorgi 패턴(1.5M 개발자 코드 탈취), Cursor Open-Folder 취약점 검사 |
| **기술** | Extension manifest 파싱, AST 분석 (@babel/parser), 패턴 매칭 |
| **CVE 참조** | CVE-2025-65717, CVE-2025-65716, CVE-2025-65715, CVE-2025-59944 |

---

#### Spear-16: Webhook & API Endpoint Scanner (웹훅 & API 스캐너)

**카테고리:** Infrastructure | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | 웹훅 URL 발견, Slack 웹훅 남용 테스트, API 키 검증 & 스코프 테스트, 노출된 엔드포인트 디스커버리 |
| **차별점** | KeyHacks 방법론 (170+ 서비스), 5분 내 탈취 확인 |
| **기술** | HTTP 요청, regex 패턴 매칭, API 호출 |
| **통계** | GitHub에 13M API 시크릿 노출 (2024), 130,000+ Slack 웹훅 노출 |

---

#### Spear-17: LLM Output Exploitation Tester (LLM 출력 익스플로잇)

**카테고리:** AI/Agent Attacks | **우선순위:** P0

| 항목 | 내용 |
|------|------|
| **공격** | Slopsquatting 탐지, AI 백도어 패턴 탐지, 스테가노그래픽 페이로드 분석, 코드 완성 포이즈닝 탐지 |
| **차별점** | AI 생성 코드의 45% 취약점 자동 탐지, 존재하지 않는 패키지 참조 검증 |
| **기술** | Registry API, AST 분석, 엔트로피 분석 |
| **논문 근거** | Paper 10 (Slopsquatting), Paper 25 (Sleeper Agents), Paper 26 (상수 샘플 포이즈닝) |

---

#### Spear-18: Certificate & TLS Recon (인증서 & TLS 정찰)

**카테고리:** Infrastructure | **우선순위:** P2

| 항목 | 내용 |
|------|------|
| **공격** | CT 로그 서브도메인 열거, 자체 서명 인증서 탐지, TLS 설정 오류 감사, 와일드카드 인증서 리스크 |
| **차별점** | crt.sh API 기반 인프라 정찰, `NODE_TLS_REJECT_UNAUTHORIZED=0` 패턴 탐지 |
| **기술** | crt.sh API, tls.connect(), HTTPS 설정 테스트 |

---

#### Spear-19: Social Engineering Code Analyzer (소셜 엔지니어링 코드 분석)

**카테고리:** Supply Chain | **우선순위:** P1

| 항목 | 내용 |
|------|------|
| **공격** | 트로이 PR 탐지, 락 파일 조작 탐지, post-install 스크립트 분석, 난독화 코드 탐지, 기여자 신뢰 점수 |
| **차별점** | GhostAction 패턴 매칭, renovate[bot] 위장 탐지 |
| **기술** | Git diff 파싱 (simple-git), AST 분석, GitHub API, 엔트로피 분석 |

---

#### Spear-20: Hardware Token & Auth Bypass (하드웨어 토큰 & 인증 우회)

**카테고리:** Infrastructure | **우선순위:** P2

| 항목 | 내용 |
|------|------|
| **공격** | FIDO2 다운그레이드 탐지, 세션 토큰 사후 인증 감사, EUCLEAK 취약점 확인, QR 코드 릴레이 시뮬레이션 |
| **차별점** | Proofpoint FIDO 다운그레이드 재현, YubiKey 펌웨어 버전 확인 |
| **기술** | @simplewebauthn/server, HTTP 프록시, USB HID (선택) |
| **CVE 참조** | EUCLEAK (YSA-2024-03) |

---

### 4.3 우선순위 매트릭스

| 우선순위 | 모듈 (7개 P0) | 근거 |
|---------|--------------|------|
| **P0** | #01 Secret Scanner | 즉시 데모 가능, 가장 직관적 |
| **P0** | #02 Git History Miner | "삭제해도 안 사라진다" 충격 효과 |
| **P0** | #04 MCP Poisoning Tester | 2026년 핫이슈, 시장에 없는 기능 |
| **P0** | #06 Prompt Injection Fuzzer | 85% 성공률 통계 임팩트 |
| **P0** | #10 AI Agent Manipulation | CVE 재현으로 즉시 신뢰도 확보 |
| **P0** | #11 CI/CD Pipeline Exploit | 23,000+ 레포 영향 사례 |
| **P0** | #13 Cloud Credential Chain | 클라우드 침해 #1 벡터 |
| **P0** | #17 LLM Output Exploitation | AI 생성 코드 20% 가짜 패키지 |
| **P1** | #03, #05, #08, #12, #14, #15, #16, #19 | 제품 완성도 |
| **P2** | #07, #09, #18, #20 | 엔터프라이즈 확장 |

---

## 5. 기존 도구 대비 차별화

### 5.1 비교 매트릭스

| 기능 | TruffleHog | Semgrep | GitLeaks | Snyk | Nuclei | **SPEAR** |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| 시크릿 패턴 매칭 | 800+ | - | 150+ | - | - | **800+** |
| 라이브 키 검증 | O | - | - | - | - | **O** |
| Git 히스토리 전체 스캔 | O | - | O | - | - | **O** |
| Dangling commit 복원 | - | - | - | - | - | **O** |
| 코드 정적 분석 | - | O | - | O | - | **부분** |
| 의존성 취약점 | - | O | - | O | - | **O** |
| AI 에이전트 공격 테스트 | - | - | - | - | - | **O** |
| MCP 포이즈닝 | - | - | - | - | - | **O** |
| 프롬프트 인젝션 퍼징 | - | - | - | - | - | **O** |
| Slopsquatting 탐지 | - | - | - | - | - | **O** |
| CI/CD 파이프라인 공격 | - | - | - | - | 부분 | **O** |
| 컨테이너 레이어 분석 | - | - | - | O | - | **O** |
| 클라우드 크레덴셜 체인 | - | - | - | - | - | **O** |
| IDE 확장 감사 | - | - | - | - | - | **O** |
| SARIF CI/CD 통합 | - | O | O | O | - | **O** |
| 웹 대시보드 | - | O (유료) | - | O (유료) | - | **O** |

### 5.2 핵심 차별화 요약

1. **능동적 공격 시뮬레이션** vs 수동적 취약점 스캔
2. **AI/MCP 공격면 전문** - 시장에 경쟁자 없음
3. **Promptware Kill Chain 기반 테스트** - 학술 연구 → 실용 도구
4. **SHIELD 연동** - 공격-방어 사이클 완성
5. **바이브 코딩 시대 특화** - 2026년 핫이슈 정면 대응

---

## 6. 기술 스택 타당성 분석

### 6.1 Node.js/TypeScript 구현 가능성

| 기능 | 가능 여부 | 라이브러리 | 비고 |
|------|:---------:|-----------|------|
| 시크릿 패턴 매칭 | **YES** | JS RegExp, re2 | JS 정규식이 Go보다 강력 (lookahead 지원) |
| Shannon 엔트로피 | **YES** | 15줄 구현 | `shannonEntropy()` |
| Aho-Corasick 프리필터 | **YES** | aho-corasick npm | TruffleHog과 동일 방식 |
| Git 히스토리 스캔 | **YES** | simple-git | 시스템 git 래핑, 안정적 |
| 대규모 파일 스캔 | **YES** | fast-glob, @nodelib/fs.walk | 수백만 파일 처리 가능 |
| 네트워크 포트 스캔 | **YES** | net.Socket, portscanner | 기본 스캔은 순수 JS |
| 클립보드 모니터링 | **YES** | clipboardy | OS 유틸리티 래핑 |
| 프로세스 메모리 | **부분** | napi-rs + Rust 애드온 | 외부 프로세스는 네이티브 필요 |
| 브라우저 확장 분석 | **YES** | CRX 파싱 + AST | JSZip + @babel/parser |
| AST 다중 언어 분석 | **YES** | tree-sitter | 35+ 언어, Semgrep과 동일 C 라이브러리 |
| Docker 이미지 분석 | **YES** | dockerode | Node.js Docker SDK |
| 클라우드 SDK | **YES** | AWS v3, GCP, Azure | 모두 TypeScript 네이티브 |
| YAML 파싱 | **YES** | js-yaml | 워크플로우 분석 |
| SARIF 출력 | **YES** | sarif-builder | CI/CD 표준 통합 |
| 샌드박스 실행 | **YES** | isolated-vm | V8 Isolate 기반 (vm2는 회피) |
| 워커 스레드 | **YES** | worker_threads | Go goroutine 대체 |

### 6.2 참조 도구 내부 구조 포팅 가능성

**TruffleHog (Go) → TypeScript:**

| Go 컴포넌트 | TS 대체 |
|-------------|---------|
| Aho-Corasick 키워드 프리필터 | `aho-corasick` npm |
| 800+ regex 디텍터 | JS `RegExp` / `re2` |
| API 검증 호출 | `fetch` / `undici` |
| Git 소스 스캔 | `simple-git` |
| 청킹 파이프라인 | Node.js Streams/Transform |
| 워커 풀 (goroutines) | `worker_threads` |
| 채널 기반 파이프라인 | `AsyncGenerator` + bounded queue |

**Semgrep (OCaml) → TypeScript:**

| OCaml 컴포넌트 | TS 대체 |
|---------------|---------|
| Tree-sitter 파서 | `tree-sitter` npm (동일 C 라이브러리) |
| Generic AST | TypeScript 유니파이드 AST 타입 |
| 메타변수 패턴 매칭 | 커스텀 visitor 패턴 |
| Taint 추적 | 커스텀 데이터플로우 분석 |
| 병렬 실행 | `worker_threads` 풀 |

**GitLeaks (Go) → TypeScript:**

| Go 컴포넌트 | TS 대체 |
|-------------|---------|
| TOML 설정 룰 | `toml` npm으로 동일 TOML 파싱 |
| Go regexp (lookahead 미지원) | JS RegExp **(lookahead 지원 = 장점!)** |
| Shannon 엔트로피 | 직접 구현 (15줄) |
| 허용목록 시스템 | 오브젝트 매칭 |

### 6.3 추천 기술 스택

```
wigtn-spear/
├── turbo.json                    # Turborepo 모노레포
├── package.json
├── packages/
│   ├── core/                     # 스캔 엔진
│   │   ├── src/
│   │   │   ├── detectors/        # 시크릿 패턴 매처
│   │   │   ├── entropy/          # Shannon 엔트로피
│   │   │   ├── scanners/         # Git, FS, Network, etc.
│   │   │   ├── reporters/        # SARIF, JSON, HTML, CSV
│   │   │   └── types/            # 공유 TypeScript 타입
│   │   └── package.json
│   ├── rules/                    # 탐지 룰 정의 (YAML)
│   │   ├── secrets/              # 시크릿 패턴 룰
│   │   ├── vulnerabilities/      # 취약점 룰
│   │   └── misconfigurations/    # 설정 오류 룰
│   ├── plugins/                  # 플러그인 SDK + 20개 모듈
│   │   ├── sdk/                  # 플러그인 인터페이스
│   │   ├── secret-scanner/
│   │   ├── git-miner/
│   │   ├── mcp-poisoner/
│   │   ├── prompt-fuzzer/
│   │   └── ... (20개)
│   └── db/                       # Drizzle + SQLite
├── apps/
│   ├── cli/                      # oclif 기반 CLI
│   │   ├── src/commands/
│   │   └── package.json
│   └── dashboard/                # Vite + React 19
│       ├── src/
│       └── package.json
└── configs/
    ├── eslint/
    ├── tsconfig/
    └── vitest/
```

| 영역 | 선택 | 이유 |
|------|------|------|
| **모노레포** | Turborepo | 간결, 빠름, 캐시 우수 |
| **CLI** | oclif | 플러그인 시스템 내장, Heroku/Salesforce 사용 |
| **대시보드** | Vite + React 19 | SPA, SSR 불필요, 빠른 HMR |
| **DB** | SQLite (better-sqlite3) | CLI 도구 최적, 제로 설치 |
| **UI 컴포넌트** | shadcn/ui | Tailwind 기반, 복붙 방식 |
| **AST 파싱** | tree-sitter | 35+ 언어, Semgrep과 동일 엔진 |
| **Git** | simple-git | 안정적, 시스템 git 래핑 |
| **리포트** | SARIF 2.1.0 | GitHub/GitLab CI 통합 표준 |
| **차트** | Recharts | 스캔 결과 시각화 |
| **테스트** | Vitest | Vite 네이티브, Jest 호환 |

---

## 7. 아키텍처 참조 분석

### 7.1 Nuclei (ProjectDiscovery) - 템플릿 기반 스캔

- Go 기반, YAML DSL 템플릿
- 9,000+ 커뮤니티 템플릿, 월 197+ 신규
- 6+ 프로토콜 지원: HTTP, DNS, TCP, File, Headless, Code
- **채택 포인트:** YAML 룰 정의, 커뮤니티 마켓플레이스, 속도 제한 제어

### 7.2 OWASP ZAP - 플러그인 아키텍처

- Java 기반, 인터셉팅 프록시
- Passive Scanner + Active Scanner 분리
- 애드온 마켓플레이스, REST API
- **채택 포인트:** 수동/능동 스캔 분리, REST API CI/CD 통합

### 7.3 Burp Suite - 상업 모델

- Java 기반, 모듈화 (Proxy, Repeater, Intruder, Scanner, Extender)
- Montoya API로 확장
- **채택 포인트:** 확장 마켓플레이스, 계층 가격 (Community/Pro/Enterprise)
- **회피:** Java 메모리 오버헤드 (16-17GB)

### 7.4 Metasploit - 모듈 시스템

- Ruby 기반, 모듈 계층
- 모듈 타입: Exploits, Auxiliary, Payloads, Encoders, Post-exploitation
- 표준화된 인터페이스 (metadata + run())
- **채택 포인트:** 모듈 카테고리화, DB 기반 결과/세션 관리

### 7.5 SPEAR 플러그인 인터페이스 설계

```typescript
interface SpearPlugin {
  metadata: {
    id: string;
    name: string;
    version: string;
    author: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    tags: string[];
    references: string[];       // CVE, CWE 링크
    safeMode: boolean;          // Safe Mode 호환?
    requiresNetwork: boolean;   // 네트워크 필요?
  };

  // 라이프사이클 훅
  setup?(context: PluginContext): Promise<void>;
  scan(target: ScanTarget): AsyncGenerator<Finding>;
  teardown?(context: PluginContext): Promise<void>;

  // 선택적 검증
  verify?(finding: Finding): Promise<VerificationResult>;
}
```

**3단계 플러그인 계층:**
1. **Core** (번들) - Git 스캔, 파일시스템, 엔트로피, 패턴 매칭
2. **Official** (npm install) - 네트워크, 클라우드, 브라우저 분석
3. **Community** (oclif plugin install) - 커스텀 디텍터, 통합

### 7.6 Safe Mode vs Aggressive Mode

| 기능 | Safe Mode | Aggressive Mode |
|------|-----------|-----------------|
| Regex 스캐닝 | O | O |
| 엔트로피 분석 | O | O |
| Git 히스토리 깊이 | 최근 100 커밋 | 전체, 모든 브랜치 |
| API 검증 | X (수동만) | O (능동 호출) |
| 네트워크 스캐닝 | X | 포트 스캔, DNS 열거 |
| 클립보드 접근 | X | 모니터링 활성화 |
| 파일시스템 범위 | 현재 프로젝트만 | 설정 가능 |
| 프로세스 검사 | X | 명시적 동의 필요 |
| 스캔 속도 | 스로틀링 | 전속력 |

**기본값: Safe Mode.** Aggressive는 `--mode aggressive` + 확인 프롬프트 필요.

---

## 8. SHIELD-SPEAR 시너지

```
┌─────────────────────────────────────────────────────────────┐
│                  RED TEAM / BLUE TEAM CYCLE                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [Developer Environment]                                     │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────┐    공격 시뮬레이션    ┌─────────────────┐  │
│  │ WIGTN-SPEAR │ ──────────────────→ │  취약점 발견     │  │
│  │  (Red Team) │                      │  + 증거 수집    │  │
│  └─────────────┘                      └────────┬────────┘  │
│                                                 │            │
│                                                 ▼            │
│                                       ┌─────────────────┐   │
│                                       │ WIGTN-SHIELD    │   │
│                                       │ (Blue Team)     │   │
│                                       │ 탐지 여부 검증   │   │
│                                       └────────┬────────┘   │
│                                                 │            │
│                                    ┌────────────┴──────┐    │
│                                    │                   │    │
│                              [탐지 성공]          [탐지 실패]│
│                              Shield 검증됨   Shield 개선 필요│
│                                    │                   │    │
│                                    └────────┬──────────┘    │
│                                             │               │
│                                             ▼               │
│                                    ┌─────────────────┐      │
│                                    │  Security Score  │      │
│                                    │  종합 보안 등급  │      │
│                                    └─────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### 통합 리포트 구조

1. **SPEAR Scan Report** - 발견된 취약점, 공격 체인, CVSS 점수
2. **SHIELD Detection Report** - 각 공격에 대한 탐지 성공/실패
3. **Gap Analysis** - SHIELD가 놓친 공격 분석
4. **Security Score** - 종합 보안 등급 (A~F)
5. **Remediation Playbook** - 개선 방안 자동 생성

---

## 참고 문헌

### AI/LLM 보안
- [arXiv:2302.12173](https://arxiv.org/abs/2302.12173) - Greshake et al. Indirect Prompt Injection
- [arXiv:2306.05499](https://arxiv.org/abs/2306.05499) - Liu et al. HouYi
- [arXiv:2601.09625](https://arxiv.org/abs/2601.09625) - Schneier et al. Promptware Kill Chain
- [arXiv:2402.07867](https://arxiv.org/abs/2402.07867) - PoisonedRAG
- [arXiv:2406.05870](https://arxiv.org/html/2406.05870v4) - Machine Against the RAG
- [arXiv:2601.17548](https://arxiv.org/abs/2601.17548) - SoK on Agentic Coding Assistants
- [arXiv:2509.22040](https://arxiv.org/abs/2509.22040) - AIShellJack
- [arXiv:2511.20920](https://arxiv.org/abs/2511.20920) - Securing MCP
- [arXiv:2403.02817](https://arxiv.org/abs/2403.02817) - Morris II AI Worm
- [arXiv:2401.05566](https://arxiv.org/abs/2401.05566) - Sleeper Agents
- [arXiv:2510.07192](https://arxiv.org/abs/2510.07192) - Constant-Sample Poisoning
- [arXiv:2511.02600](https://arxiv.org/abs/2511.02600) - Poisoned LLMs in Security Automation
- [arXiv:2510.09093](https://arxiv.org/abs/2510.09093) - AI Agent Data Exfiltration

### 공급망 보안
- [arXiv:2406.10279](https://arxiv.org/abs/2406.10279) - Package Hallucinations / Slopsquatting
- [arXiv:2502.20528](https://arxiv.org/html/2502.20528v1) - TypoSmart
- [arXiv:2309.02637](https://arxiv.org/abs/2309.02637) - Cerebro
- [OWASP Top 10:2025 A03](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [Birsan - Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-how-i-hacked-into-apple-microsoft-and-dozens-of-other-companies-4a5d60fec610)
- [Valsorda - Compromise Survey](https://words.filippo.io/compromise-survey/)

### 시크릿/키 탈취
- [Microsoft - Whisper Leak](https://www.microsoft.com/en-us/security/blog/2025/11/07/whisper-leak-a-novel-side-channel-cyberattack-on-remote-language-models/)
- [Varonis - Cookie-Bite](https://www.varonis.com/blog/cookie-bite)
- [Truffle Security - API Keys in Training Data](https://trufflesecurity.com/blog/research-finds-12-000-live-api-keys-and-passwords-in-deepseek-s-training-data)
- [DFRWS 2024 - TLS Key Material](https://dfrws.org/wp-content/uploads/2024/07/TLS-key-material-identification-and-extractio_2024_Forensic-Science-Internat.pdf)

### 개발 환경 공격
- [NDSS 2024 - UntrustIDE](https://www.ndss-symposium.org/ndss-paper/untrustide-exploiting-weaknesses-in-vs-code-extensions/)
- [Unit 42 - tj-actions Supply Chain](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- [IDEsaster](https://maccarita.com/posts/idesaster/)
- [Check Point - Claude Code CVEs](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)

### 공격 도구 아키텍처
- [TruffleHog Engine - DeepWiki](https://deepwiki.com/trufflesecurity/trufflehog/2.1-engine-configuration)
- [Semgrep Architecture - DeepWiki](https://deepwiki.com/semgrep/semgrep/2-core-architecture)
- [GitLeaks Rules - DeepWiki](https://deepwiki.com/gitleaks/gitleaks/4-rule-system)
- [Nuclei - ProjectDiscovery](https://github.com/projectdiscovery/nuclei)

### CVE 참조
- CVE-2025-54135, CVE-2025-54136 (Cursor CurXecute/MCPoison)
- CVE-2025-59536, CVE-2026-21852 (Claude Code RCE/API Key)
- CVE-2025-6514 (mcp-remote RCE)
- CVE-2025-30066 (tj-actions/changed-files)
- CVE-2024-32002, CVE-2025-48384 (Git Submodule RCE)
- CVE-2025-9074 (Docker Desktop, CVSS 9.3)
- CVE-2025-51591 (pandoc SSRF→IMDS)
- CVE-2025-65717, CVE-2025-65716, CVE-2025-65715 (VS Code Extensions)
- CVE-2025-59944 (Cursor Case-Sensitivity)
