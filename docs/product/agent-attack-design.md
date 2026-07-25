# SPEAR Agent Attack vertical — design and rationale

기준일: 2026-07-25

## 문제와 포지셔닝

고객사가 자사 AI/agent 제품을 "뚫어달라"고 authorized로 맡기는 pentest 비즈니스.
대상은 미지의 취약점을 가진 실제 black-box agent(챗봇·코딩 agent·RAG·MCP tool 사용
agent)다. 따라서 fixture 순환논리는 사라지고 도구가 실제 발견을 수행할 수 있다.

기존 도구(garak, PyRIT, promptfoo)와의 차별점은 엔진 payload가 아니라 **증거 등급**이다.

- 그들 대부분: "모델 출력이 탈옥처럼 보인다"(regex / LLM-judge) → 자기보고 기반 신호.
- SPEAR: **독립적·결정적 oracle이 실제 효과를 관측했을 때만 `proven`.** 나머지는
  `candidate`로만 보고하고 절대 승격하지 않는다(FR-408/FR-453 준수).

## 구현된 것 (`src/agent/`, 테스트 3종 통과)

- `AgentTarget` 어댑터: 임의의 agent HTTP 엔드포인트를 body 템플릿 + reply JSON path로
  기술. 소켓 열기 전 authorization scope(`DestinationGuard`)로 검증.
- 두 개의 **proven-capable** oracle:
  - `agent-canary-leak` — engagement가 심어둔 canary(시스템 프롬프트/RAG/타 사용자
    레코드)가 응답에 **정확히** 등장 → 데이터 유출. 결정적 exact-match, judge 불필요.
  - `agent-tool-egress` — **owned sink**이 run-scoped canary를 관측 → tool 호출이
    프로세스 밖으로 실제 exfiltration했음을 응답과 무관하게 입증. 가장 차별적.
- 하나의 **candidate-only** oracle: `agent-marker-compliance`. self-report이므로
  `runAgentAttack`이 명시적으로 거부한다(증거 정직성).
- baseline / attack×N / counterfactual + 반복 임계(FR-603: 3-of-2)로 기존
  `deriveCausalDisposition` 재사용 → `proven`/`rejected`/`flaky`/`error`.
- canary redaction + Ed25519 서명 evidence bundle(`signAgentEvidence`/`verifyAgentEvidence`).
- 프로브 카탈로그 seed(`PROBE_CATALOG`): direct extraction, role confusion, indirect
  tool egress. 각 프로브는 자기를 입증하는 oracle을 선언.
- fixture: 취약/수정 agent + owned sink 서버로 vulnerable=proven / fixed=rejected 실증.

## 동작 방식 (한 줄)

benign baseline과 counterfactual에는 canary가 안 나오고, 오직 injection 공격에서만
**독립 witness**가 canary/tool-egress를 관측하며, 그 재현이 임계를 넘을 때만 `proven`.

## 추가로 구현된 것 (2026-07-25 이어서)

- **CLI `spear run agent`** — manifest→`verifyAuthorization`(서명/scope/expiry/
  capability `run:agent`/build binding)을 네트워크 전에 통과 → 서명 evidence bundle.
  `validateAgentAttackProgram`로 untrusted program JSON 검증(agent는 nondeterministic:true
  강제 + FR-603 완화 임계). proven=exit 1.
- **hostname socket pinning** — 실제 고객 엔드포인트(hostname)를 기존 `pinning.ts`
  undici dispatcher로 pin + 매 요청 revalidate → DNS-rebinding 안전. IP-literal 제약 해소.
- **provider 프리셋** — `openAiChatTarget`/`anthropicMessagesTarget`. API 키는 evidence
  bundle에서 redact(env 주입 권장). LLM은 target/seed용이며 **판정엔 여전히 금지**.
- **project-only counterfactual 분리(FR-455)** — `program.projectOnly`: agent 없이 동일
  효과를 직접 시도하는 요청 + detection(`canary-in-response`/`sink-egress`). 결과를
  `agent-required`(agent 경유만 됨 → 진짜 AI 취약점) vs `backend-reachable`(백엔드 단독
  가능 → misconfig)로 분류. `AgentRunResult.projectOnly`에 기록, evidence에서 redact.

## 아직 안 된 것 / 다음 단계 (우선순위)

1. **compound chain** — injection → tool arg → 기존 HTTP sink(SSRF/BOLA)까지 한
   candidate로 연결. 기존 causal HTTP 엔진 재사용률 높음(ROI 큼).
2. **MCP pack(FR-456)** — tool shadowing / rug-pull / capability drift snapshot.
3. **memory pack(FR-457/458)** — poisoned write → 지연 activation, provenance 손실.
4. **seed/mutation 생성기** — LLM으로 injection carrier 변형 생성(판정 아님).

## 판정 원칙 (agent에도 동일 적용)

- self-report(모델 텍스트/agent trace)는 참고 증거일 뿐, 독립 witness와 불일치하면
  witness 우선.
- `proven`은 effect oracle + baseline/attack/counterfactual + replay 임계 전부 필요.
- LLM은 seed/mutation 제안까지만. 성공 판정과 publish는 deterministic oracle이 한다.
- 외부/제3자 live target 자동 공격 금지. owned/authorized/disposable만.
