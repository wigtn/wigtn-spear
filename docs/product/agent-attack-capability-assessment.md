# SPEAR agent-attack capability — cold assessment

기준일: 2026-07-25. 목적: "우리가 실제로 AI 에이전트를 어느 수준까지 털 수 있나"를
과장 없이 판정한다. 마케팅 문구가 아니라 코드와 테스트가 뒷받침하는 것만 적는다.

## 지금 검증된 것 (fixture + 테스트 126개 기준)

witness 기반 proven vertical 6종이 vulnerable/fixed fixture로 실증됨:

- direct injection → system-prompt/secret 유출 (`agent-canary-leak`)
- tool 호출 남용 → owned sink으로 exfil (`agent-tool-egress`)
- confused deputy / excessive agency → 권한 백엔드 상태변화 (`agent-backend-state`)
- indirect(문서) injection → untrusted 데이터 경유 (carrier)
- MCP rug-pull / shadowing → capability digest drift (`verifyMcpIntegrity`)
- memory poisoning → 주입/활성화 분리 + sleeper (`runMemoryAttack`)

공통 강점: baseline/attack/counterfactual + replay 임계 + **독립 out-of-process
witness**. self-report(모델 텍스트)만 있는 신호는 candidate로 강등하고 proven을 거부.

## 한계 진행 상황 (닫힌 것 / 남은 것)

1. **[부분 해소] 발견 vs 검증.** 두 갈래로 대응: (a) `mutator.ts`+`search.ts`(적응형
   탐색, FR-407)로 seed를 변형해 **타깃에 먹히는 exploit을 스스로 탐색**. (b) `corpus.ts`
   `parseInjecAgent`로 **공개 corpus(InjecAgent MIT, 1,054)를 프로브로 ingest** → "손으로 짠
   3개 seed"를 필드 축적으로 대체. corpus의 성공 라벨은 hint로 강등하고 우리 witness로
   재판정. **여전한 경계**: 알려진 클래스 안에서 통하는 걸 찾는 것이지 새 클래스 발명은
   아니다. garak/AgentDojo 어댑터는 다음. 판정은 여전히 deterministic(FR-408).
2. **[해소] adaptive search(FR-407).** 위 `searchAgentAttack`가 실패 시 다음 전략으로
   진행하고 proven이면 조기 종료, budget으로 bound. 고정 프로그램만 돌던 상태 해소.
3. **[부분 해소] witness 의존 / black-box.** `agent-gateway-egress` oracle +
   `GatewayWitness`로, 에이전트 tool egress를 **프록시 chokepoint**로 통과시켜 임의
   목적지(공격자 서버 포함)로 나가는 exfil을 관측한다. owned sink을 pre-register할
   필요 없이 **egress 경로만 통제하면** 됨(현실적 black-box 세팅: 에이전트 프록시를
   우리로). **여전한 경계**: 에이전트가 프록시를 우회하거나 egress를 계측 못 하면 여전히
   candidate. 완전 무협조 black-box는 미해결.
4. **[남음] fixture-proven ≠ real-world.** 실제 확률적 LLM 에이전트 end-to-end 실증
   **여전히 0건**. flaky 비율 미실측. provider 어댑터는 준비됐으나 라이브 실행은 미수행.

## "어느 수준까지 터나" — 정직한 3단계

| 교전 유형 | 현실적 역량 |
|---|---|
| **Authorized gray-box (고객이 staging에 canary 심고 witness 노출)** | 6종 전부 실제 finding 입증 가능. **여기가 SPEAR의 sweet spot이자 팔 수 있는 역량.** |
| **Authorized black-box (egress 프록시만 우리로)** | gateway witness로 임의 목적지 exfil까지 proven. canary 심으면 reply-leak도. 프록시조차 못 태우는 완전 무협조면 candidate. |
| **자율 발견 / 새 공격 생성** | **역량 아님.** SPEAR는 verifier지 discoverer가 아니다. |

## 이 벤치마크 하네스가 하는 것 / 못 하는 것

- **한다**: 프로브 corpus를 campaign으로 돌려 proven/candidate/rejected/flaky를 집계하고,
  **독립 witness proven vs reply-only proven을 분리**해 정직한 스코어카드를 낸다. 프로브를
  늘려가며 커버리지 진척을 *측정*할 수 있다.
- **못 한다**: 우리 fixture에서 나온 proven rate는 **역량 주장이 아니다**. 스코어카드가
  항상 disclaimer 3종을 달고 나오는 이유다. 공개 벤치마크(AgentDojo/InjecAgent) 케이스를
  이 corpus로 *수입*해야 대외 비교가 성립한다(다음 작업).

## 남은 상향 작업 (우선순위)

1. **corpus ingestion 확장** — InjecAgent(indirect)·garak(direct) 어댑터 구현됨
   (`parseInjecAgent`/`parseGarakPrompts`). 다음: AgentDojo(MIT) 어댑터, 실제 corpus 파일로 대량 실행.
2. **attacker-LLM 루프** — PAIR/TAP tree-search + Crescendo 멀티턴 재구현(black-box). 판정은
   여전히 deterministic(FR-408). mutation 엔진 + corpus를 이 루프의 seed로.
3. **실제 LLM 에이전트 라이브 실증 1건** — flaky 비율 실측(#4). provider 어댑터는 준비됨,
   API 키(env) 필요. gateway witness는 구현됨(black-box egress 관측).
3. **공개 벤치마크 케이스 수입** — InjecAgent(1,054)/AgentDojo(629)를 프로브 corpus로
   변환해 벤치마크 하네스로 "SPEAR proven vs 저들 judge" 대외 비교.
4. **LLM 기반 변형 전략 추가** — `MUTATION_STRATEGIES`에 LLM 생성 변형을 한 소스로 추가.
   단 판정은 여전히 deterministic(FR-408).

## 한 줄 결론

엔진·증거·**적응형 탐색**까지 진짜다(6종 witness-proven + mutation search, 129 테스트).
정직한 상한은 여전히 **"고객 협조 gray-box 교전에서 알려진 6클래스를 반박불가 증거로
입증·회귀 + 통하는 exploit 변형 자동 탐색"**. 남은 격차는 (a) black-box에서의 독립
witness(gateway), (b) 실제 LLM 라이브 실증 — 둘 다 진행 중 항목이다.
