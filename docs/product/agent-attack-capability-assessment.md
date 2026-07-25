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

## 냉정한 한계 (이걸 감추면 사기다)

1. **발견이 아니라 검증이다.** SPEAR는 사람이/LLM이 작성한 attack program을 실행해
   *입증*한다. 미지의 취약점을 스스로 *발견*하거나 새로운 jailbreak를 생성하지 않는다.
   내장 프로브 카탈로그는 3개짜리 seed에 불과하다. **얼마나 터느냐 = 프로브가 얼마나
   좋으냐**이고, 그건 아직 사람 손에 달렸다.
2. **witness에 의존한다.** `proven`은 계측 가능한 witness(owned sink, backend witness,
   MCP 엔드포인트, 심어둔 reply canary)가 있어야 한다. 계측이 전혀 없는 완전 black-box
   타깃에서는 대부분 candidate로 떨어진다.
3. **fixture-proven ≠ real-world-proven.** 지금 모든 테스트는 *우리가 취약하게 만든*
   fixture를 증명한다. 엔진은 검증됐지만, **실제 확률적 LLM 에이전트를 상대로 한
   end-to-end 실증은 아직 0건**이다. flaky 비율도 실측된 적 없다(3-of-2 임계는 이론).
4. **adaptive search 없음(FR-407 미구현).** 공격이 실패해도 재시도·진화하지 않는다.
   고정된 프로그램만 돈다.
5. **black-box tool 관측용 gateway/OTel witness 없음.** v2 cold assessment가 최우선
   Blocker로 지목한 "대상이 준 trace를 안 믿고 독립 수집" — agent tool 계층에선 아직
   owned sink을 우리가 세팅해야만 가능하다(고객 협조 전제).

## "어느 수준까지 터나" — 정직한 3단계

| 교전 유형 | 현실적 역량 |
|---|---|
| **Authorized gray-box (고객이 staging에 canary 심고 witness 노출)** | 6종 전부 실제 finding 입증 가능. **여기가 SPEAR의 sweet spot이자 팔 수 있는 역량.** |
| **Authorized black-box (라이브 엔드포인트, 계측 없음)** | canary를 심을 수 있으면 reply-leak까지. tool-egress/backend-state/memory는 owned witness 없이는 proven 불가 → candidate 수준. |
| **자율 발견 / 새 공격 생성** | **역량 아님.** SPEAR는 verifier지 discoverer가 아니다. |

## 이 벤치마크 하네스가 하는 것 / 못 하는 것

- **한다**: 프로브 corpus를 campaign으로 돌려 proven/candidate/rejected/flaky를 집계하고,
  **독립 witness proven vs reply-only proven을 분리**해 정직한 스코어카드를 낸다. 프로브를
  늘려가며 커버리지 진척을 *측정*할 수 있다.
- **못 한다**: 우리 fixture에서 나온 proven rate는 **역량 주장이 아니다**. 스코어카드가
  항상 disclaimer 3종을 달고 나오는 이유다. 공개 벤치마크(AgentDojo/InjecAgent) 케이스를
  이 corpus로 *수입*해야 대외 비교가 성립한다(다음 작업).

## 상향하려면 필요한 것 (우선순위)

1. **실제 LLM 에이전트 라이브 실증 1건** — flaky 비율 실측. 지금 가장 큰 공백.
2. **공개 벤치마크 케이스 수입** — InjecAgent(1,054케이스)/AgentDojo(629 injection)를
   프로브 corpus로 변환해 이 하네스로 돌리고 "SPEAR proven vs 저들 judge" 비교.
3. **gateway/OTel witness 수집** — black-box에서 tool 호출을 독립 관측(협조 없이도).
4. **adaptive/LLM 프로브 생성(FR-407)** — 단, 판정은 여전히 deterministic(FR-408).

## 한 줄 결론

엔진과 증거 체계는 진짜다(6종 witness-proven, 126 테스트). 하지만 지금은 **"고객이
협조하는 gray-box 교전에서, 알려진 6개 클래스를 반박 불가능한 증거로 입증·회귀"**가
정직한 상한이다. "실제 에이전트를 자율로 턴다"는 아직 못 하고, 그 격차를 메우는 건
프로브 corpus 확장 + 라이브 실증 + gateway witness이지 엔진을 더 짓는 게 아니다.
