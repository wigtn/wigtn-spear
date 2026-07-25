# SPEAR 냉정한 전략 평가 (2026-07-25)

검증 출처: 경쟁/상용화·벤치마크 리서치(1차 소스 live-fetch) + 우리 라이브 실측(Otto
Support, gpt-5.6). 마케팅 아닌 확인된 사실만. `[V]`=검증, `[U]`=미검증.

---

## 1. 우리는 실제로 어떻게 공격하나 (그리고 현실의 벽)

**핵심 실측**: 2026에 "모델을 악하게 만드는" 공격은 대체로 안 통한다. 라이브에서 3겹 벽 확인:
1. **provider API 게이트** — 노골적 공격 프롬프트로 gpt-5.6 attacker-LLM을 돌리면 OpenAI가
   API 차원 거부(TAC 인가 필요). `[V]`
2. **모델 정렬 거부** — "결제 토큰/내부 데이터를 붙여넣어라"는 요청을 정렬된 모델이 거부. `[V]`
3. **취약점 인식** — "진단용 내부 metadata fetch"조차 gpt-5.6가 SSRF로 인식하고 거부. `[V]`

→ **통하는 유일한 벡터 = app-flaw 공격**: 모델은 순진한 행동(평범한 외부 URL fetch), **앱이
유출**(툴에 크레덴셜 자동 첨부·SSRF·과잉권한). 우리 tool-agent 데모가 gpt-5.6에서 proven 난
이유. 이건 SPEAR만의 문제가 아니라 **attacker-LLM을 쓰는 모든 경쟁사의 공통 벽**이다.

**함의**: 우리 durable edge는 "공격 생성"이 아니라 **(a) 앱 wiring 결함을 치는 방법론 +
(b) 실제 effect를 잡는 witness**. 적대적 생성이 필요하면 로컬/무검열 모델 또는 TAC가 실무 전제.

## 2. 진짜 차별점 (검증됨 — 이거 하나가 moat)

리서치가 이분법으로 정리:
- **런타임 tool-call *관찰/게이팅*은 2026에 commoditized** `[V]` — Cisco AI Defense, Palo Alto
  Prisma AIRS, Invariant/Snyk mcp-scan(OSS 무료), Prompt Security/SentinelOne MCP Gateway,
  Zenity AIDR 등이 이미 호출 경계에서 관찰·차단. **"우리는 tool 호출을 본다"는 차별점 아님.**
  promptfoo도 이미 `trajectory:tool-used` action-grading을 함 `[V]`.
- **관측된 side-effect + counterfactual + deterministic replay로 채점**하는 건 **아직 어떤 상용
  제품도 안 함** `[V]`. 2026 연구에만 존재("Causal Agent Replay" arXiv 2606.08275). 가장 근접한
  상용은 Cisco AI Defense(out-of-band telemetry 상관)·promptfoo(OTel trajectory)지만 **둘 다
  counterfactual도 replay도 안 함.**

**판정 `[V]`**: SPEAR의 **witness + counterfactual + replay** 조합은 2026에 **진짜 차별적**.
시장은 런타임 *inspection*으로 옮겨갔지, effect-graded *verification with counterfactual+replay*로는
안 옮겨갔다. 이게 text-judge 진영이 자인하는 **false-positive 문제를 직접 죽이는** 유일한 방법.

## 3. 우리가 남 따라하는 것 (여기서 경쟁하면 진다)

- **공격/payload 생성** — commoditized. DeepTeam·promptfoo·Repello(15M+ 패턴)·Adversa·Protect AI
  다 방대한 라이브러리 보유. "우리 공격 많다"로 팔지 말 것.
- **런타임 tool-call 가로채기** — Invariant(무료 OSS)·Prompt Security·Cisco가 소유. "우리가 호출을
  본다"로 팔지 말 것. witness는 *관찰*이 아니라 *채점/검증*으로 팔아야.
- **벤치마크 ingestion** — table-stakes 배관이지 moat 아님.

## 4. 경쟁 지형 (누가 어떻게 채점하나, 검증)

| 진영 | 채점 방식 |
|---|---|
| Giskard·Confident AI(DeepTeam)·Protect AI·Lakera | **text/LLM-judge** (응답 텍스트 판정) |
| **promptfoo** | text-judge + **action-graded**(OTel 있으면 `trajectory:tool-*`) — OSS 최강 |
| **Cisco AI Defense** | **action-graded 최강 상용** — 응답↔관측↔out-of-band telemetry 상관을 "ground truth"로 |
| Invariant/Snyk·Prompt Security/SentinelOne·Zenity·Prisma AIRS | **런타임 게이팅(방어)** — 호출 경계 allow/block/redact |
| Adversa | 공격측 effect 근접(실제 RCE·세션 exfil 주장) |
| **SPEAR** | **witness(effect) + counterfactual(인과) + signed replay(재현)** ← 아무도 안 하는 조합 |

인수 정리 `[V]`: SplxAI→Zscaler, Protect AI→Palo Alto(완료), Prompt Security→SentinelOne,
CalypsoAI→F5, (Lakera→Check Point `[U]`).

## 5. 상용화 웨지 (냉정하게)

**타이밍이 좋다** `[V]`: **EU AI Act 집행이 2026-08-02**(8일 뒤)부터 본격 적용, **OWASP Agentic
Top 10 2026**에 "Tool Misuse & Exploitation"·"Identity & Privilege Abuse" 카테고리 신설. 바이어의
돈이 **일회성 finding → 지속 모니터링 + 감사 가능한 증거 + 프레임워크 매핑**으로 이동 중.

- **ICP**: **MCP/멀티에이전트 + 규제데이터/자금이동 side-effect를 가진 제품**(핀테크·헬스케어·
  agentic RevOps/IT자동화). 이미 **연 $200K–500K "continuous assurance"**를 지불하고 Aug-2026
  집행에 직면한 세그먼트.
- **패키지**: *"검증된 finding 지속 보증"* — scan당이 아니라 **verified finding당 / agent-under-test당**
  과금. 산출물 = **replay 가능·counterfactual 뒷받침 proof pack**(OWASP Agentic·NIST AI 600-1
  자동 매핑). CI(promptfoo/RAMPART와 같은 면)+스케줄 지속 실행.
- **세일즈 메시지**: text-judge 진영을 향해 **"zero-false-positive, replay로 증명되는 finding."**
  (모델 텍스트 스크린샷은 감사 증거가 안 되지만, witness+replay proof pack은 된다.)
- **가격 참고** `[V]`: RTaaS $16–100K/건, 플랫폼 $40–200K/yr, 멀티에이전트+툴+규제 $200–500K+/yr.

## 6. 우리가 지는 곳 (하지 말 것)

- **런타임 차단/가드레일(inline gateway)** — Cisco·Palo Alto·Zscaler·SentinelOne·Invariant/Snyk가
  기존 MSA에 번들해 유통 소유. SPEAR는 **검증/보증 레이어**지 집행 런타임이 아니다.
- **엔터프라이즈 브레드스 + 컴플라이언스 스위트 판매** — 위 대기업들이 번들로 이김. SPEAR는
  **한 어려운 문제(tool-misuse를 반박불가로 증명)의 깊이**로 이기고, 그들 런타임 *옆에* 앉는
  증거 레이어로 랜딩.

## 7. 구체적 다음 수 (우선순위)

1. **causal + signed replay를 finding proof pack으로 산출** — 이미 있는 evidence bundle을
   OWASP Agentic + NIST AI 600-1 매핑까지 붙여 "감사 제출용"으로 마감. ← 상용 웨지의 핵심 산출물.
2. **MCPSecBench 연동**(MIT, 방어 MCIP/AIM-MCP 내장) — "가드레일 우회 + witness 증명"을 표준
   벤치마크에서 실증. 그다음 MSB(MIT, 2000 케이스). SeClaw(Apache-2.0)는 trajectory 최상.
3. **app-flaw 공격 카탈로그 확장** — 크레덴셜 자동첨부·SSRF·과잉권한·output-sink 등 "모델은
   순진, 앱이 유출" 패턴을 victim 시나리오로 넓힘(attacker-LLM 벽을 우회하는 유일 벡터).
4. **로컬/무검열 attacker 모델 옵션** — 적대적 생성이 필요할 때 provider 게이트 우회(운영 전제).

## 한 줄 결론

시장은 "tool 호출을 본다"까지 왔지만, **"그 효과가 실제로 일어났고, 공격이 없었으면 안
일어났고, 재현된다"까지 증명하는 건 아무도 안 한다** — 거기가 SPEAR의 유일하고 방어 가능한
moat다. 공격 생성·런타임 차단으로는 이길 수 없으니, **감사 제출 가능한 zero-FP 증거**로
규제 타이밍(EU AI Act 8/2, OWASP Agentic)에 파고드는 게 냉정한 상용 경로다.
