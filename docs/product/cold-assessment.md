# SPEAR v2 cold assessment

기준일: 2026-07-23

## Facts

- `Fact` SPEAR v2는 구형 플러그인 25개와 대회 코드를 제거하고 agent action contract 및 authorized HTTP attack runner만 남겼다.
- `Fact` 현재 agent verifier는 6개 결정론적 rule type을 지원하며 모든 finding에 trace event ID를 연결한다.
- `Fact` 현재 active agent runner가 받는 trace는 테스트 대상 adapter가 제공한다. 독립 수집 또는 artifact 서명은 아직 없다.
- `Fact` project runner는 exact origin, redirect 차단, request cap, timeout, response cap, remote/mutation 이중 동의를 구현한다.
- `Fact` Promptfoo는 이미 OpenTelemetry trace, tool argument, tool sequence, step count, goal success assertion과 finding-to-regression 흐름을 제공한다.
- `Fact` Snyk Agent Scan과 Cisco AI Defense는 MCP/skill 발견과 정적·행동 분석 영역에서 훨씬 넓은 제품 범위를 제공한다.

## Inferences

- `Inference` 현재 코드만으로 독립 상용 제품의 moat는 없다. Promptfoo의 작은 action-policy subset으로 평가될 가능성이 높다.
- `Inference` 범용 payload 생성, MCP discovery 또는 프로젝트 scanner를 다시 추가하면 기존 실패 구조와 경쟁 제품 중복으로 돌아간다.
- `Inference` 살릴 수 있는 차별점은 엔진이 아니라 고객별 action contract, 한국어 실제 업무 공격 carrier, 독립 trace 증거, incident-to-regression 운영과 보안 진단 전달력이다.
- `Inference` project attack은 자동 취약점 탐색기가 아니라 재현 가능한 공격 test runner다. 이 경계를 유지해야 결과의 신뢰도가 높다.

## Open questions

- `Open question` 공개 도구 기본 설정으로는 발견하지 못하지만 SPEAR contract가 발견하는 실제 고위험 문제가 존재하는가?
- `Open question` 고객 agent에서 독립 OTel collector를 설치할 수 있는가?
- `Open question` 실제 두 사용자 또는 두 tenant fixture를 자동 준비해 BOLA/권한 상승을 검증할 수 있는가?
- `Open question` 한국어 업무 시나리오와 보고서가 구매 이유가 될 만큼 반복되는가?

## Prioritized gates

1. `Blocker` 독립 OTel trace ingestion과 run artifact integrity를 구현한다. 대상이 스스로 제공한 trace만으로 “입증”을 주장하지 않는다.
2. `Blocker` 실제 WIGTN agent 한 개에서 간접 prompt injection → tool call → data egress 또는 approval bypass를 재현하고 수정 후 회귀를 증명한다.
3. `High` project attack에 두 identity/tenant fixture, 변수 추출, 요청 chain을 추가해 BOLA/BFLA와 workflow authorization을 검증한다.
4. `High` Promptfoo 동일 시나리오와 비교해 SPEAR만 제공하는 조직별 policy/evidence가 무엇인지 문서화한다.
5. `Medium` JUnit/SARIF 및 redacted replay bundle을 추가해 CI와 진단 보고서 전달을 완성한다.
6. `Stop condition` 실제 파일럿에서 고유 finding 또는 운영 비용 절감이 입증되지 않으면 독립 제품화를 중단하고 Promptfoo용 한국어 scenario pack으로 전환한다.
