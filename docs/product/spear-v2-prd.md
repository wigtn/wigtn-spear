# SPEAR v2 PRD

## Context and problem

`Fact` 기존 SPEAR는 시크릿 스캔, 공급망, MCP, 프롬프트 공격, 인프라 진단, 대회 제출물까지 하나의 플러그인 제품에 포함했지만 CLI 연결과 검증 근거가 일관되지 않았다.

`Fact` AI 에이전트 보안에서는 모델의 답변보다 실제 도구 호출, 승인, 데이터 흐름과 결과를 관측해야 보안 통제 실패를 입증할 수 있다.

`Inference` SPEAR가 범용 스캐너와 경쟁하기보다 조직별 행동 계약과 공격 시나리오를 재현 가능한 보안 테스트로 만드는 데 집중할 때 제품 가치가 생긴다.

## Goals

- `G-101` 에이전트 trace를 조직의 행동 계약과 대조해 실제 정책 위반을 입증한다.
- `G-102` 승인된 프로젝트 HTTP 대상에 공격 테스트를 실행해 보안 통제 실패를 응답 증거로 입증한다.
- `G-103` 같은 공격을 CI에서 재실행할 수 있는 결정론적 JSON 결과를 제공한다.
- `G-104` 모든 능동 테스트에 명시적 authorization scope와 실행 시점 동의를 요구한다.

## Non-goals

- 범용 SAST, 시크릿 스캐너, 의존성 스캐너 또는 클라우드 CSPM을 재구현하지 않는다.
- 인터넷 자산 탐색, 자동 exploit 생성, 무차별 대입, 지속성 확보, 데이터 파괴를 지원하지 않는다.
- 모델 응답에 대한 LLM judge 결과만으로 취약점을 확정하지 않는다.
- MCP 호스트, 런타임 방화벽, 대시보드 또는 취약점 관리 플랫폼을 우선 구축하지 않는다.
- OWASP AISVS/ASVS 또는 국내 인증 준수를 보장하지 않는다.

## Users and key scenarios

- AI 제품 개발자: 모델·프롬프트·도구 변경 전후의 행동 회귀를 검증한다.
- 제품 보안 담당자: 실제 사고나 위협 가설을 행동 계약과 공격 캠페인으로 고정한다.
- 모의침투 수행자: 고객이 승인한 프로젝트에서 HTTP 보안 통제 실패를 안전하게 재현한다.
- CI 운영자: JSON 결과와 exit code로 배포 차단 여부를 결정한다.

## Functional requirements

| ID | Requirement | Priority |
|---|---|---|
| `FR-101` | 시스템은 tool call, approval, data access, message event로 구성된 trace bundle을 입력받아야 한다. | Must |
| `FR-102` | 시스템은 deny-tool, require-approval, deny-argument-match, deny-data-egress, limit-tool-calls, deny-sequence 행동 규칙을 결정론적으로 평가해야 한다. | Must |
| `FR-103` | 각 agent finding은 위반 rule과 관련 trace event ID를 증거로 포함해야 한다. | Must |
| `FR-104` | agent attack은 adapter에 시나리오를 전달하고 반환된 trace만을 판정해야 한다. | Must |
| `FR-105` | project attack은 정확한 승인 origin에 정의된 HTTP 요청만 실행해야 한다. | Must |
| `FR-106` | project attack은 status, header, body, JSON path 보안 assertion 실패를 finding으로 변환해야 한다. | Must |
| `FR-107` | 능동 공격은 유효한 scope 파일과 CLI 동의 플래그가 모두 없으면 시작하지 않아야 한다. | Must |
| `FR-108` | 원격 대상과 mutating HTTP method는 각각 scope 및 CLI의 이중 동의를 요구해야 한다. | Must |
| `FR-109` | redirect, scope 밖 origin, 만료된 scope, 요청 수 초과를 실행 전에 또는 응답 시 차단해야 한다. | Must |
| `FR-110` | 결과는 사람이 읽을 수 있는 출력과 기계 판독 가능한 JSON 파일을 지원해야 한다. | Must |
| `FR-111` | 설정 및 응답 크기에 상한을 두고 결과 증거에서 토큰·cookie·authorization 값을 마스킹해야 한다. | Must |

## Non-functional requirements

- Node.js 22 이상에서 외부 런타임 의존성 없이 동작한다.
- assertion 결과는 동일한 입력과 trace에 대해 동일해야 한다.
- 네트워크 요청 기본 timeout은 5초이며 scope로 30초를 초과할 수 없다.
- 응답 증거는 scope의 크기 제한을 적용하며 최대 1 MiB를 넘을 수 없다.
- 공격 실행기는 셸 또는 사용자 제공 코드를 실행하지 않는다.
- GenAI trace 필드는 OpenTelemetry GenAI convention으로 변환 가능한 의미를 유지하되 아직 변동 중인 convention에 직접 종속되지 않는다.

## Acceptance criteria

| ID | Observable criterion | Verification method |
|---|---|---|
| `AC-101` | 금지 도구 호출 trace를 검증하면 해당 event ID를 가진 finding과 실패 exit code가 생성된다. | 단위 테스트 및 CLI 실행 |
| `AC-102` | 승인된 tool call은 require-approval finding을 만들지 않고 미승인 호출은 만든다. | 단위 테스트 |
| `AC-103` | 데이터 분류가 지정된 외부 전송 tool call은 deny-data-egress finding을 만든다. | 단위 테스트 |
| `AC-104` | 동의 플래그 없이 agent/project attack을 실행하면 네트워크 요청 전에 종료된다. | 단위 테스트 |
| `AC-105` | scope와 다른 origin 또는 redirect 응답은 차단된다. | 통합 테스트 |
| `AC-106` | mutating method는 이중 동의가 없으면 차단된다. | 단위 테스트 |
| `AC-107` | 안전 assertion을 충족하지 못한 HTTP 응답은 응답 status/header/body의 제한된 증거와 함께 finding이 된다. | 통합 테스트 |
| `AC-108` | 설정·trace·plan 예제가 schema validator를 통과하고 README 명령이 실행된다. | CI smoke test |

## Assumptions and open decisions

- `Assumption` 초기 adapter는 SPEAR의 최소 HTTP protocol을 구현하며 특정 agent framework SDK와 직접 결합하지 않는다.
- `Assumption` 프로젝트 공격의 첫 범위는 HTTP API와 웹 애플리케이션이다.
- `Open question` 첫 실제 고객 업무 흐름에서 공개 도구의 기본 테스트로 찾지 못하는 고유 위반을 발견할 수 있는가?
- `Open question` 에이전트 trace 수집을 OTel collector adapter로 제공할지 framework별 adapter로 제공할지 파일럿 후 결정한다.
- `Open question` 한국어 산업별 시나리오 팩을 오픈소스와 유료 자산 중 어디에 둘지 결정해야 한다.

## Risks and mitigations

- 오탐: 자유 형식 LLM 판정을 핵심 oracle에서 제외하고 구체적인 event/response assertion을 사용한다.
- 공격 오용: exact origin, scope 만료, 이중 동의, request cap, redirect 차단, mutating method 차단을 적용한다.
- 민감정보 유출: 입력 크기 제한, 결과 evidence 제한, 공통 secret header 마스킹을 적용한다.
- adapter 조작: trace는 대상이 제공한 주장이라는 점을 결과에 표시하며, 장기적으로 독립 OTel 수집과 서명된 run artifact를 도입한다.
- 표준 변동: OWASP risk ID와 OTel 변환은 metadata로 분리하고 실행 모델을 특정 버전에 고정하지 않는다.

## Delivery outline

1. 계약·trace·scope·attack plan 스키마와 validator
2. 오프라인 agent verifier
3. 승인된 agent adapter campaign runner
4. 승인된 project HTTP attack runner
5. CLI, JSON artifact, 테스트 및 예제
6. 실제 WIGTN 에이전트 파일럿과 incident-to-regression 검증
