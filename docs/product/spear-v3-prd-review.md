# SPEAR v3 PRD deep review

검토 대상: `docs/product/spear-v3-prd.md`  
검토일: 2026-07-23  
결론: **Phase 0–1 구현 진입 가능, 전체 제품화는 조건부**

> 이 문서는 최초 Next.js/Supabase 중심 draft의 리뷰다. 범용 web/API/backend coverage 확장에 대한 후속 공격 검토는 `spear-v3-coverage-red-team-review.md`를 기준으로 한다.

## 1. Evidence inspected

### Facts

- `Fact` 현재 SPEAR 구현은 target-provided agent trace와 operator-authored HTTP assertion을 평가한다.
- `Fact` 현재 구현에는 source mapper, multi-principal twin, database/process witness, causal replay, adaptive search와 minimizer가 없다.
- `Fact` 현재 안전 통제에는 exact origin, redirect 차단, timeout, request/response cap, remote/mutation 이중 동의와 redaction이 있다.
- `Fact` WIGTN core boilerplate는 Next.js App Router, route handler, server action, Supabase Auth/Postgres/RLS, OpenAPI와 monorepo 구조를 사용한다.
- `Fact` PRD는 v2 backward compatibility를 non-goal로 선언하고 v3를 사실상 재구축하는 delivery로 정의한다.

## 2. Findings

### Blocker

#### `REV-B01` Authorization manifest의 진위가 보장되지 않았다 — Resolved

- 영향 구간: `FR-101`–`FR-105`, 권한 모델
- `Fact` 최초 draft는 로컬 JSON manifest를 “engagement owner만 발급”한다고 했지만 owner임을 검증하는 수단이 없었다.
- `Inference` active exploitation 권한을 일반 파일의 문자열에만 의존하면 안전 경계를 제품이 강제한다고 주장할 수 없다.
- 조치: Ed25519 signature, trust-store key ID, key revocation, expiry와 capability 검증을 `FR-105`, `AC-103`에 추가했다.

#### `REV-B02` Production read-only active test의 안전 경계가 모호했다 — Resolved

- 영향 구간: `FR-103`, `AC-102`, Non-goals
- `Fact` 최초 draft는 production에서 read-only 검증을 허용했다.
- `Inference` GET 또는 read-only operation도 개인정보·secret 노출, cache 변화와 rate impact를 일으킬 수 있으므로 초기 autonomous search에 안전하지 않다.
- 조치: 초기 release는 disposable/test target만 허용하고 production-class manifest는 method와 관계없이 거부하도록 변경했다.

### High

#### `REV-H01` P0 XSS·CSRF와 browser delivery 시점이 충돌했다 — Resolved

- 영향 구간: Initial technical scope, `FR-406`, Phase 1과 Phase 4
- `Fact` 최초 draft는 browser witness가 Phase 4인데 XSS와 CSRF를 P0로 분류했다.
- `Inference` browser가 없는 Phase 1에서 browser-enforced control을 proven으로 주장하면 acceptance contract가 거짓이 된다.
- 조치: browser-enforced CSRF/XSS/navigation을 P1로 분리하고 `AC-406`을 Phase 4 exit로 유지했다.

#### `REV-H02` WIGTN 핵심 권한 경계인 Supabase RLS가 mapper contract에 명시되지 않았다 — Resolved

- 영향 구간: `FR-201`–`FR-206`, `AC-203`
- `Fact` 실제 boilerplate는 Supabase Auth/Postgres/RLS를 사용한다.
- `Inference` route handler만 분석하면 application check와 database policy 사이의 이중 경계를 설명하지 못하고 cross-tenant finding의 원인을 잘못 귀속할 수 있다.
- 조치: migration table/function, RLS enablement/policy, storage policy와 service-role 후보를 route/data edge에 연결하는 `FR-206`, `AC-203`을 추가했다.

#### `REV-H03` P0 vulnerability family와 acceptance matrix의 범위가 일치하지 않았다 — Resolved

- 영향 구간: Initial vulnerability families, Acceptance criteria
- `Fact` 최초 draft는 session, query/data exposure와 mass assignment를 P0로 선언했지만 직접 검증하는 acceptance criterion이 없었다.
- 조치: session actor matrix `AC-409`, query/data-flow `AC-410`, mass-assignment/state-transition `AC-411`을 추가했다.

#### `REV-H04` `proven` 재현 기준을 campaign이 지나치게 낮출 수 있었다 — Resolved

- 영향 구간: `FR-602`, `FR-603`
- `Inference` 1회 성공도 허용하면 비결정적인 agent 결과를 causal proof로 과장할 수 있다.
- 조치: project-only는 최소 2/2, agent 포함 candidate는 최소 3회 중 2회 재현을 하한으로 두고 campaign은 더 엄격하게만 변경할 수 있도록 했다.

#### `REV-H05` 웹·백엔드 탐지가 범용 DAST로 확장될 위험이 있다 — Controlled, not eliminated

- 영향 구간: Product thesis, Non-goals, `FR-402`, Delivery outline
- `Fact` PRD는 project-only finding도 독립 결과로 허용한다.
- `Inference` compound mode보다 일반 HTTP 취약점 개수에 집중하면 SPEAR의 독자성이 다시 사라진다.
- 통제: Next.js/Supabase, multi-principal authorization, source-assisted candidate와 independent state proof로 범위를 제한했다.
- 잔여 gate: Phase 2에서 fixed payload baseline보다 unique proven chain을 더 찾지 못하면 adaptive engine 개발을 중단한다.

### Medium

#### `REV-M01` 현재 저장소에서 점진적 확장이 아니라 실행 코어 재구축이 필요하다 — Accepted

- 영향 구간: Repository fit, Phase 0
- `Fact` 기존 types와 runner는 flat rules, 단일 HTTP request와 target-provided trace를 중심으로 한다.
- `Inference` graph, twin, witness와 causal replay를 기존 result schema 안에 억지로 추가하면 v2 호환 복잡도만 증가한다.
- 조치: PRD에서 v2 schema compatibility를 제거하고 안전 원칙만 이관하도록 명시했다.

#### `REV-M02` Source mapper의 false-negative 경계가 framework별로 크게 달라진다 — Accepted with guard

- 영향 구간: Supported target profile, `FR-201`–`FR-206`, Compatibility
- `Inference` dynamic route registration, wrapper middleware, generated RPC와 raw SQL은 static mapper가 놓칠 수 있다.
- 통제: source/runtime inventory 병합, extraction diagnostics와 unsupported construct error를 요구하고 static 결과는 candidate로만 취급한다.
- `Open question` Express/Fastify 지원은 Next.js pilot이 끝나기 전 추가하지 않는다.

#### `REV-M03` 실제 campaign cost와 hard budget 기본값이 아직 없다 — Open

- 영향 구간: `FR-802`, Open decisions
- `Fact` PRD는 request, token, 시간, concurrency와 disk budget의 존재를 요구하지만 수치는 정하지 않는다.
- `Inference` target 성능과 model provider가 정해지기 전에 임의 숫자를 PRD에 고정하면 근거 없는 SLA가 된다.
- 결정 시점: Phase 1 fixture benchmark로 project mode hard default를, Phase 2 provider 결정으로 compound token/cost ceiling을 확정한다.

#### `REV-M04` Receipt hash-chain만으로 완전한 non-repudiation을 주장할 수 없다 — Accepted with wording limit

- 영향 구간: `FR-503`, Isolation and security, Open decisions
- `Fact` hash-chain은 event 삭제·변경 탐지에 유용하지만 공격자가 전체 chain과 storage를 교체할 수 있으면 서명과 동일하지 않다.
- 통제: witness와 storage를 target 밖에 두고 PRD는 receipt를 “tamper-evident” evidence로만 사용한다.
- `Open question` receipt signature는 threat-model review에서 별도 결정하며 authorization signature와 혼동하지 않는다.

### Low

#### `REV-L01` Severity 산정식의 구체적인 weight가 없다 — Intentionally deferred

- 영향 구간: `FR-703`
- `Inference` 현재 단계에서 CVSS 또는 독자 점수 weight를 고정하는 것보다 prerequisite, privilege, asset, effect와 reproducibility를 원자료로 보존하는 편이 낫다.
- 조치: Phase 1 schema specification에서 severity rubric을 만들되 단일 불투명 점수는 만들지 않는다.

## 3. Opposing hypotheses

### `OH-101` 일반 scanner와 human red team이면 충분하다

- 가능성: 기존 scanner가 project-only 문제를 대부분 찾고 SPEAR의 causal replay 비용이 이득보다 클 수 있다.
- 검증: 같은 project clone과 run budget에서 일반 response assertion, 고정 payload, SPEAR와 human red team의 unique proven chain 및 triage cost를 비교한다.
- 실패 조건: SPEAR 고유 finding 또는 재현 비용 절감이 없으면 독자 제품화를 중단한다.

### `OH-102` Canaries가 실제 exploitability를 과대평가한다

- 가능성: canary sink·fixture process는 실제 network, credential와 deployment 제약을 충분히 반영하지 못할 수 있다.
- 검증: canary가 실제 data class, authorization boundary와 sink semantics를 보존하는지 finding별 reviewer가 확인한다.
- 제한: canary proof를 실제 production compromise와 동일하다고 표현하지 않는다.

### `OH-103` Next.js/Supabase 특화는 시장을 지나치게 좁힌다

- 가능성: 초기 사용처는 좁아진다.
- 반대 근거: 현재 WIGTN 프로젝트와 직접 맞고 ground truth 구축 비용이 낮다.
- 결정: 한 framework에서 실제 non-seeded finding을 입증하기 전에 두 번째 framework를 추가하지 않는다.

### `OH-104` Independent witness가 제품 통합 비용을 과도하게 높인다

- 가능성: proxy, DB audit, filesystem/process와 identity witness 설치가 고객 환경에서 어려울 수 있다.
- 검증: Attack Twin에서 자동 준비율과 수동 단계 수, finding당 준비 시간을 측정한다.
- 실패 조건: witness 자동화 없이 전문가가 매번 환경을 수작업 구성해야 하면 제품이 아니라 연구 harness로 제한한다.

## 4. Traceability result

- 모든 Must 기능 영역에는 하나 이상의 observable acceptance criterion 또는 명시적 Phase exit가 있다.
- project-only와 compound finding은 `FR-455`에 의해 인과적으로 분리된다.
- static suspicion, target trace, LLM confidence는 proven 조건에서 제외됐다.
- cancellation, partial witness loss, snapshot mismatch, stale build와 utility regression 상태가 정상 취약점과 분리됐다.
- migration은 backward compatibility 대신 Phase 0 cutover로 명시됐다.

## 5. Final review verdict

### Facts

- `Fact` unresolved blocker는 없다.
- `Fact` Phase 0–1은 현재 repository와 WIGTN boilerplate를 기준으로 구현 범위와 검증 조건이 정의됐다.
- `Fact` Phase 2 이후의 adaptive superiority와 실제 고유 finding은 아직 입증되지 않았다.

### Inference

- `Inference` 이 PRD는 구현을 시작할 만큼 구체적이지만, “독자 제품이 된다”는 주장은 Phase 2–3 Go gate를 통과하기 전까지 유보해야 한다.

### Prioritized change proposal

1. `P0` signed authorization manifest와 disposable-only safety gate를 가장 먼저 구현한다.
2. `P0` Next.js/Supabase ground-truth lab과 reset digest를 만든다.
3. `P0` multi-principal BOLA/BFLA/RLS와 state witness를 end-to-end로 통과시킨다.
4. `P0` baseline/attack/counterfactual 판정과 finding state machine을 구현한다.
5. `P1` source-assisted graph search와 고정 payload baseline 비교를 수행한다.
6. `P1` agent gateway witness와 project-only/compound causal separation을 추가한다.
7. `Stop` 실제 non-seeded chain 또는 triage 이득이 없으면 범용 scanner 기능을 더 추가하지 않는다.
