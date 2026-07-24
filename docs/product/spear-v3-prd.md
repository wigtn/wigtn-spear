# SPEAR v3 PRD

상태: Draft after internal review  
기준일: 2026-07-23  
제품명: **SPEAR — Security Provenance-guided Exploit Attribution & Reproduction**

## 1. Context and problem

### Facts

- `Fact` 현재 SPEAR v2의 project runner는 운영자가 작성한 단일 HTTP 요청과 assertion을 재실행할 뿐, route·identity·state를 조합해 새로운 취약점을 탐색하지 않는다.
- `Fact` 현재 agent runner의 trace는 공격 대상 adapter가 제공하므로 독립적인 행동 증거가 아니다.
- `Fact` 현재 저장소는 Node.js 22와 TypeScript로 구성되며 agent verifier, HTTP runner, scope enforcement와 9개의 자동 테스트가 존재한다.
- `Fact` WIGTN core boilerplate의 실제 애플리케이션은 Next.js App Router, route handler, server action, Supabase SSR/Auth/RLS와 OpenAPI contract를 사용한다.
- `Fact` 웹·백엔드 취약점과 agent 취약점은 독립적으로 존재할 수 있지만, prompt-controlled tool argument가 취약한 backend sink에 도달할 때 하나의 compound exploit이 된다.

### Inferences

- `Inference` SPEAR가 일반 목적 SAST 또는 DAST의 탐지 개수를 경쟁하면 기존 전문 제품보다 약한 스캐너가 된다.
- `Inference` SPEAR의 고유 가치는 source-assisted mapping, stateful attack search, 독립 witness와 causal replay를 결합해 **실제로 악용 가능한 project-only 또는 agent-project 공격 사슬**을 입증하는 것이다.
- `Inference` 첫 구현은 WIGTN이 실제로 통제하는 TypeScript/Next.js/Supabase 계열 프로젝트에 집중해야 빠르게 ground truth와 실제 finding을 모두 확보할 수 있다.

## 2. Product thesis

SPEAR는 승인된 프로젝트의 소스·런타임·사용자 권한·에이전트 도구를 하나의 compound security graph로 만들고, 금지된 상태 변화까지 도달하는 공격 경로를 탐색한다.

Finding의 기본 단위는 문자열 패턴이나 안전하지 않은 응답이 아니라 다음 조건을 만족하는 **proven causal exploit chain**이다.

1. 공격자가 통제할 수 있는 source가 존재한다.
2. source에서 실제 capability 또는 backend sink까지 재현 가능한 경로가 존재한다.
3. 독립 witness가 금지된 상태 변화 또는 데이터 흐름을 관측한다.
4. benign baseline과 counterfactual replay에서는 같은 효과가 발생하지 않는다.
5. 공격 사슬이 disposable environment에서 반복 재현된다.

SPEAR는 두 실행 모드를 제공한다.

- **Project mode**: agent 없이 웹·API·백엔드 자체의 인증, 인가, 입력검증과 workflow 취약점을 탐색하고 입증한다.
- **Compound mode**: untrusted artifact 또는 사용자 입력이 agent 행동을 바꾸고 project 취약점까지 도달하는 전체 사슬을 탐색하고 입증한다.

### Coverage claim

SPEAR가 목표로 하는 “대부분의 제품”은 **disposable/test 환경으로 복제할 수 있는 browser, web, API, backend, worker, integration과 agent surface를 가진 서비스형 제품**이다. 구현 언어와 framework가 달라도 runtime protocol, identity fixture와 state witness를 연결할 수 있으면 black-box/gray-box attack pack을 적용할 수 있어야 한다. Source pack이 존재하면 white-box mapping과 sink-directed search를 추가한다.

어떤 surface도 조용히 “검사 완료”로 처리하지 않는다. Target별 coverage ledger가 surface마다 다음 상태를 기록해야 한다.

```text
discovered -> mapped -> attackable -> exercised -> witnessed -> proven|no-effect
                  \-> unsupported|blocked|not-applicable|error
```

`no finding`과 `secure`는 동의어가 아니다. 필수 surface가 `unsupported`, `blocked` 또는 `error`이면 SPEAR는 target 전체를 `coverage-incomplete`로 표시해야 한다.

## 3. Goals

- `G-101` 소스와 런타임 정보를 결합해 웹·백엔드의 공격 가능한 route, identity boundary, data flow와 sink를 구조화한다.
- `G-102` 다중 사용자·역할·tenant와 stateful request sequence를 이용해 project-only 보안 취약점을 능동 탐색한다.
- `G-103` agent의 입력·메모리·도구 호출이 backend 취약점과 연결되는 compound exploit chain을 탐색한다.
- `G-104` 독립 witness, canary와 three-way replay로 공격 입력과 실제 효과 사이의 인과관계를 입증한다.
- `G-105` finding을 최소 재현 사슬과 수정 후 회귀 테스트로 변환한다.
- `G-106` 모든 능동 테스트를 서명된 범위로 승인된 disposable/test target과 제한된 안전 예산 안에서 수행한다.
- `G-107` 제품의 protocol, identity, data, execution, integration과 deployment surface별 관측·공격 coverage와 blind spot을 정량적으로 보고한다.

## 4. Non-goals

- 인터넷 전체 자산 탐색, 대량 포트 스캔 또는 승인되지 않은 target 테스트
- 모든 언어와 framework를 지원하는 범용 SAST
- OWASP Top 10 payload를 무차별 발사하는 범용 DAST
- dependency CVE, secret inventory, malware, cloud posture와 container benchmark의 전면 재구현
- production 데이터 파괴, persistence, credential theft 또는 real-world egress
- LLM judge, target self-report 또는 static suspicion만으로 `proven` finding 발행
- zero-day 발굴 개수로 Big Sleep, AIxCC 또는 대규모 전문 시스템과 경쟁
- 초기 버전의 웹 대시보드, multi-organization SaaS 또는 실시간 runtime firewall
- native mobile/desktop client 내부, browser engine, kernel, firmware, embedded/OT와 smart contract 자체의 exploit discovery
- network perimeter, Kubernetes/cloud posture 전체와 memory-unsafe native binary의 전면 취약점 진단
- 모든 target에 모든 공격이 적용됐다는 근거 없는 “100% secure” 또는 “완전 커버” 판정

## 5. Users and key scenarios

### Users

- **Product security engineer**: 프로젝트 복제본에 공격 캠페인을 실행하고 재현 가능한 finding을 개발팀에 전달한다.
- **Agent security engineer**: coding/developer agent의 tool use가 프로젝트 권한 경계를 넘는지 검증한다.
- **Application developer**: 수정 전후에 최소 replay bundle을 실행해 보안 회귀를 확인한다.
- **Authorized red team operator**: scope, identity fixture, 금지 상태와 공격 예산을 정의하고 캠페인을 통제한다.
- **CI maintainer**: 기존 finding의 고정 replay만 실행해 재발 여부를 판정한다.

### Key scenarios

- `SC-101` 사용자 A의 object ID를 사용자 B 요청에 대입해 BOLA 또는 tenant isolation 실패를 찾는다.
- `SC-102` 일반 사용자와 관리자 route/action을 비교해 BFLA 또는 server action authorization 누락을 찾는다.
- `SC-103` agent-controlled URL, path, query, template 또는 command argument가 backend sink까지 도달하는지 canary로 검증한다.
- `SC-104` PR, issue, web page, tool result 또는 memory entry가 coding agent를 조종해 승인되지 않은 repository/CI/API action을 유발하는지 검증한다.
- `SC-105` 정상 workflow의 순서, actor, object 또는 idempotency key를 변형해 승인 우회, replay, mass assignment 또는 잘못된 상태 전이를 찾는다.
- `SC-106` 수정된 build에서 동일한 초기 snapshot과 최소 공격 사슬을 재실행해 forbidden state가 더 이상 발생하지 않는지 확인한다.
- `SC-107` OAuth/OIDC login, account recovery, MFA enrollment과 delegated scope를 actor·redirect·token binding별로 변형해 account takeover 또는 privilege confusion을 검증한다.
- `SC-108` GraphQL query/batch, WebSocket message, gRPC method와 async event를 동일 principal/asset graph에 연결해 protocol boundary의 인증·인가 누락을 찾는다.
- `SC-109` file upload → object storage → parser/worker → public retrieval 사슬을 변형해 traversal, type confusion, unsafe active content, parser egress와 decompression abuse를 canary로 검증한다.
- `SC-110` webhook, queue, scheduled job, retry/dead-letter와 third-party response를 조작해 signature bypass, duplicate side effect, unsafe API consumption과 confused deputy를 찾는다.
- `SC-111` cache key, proxy-normalization, concurrent request와 exception/fallback path를 변형해 cross-user disclosure, stale authorization, race와 fail-open 상태를 검증한다.

## 6. Definitions, finding and coverage states

| Term | Definition |
|---|---|
| `Attack Twin` | 실제 target의 build, principal, state와 capability를 제한된 canary 환경에 재현한 disposable test environment |
| `Compound Security Graph` | principal, authority, artifact, route, tool, state, data와 sink를 typed node/edge로 표현한 graph |
| `Witness` | target self-report와 독립적으로 network, process, filesystem, database, browser, memory 또는 identity event를 수집하는 관측점 |
| `State Oracle` | 관측된 상태가 사전에 선언된 forbidden predicate를 만족하는지 결정론적으로 판단하는 함수 |
| `Counterfactual` | target state와 정상 task를 유지하고 특정 adversarial influence만 제거하거나 약화한 실행 |
| `Attack Program` | principal, precondition, state, mutation, expected flow와 oracle을 선언한 실행 가능한 공격 정의 |
| `Evidence Bundle` | snapshot, build, graph, receipts, state diff, replay와 remediation을 포함한 finding artifact |
| `Target Pack` | 특정 protocol, framework, identity provider, data store 또는 execution surface를 map·mutate·witness·reset하는 독립 SPEAR extension |
| `Coverage Ledger` | 발견된 surface별 applicability, mapper, attack family, oracle, 실행 결과와 blind spot을 기록한 artifact |
| `Coverage Claim` | ledger와 evidence grade로 뒷받침되는 범위 한정 보안 주장 |

Finding 상태:

- `candidate`: mapper 또는 search가 생성했지만 실제 효과가 입증되지 않았다.
- `proven`: independent witness, state oracle와 three-way replay 조건을 통과했다.
- `rejected`: baseline 또는 counterfactual에서도 발생하거나 forbidden predicate를 충족하지 않았다.
- `flaky`: 공격 효과가 반복 기준을 충족하지 못했다.
- `error`: 환경, fixture 또는 witness 실패로 판정할 수 없다.
- `fixed`: 수정 build의 replay에서 공격 효과가 사라지고 benign utility가 유지된다.

`candidate`, `flaky`, `error`는 `proven vulnerability`로 외부 보고하지 않는다.

Coverage/run 상태:

- `coverage-complete`: target policy가 요구한 surface, pack, witness와 evidence grade가 모두 충족됐다.
- `coverage-incomplete`: 하나 이상의 필수 surface가 `unsupported`, `blocked`, `error`이거나 required invariant/witness가 없다.
- `not-applicable`: discovery evidence와 명시적 이유로 해당 pack이 surface에 적용되지 않는다.
- `no-effect`: attack은 정상 실행됐지만 forbidden predicate가 관측되지 않았다. 이는 해당 실행 범위의 결과일 뿐 target이 안전하다는 선언이 아니다.

## 7. Initial technical scope

### Universal runtime profile

언어와 framework에 독립적인 runtime core는 다음 surface를 발견하고 attack pack 적용 가능성을 판정해야 한다.

- browser navigation, form, DOM, storage, cookie, service worker와 cross-origin request
- HTTP/1.1·HTTP/2 REST/JSON, OpenAPI 3.x, GraphQL, WebSocket, gRPC와 SOAP/XML
- session, API key, OAuth 2.0/OIDC, JWT, service account와 delegated token
- relational/document database, cache, queue, object storage와 filesystem
- synchronous API, webhook, worker, scheduled job, retry/dead-letter와 event-driven function
- outbound HTTP/RPC, third-party integration, signed URL와 callback
- source repository, build artifact, CI job와 deployment simulator
- SPEAR gateway/proxy를 통해 호출 가능한 coding/developer agent

### Source-aware profiles

Source pack은 universal runtime core를 대체하지 않고 graph edge와 directed-search feedback을 추가한다.

| Priority | Source pack |
|---|---|
| P0 | TypeScript/JavaScript, Node.js 22+, Next.js App Router, Supabase/Postgres/RLS |
| P1 | Express, Fastify, NestJS, Hono와 generic Node worker |
| P1 | Python FastAPI, Django와 Flask |
| P2 | Java/Kotlin Spring Boot |
| P2 | Go `net/http`, Gin과 Echo |

지원하지 않는 language/framework에서도 OpenAPI, traffic capture, browser crawl, protocol schema와 operator fixture가 있으면 runtime pack을 실행할 수 있어야 한다. Source pack 부재는 ledger에 white-box blind spot으로 남긴다.

### Target pack contract

각 pack은 다음 capability 중 자신이 지원하는 항목과 version을 선언해야 한다.

- `discover`: endpoint, operation, message, state, identity와 dependency surface 발견
- `map`: graph node/edge 및 source/runtime provenance 생성
- `seed`: 적용 가능한 attack program과 precondition 생성
- `mutate`: protocol-aware/state-aware mutation
- `execute`: scope와 budget을 지키는 request/event/action 실행
- `witness`: 독립 side effect와 state change 관측
- `reset`: pack이 관리한 state를 snapshot으로 복원
- `minimize`: protocol artifact와 state step 축소

pack은 success oracle을 임의의 LLM 판정으로 구현할 수 없고, 미지원 capability와 version mismatch를 명시적으로 반환해야 한다.

### Initial vulnerability families

| Priority | Area | Families |
|---|---|---|
| P0 | Authentication/session | unauthenticated access, session mix-up, stale/revoked session acceptance |
| P0 | Authorization | BOLA/IDOR, BFLA, cross-tenant access, role/object substitution, delegated identity confusion, server action authorization omission |
| P0 | Input to dangerous sink | SSRF to owned canary endpoint, path traversal in disposable filesystem, command/argument injection in sandbox, SQL/query filter manipulation against fixture data |
| P0 | Data exposure | cross-user/tenant disclosure, secret canary exposure, debug/error leakage, unauthorized file or object storage access |
| P0 | Workflow/business logic | mass assignment, invalid state transition, replay/idempotency failure, approval bypass, webhook/CI trust failure |
| P0 | Agent-project compound | indirect injection, role confusion, tool result poisoning, memory poisoning, approval spoofing or conjunctive trigger reaching any P0 project family above |
| P1 | Agent capability lifecycle | tool metadata/schema shadowing, confused-deputy selection, malicious external resource, capability drift and post-approval rug pull |
| P1 | Agent memory/provenance | poisoned write, summarization/embedding provenance loss, retrieval-time role collapse, sleeper activation and cross-agent handoff |
| P1 | Contextual privacy and composition | cross-tool/session context stealing, parasitic parameter, permitted-flow mixing, recipient/purpose norm violation and derived sensitive disclosure |
| P1 | Agent propagation | poisoned output copied through agent message, RAG, email, repository or memory and reactivated across bounded hops |
| P2 | Agent/model supply-chain behavior | model/provider/adapter/prompt version substitution, semantic trigger backdoor and compromised tool-use policy |
| P2 | Agent traffic side channel | sensitive task or user-trait inference from destination, timing, size and routing metadata without payload access |
| P1 | Browser-enforced controls | CSRF, reflected/stored DOM-observable XSS and unsafe browser navigation against an isolated canary origin |
| P1 | Federated identity | OAuth/OIDC redirect and state confusion, PKCE/nonce weakness, token audience/scope confusion, account linking/recovery and MFA lifecycle abuse |
| P1 | Modern API protocols | GraphQL node/edge authorization, batching/complexity abuse, WebSocket origin/session/message authorization, gRPC method/message/stream authorization |
| P1 | File and parser chain | extension/MIME/signature confusion, filename/path overwrite, unsafe public retrieval, archive traversal/bomb, XXE, parser-triggered SSRF and active content |
| P1 | Async and integration | webhook signature/replay, queue/worker identity loss, scheduled-job privilege, retry/dead-letter abuse and unsafe third-party API consumption |
| P1 | Cache and concurrency | cache key confusion/poisoning/deception, stale authorization, duplicate spending/action, TOCTOU and race-window state corruption |
| P1 | Resource and exception | bounded query/message/upload expansion, rate/quota bypass, fail-open exception, partial transaction and fallback authorization bypass |
| P1 | Configuration and cryptographic boundary | TLS/cookie/CORS/header policy, JWT algorithm/key/issuer/audience handling, key/token rotation, debug/default configuration and sensitive error behavior |
| P2 | Delivery and supply chain reachability | CI poisoned execution, artifact integrity failure, untrusted build input, deploy authorization and reachable vulnerable dependency chain |
| P2 | Cloud/serverless application edge | event-source spoofing, over-privileged function identity, object storage/signed URL isolation and metadata/service credential reachability |
| P2 | Audit and detection integrity | missing security event, sensitive log exposure, log injection, actor/correlation loss and audit tampering |
| P2 | Dedicated HTTP edge | host/routing confusion, inconsistent normalization and request desynchronization inside a fully isolated proxy-origin Twin |
| P2 | Legacy web service | SOAP action/method authorization, XML schema/signature handling, entity expansion/XXE and message-size/resource boundary |
| P2 | Intermediary differential | WAF/API gateway/proxy/origin disagreement over decoding, parameter structure, content type and request boundaries |

### Deferred families

- low-level memory corruption and native binary exploitation
- browser engine exploitation
- cloud control-plane exploitation
- password brute force and credential stuffing
- third-party targets outside an explicitly cloned engagement
- volumetric denial of service, internet-scale enumeration and unrestricted request smuggling against shared infrastructure
- malware detonation, anti-virus replacement and arbitrary hostile document execution outside a dedicated parser sandbox

## 8. Functional requirements

### 8.1 Authorization and engagement

| ID | Requirement | Priority |
|---|---|---|
| `FR-101` | 시스템은 engagement ID, owner, exact repository path, commit/build digest, allowed origin, expiry, environment class와 허용 attack capability를 포함한 authorization manifest를 요구해야 한다. | Must |
| `FR-102` | active campaign은 유효한 authorization manifest와 실행 시점 operator acknowledgement가 모두 없으면 target process 또는 network에 접근하지 않아야 한다. | Must |
| `FR-103` | 초기 release의 active campaign은 `disposable` 또는 전용 `test` environment만 허용하고 production-class target은 read-only 여부와 관계없이 거부해야 한다. | Must |
| `FR-104` | 모든 run은 authorization manifest digest와 target build digest를 evidence에 기록해야 한다. | Must |
| `FR-105` | authorization manifest는 engagement owner의 Ed25519 signature와 key ID를 포함하고 runner는 engagement trust store의 활성 public key로 signature, key revocation, expiry와 capability scope를 검증해야 한다. | Must |

### 8.2 Mapping and graph construction

| ID | Requirement | Priority |
|---|---|---|
| `FR-201` | mapper는 지원 대상 소스에서 HTTP route, server action, middleware, authentication check, authorization check, data access와 dangerous sink 후보를 추출해야 한다. | Must |
| `FR-202` | mapper는 OpenAPI, runtime route inventory와 operator-supplied fixtures를 source map과 병합하고 각 edge에 출처와 confidence를 기록해야 한다. | Must |
| `FR-203` | mapper는 principal, role, tenant, object ownership, token/scope와 agent capability를 graph node 및 typed edge로 표현해야 한다. | Must |
| `FR-204` | static 추론만으로 발견한 sink 또는 누락된 check는 `candidate`로만 기록하고 vulnerability로 확정하지 않아야 한다. | Must |
| `FR-205` | map artifact는 schema version, source/build digest와 extraction diagnostics를 포함하고 동일 build에서 재사용 가능해야 한다. | Should |
| `FR-206` | Supabase target에서 mapper는 migration의 table, function, RLS enablement, policy, storage policy와 service-role 사용 후보를 추출해 application route 및 data access edge와 연결해야 한다. | Must |
| `FR-207` | discovery는 browser crawl, traffic capture, OpenAPI/GraphQL/protobuf schema, WebSocket upgrade, source, deployment manifest와 operator fixture를 병합해 target surface inventory를 생성해야 한다. | Must |
| `FR-208` | 각 discovered surface는 protocol, entry point, principals, data class, state dependency, applicable packs와 mapping source를 coverage ledger에 가져야 한다. | Must |
| `FR-209` | mapper는 HTTP request에서 async event, worker, database/cache/object storage, outbound integration과 response까지 correlation ID 또는 canary provenance로 graph edge를 연결해야 한다. | Must |
| `FR-210` | source나 schema가 없는 dynamic surface는 runtime-observed edge로 표시하고 추론하지 못한 parameter·message field를 blind spot으로 남겨야 한다. | Must |
| `FR-211` | dependency, CI/IaC와 configuration 분석 결과는 reachable source/sink 또는 runtime effect가 입증되기 전까지 inventory/candidate evidence로만 취급해야 한다. | Must |
| `FR-212` | coverage ledger는 discovered surface가 누락 없이 `exercised`, `not-applicable`, `unsupported`, `blocked` 또는 `error` 중 하나로 종료됐는지 검증해야 한다. | Must |
| `FR-213` | state learner는 benign trace와 state digest에서 protocol/workflow의 observed state machine을 추론하고 underexplored transition, unexpected equivalence와 specification deviation을 candidate로 생성해야 한다. | Should |
| `FR-214` | learned state와 transition은 source/specification truth로 간주하지 않고 provenance, observation count, nondeterminism과 counterexample을 기록해야 한다. | Must |

### 8.3 Attack Twin and fixtures

| ID | Requirement | Priority |
|---|---|---|
| `FR-301` | Attack Twin은 최소 anonymous, user-A, user-B, privileged principal과 두 tenant/repository를 준비할 수 있어야 한다. | Must |
| `FR-302` | 각 asset fixture는 owner, tenant, classification, lifecycle과 unique canary를 가져야 한다. | Must |
| `FR-303` | runner는 campaign 시작 전 baseline snapshot을 만들고 각 causal replay 전에 DB, repository, memory, queue와 filesystem을 같은 상태로 복원해야 한다. | Must |
| `FR-304` | fixture 준비 또는 reset 검증에 실패하면 campaign을 `error`로 종료하고 attack을 계속하지 않아야 한다. | Must |
| `FR-305` | canary egress는 engagement가 소유한 sink로만 허용하며 public internet 목적지를 허용하지 않아야 한다. | Must |
| `FR-306` | Twin은 identity provider, browser profile, cache, queue/dead-letter, object storage, webhook receiver와 clock을 fixture 또는 controlled adapter로 제공해야 한다. | Should |
| `FR-307` | Twin은 timeout, dependency error, retry, duplicate event, out-of-order delivery, stale cache와 partial transaction을 deterministic fault schedule로 주입할 수 있어야 한다. | Should |
| `FR-308` | concurrent attack은 각 actor의 barrier, send order와 observed commit order를 기록하고 동일 schedule 또는 bounded permutation으로 replay할 수 있어야 한다. | Should |
| `FR-309` | file/parser test는 archive expansion, parser process, temporary storage와 outbound network가 제한된 별도 sandbox에서 실행되어야 한다. | Must |

### 8.4 Attack program and project discovery

| ID | Requirement | Priority |
|---|---|---|
| `FR-401` | attack program은 payload 목록이 아니라 principal, precondition, carrier, source, capability, state mutation, forbidden predicate와 oracle을 선언해야 한다. | Must |
| `FR-402` | project mode는 mapper가 필요한 source/runtime edge를 확보한 P0 family에 대해 source-assisted candidate를 생성하고 실행 전 operator에게 선택된 route, actor, mutation과 expected effect를 표시해야 한다. | Must |
| `FR-403` | runner는 cookie/token jar, extracted response value, CSRF token, object ID, idempotency key와 tenant context를 단계 사이에 전달하는 stateful request sequence를 실행해야 한다. | Must |
| `FR-404` | authorization test는 동일한 operation/object에 대해 최소 두 principal 또는 두 tenant의 paired request를 지원해야 한다. | Must |
| `FR-405` | injection test는 real secret 또는 external victim 대신 canary network, fixture database, disposable filesystem과 sandbox process effect를 사용해야 한다. | Must |
| `FR-406` | browser-backed test는 isolated browser context에서 DOM execution, cookie/state mutation과 network egress를 witness하고 외부 navigation을 차단해야 한다. | Should |
| `FR-407` | search는 새 graph edge, authority transition, persistent state, data-flow sink와 forbidden predicate distance를 feedback으로 candidate 우선순위를 갱신해야 한다. | Should |
| `FR-408` | LLM이 attack seed 또는 mutation을 제안하더라도 성공 판정과 publish decision은 deterministic oracle과 replay 결과로만 결정해야 한다. | Must |
| `FR-409` | attack pack은 applicability precondition, required fixture/witness, safe mutation grammar, forbidden predicates, cleanup과 standards mapping을 versioned manifest로 선언해야 한다. | Must |
| `FR-410` | identity pack은 session, OAuth/OIDC/JWT, account recovery, MFA, API key와 delegated token에 대해 actor/client/redirect/audience/issuer/scope/lifecycle 변형을 지원해야 한다. | Should |
| `FR-411` | protocol pack은 REST/OpenAPI, GraphQL, WebSocket, gRPC와 SOAP/XML operation/message를 principal, object와 state graph에 연결하고 protocol-aware replay를 지원해야 한다. | Should |
| `FR-412` | interpreter pack은 SQL/NoSQL/ORM, command/argument, path, URL, template, header/CRLF, XML/XXE와 unsafe deserialization candidate를 context-aware mutation과 canary effect로 검증해야 한다. | Should |
| `FR-413` | file pack은 upload, storage, processing, transformation과 retrieval 전 단계를 연결하고 filename, type, signature, archive, parser와 authorization mutation을 지원해야 한다. | Should |
| `FR-414` | workflow pack은 state transition, property authorization, quota, idempotency, retry, cancellation, concurrent actor와 TOCTOU schedule을 mutation해야 한다. | Must |
| `FR-415` | async/integration pack은 webhook signature/timestamp, queue actor context, event schema, retry/dead-letter, callback과 third-party response trust를 mutation해야 한다. | Should |
| `FR-416` | cache/proxy pack은 cache key composition, normalized path/header/query, authenticated response sharing, stale authorization과 response variant isolation을 검증해야 한다. | Should |
| `FR-417` | resource pack은 twin에 선언된 CPU, memory, query complexity, message, upload expansion과 rate/quota budget 안에서만 bounded exhaustion test를 실행해야 한다. | Should |
| `FR-418` | exception pack은 dependency failure, timeout, parse error, partial commit과 fallback에서 authentication, authorization, integrity 또는 disclosure predicate가 fail-open 되는지 검증해야 한다. | Must |
| `FR-419` | delivery pack은 untrusted source/PR/dependency/artifact가 CI execution 또는 deployment authority까지 도달하는 경로를 canary build artifact와 disposable runner에서 검증해야 한다. | Could |
| `FR-420` | attack scheduler는 target에 적용 가능한 pack 조합을 graph path로 구성해 단일 pack 결과뿐 아니라 multi-pack chain을 탐색해야 한다. | Should |
| `FR-421` | business-logic surface는 schema, tests, domain events와 operator fixture에서 허용 상태 전이, value/ownership constraint와 side-effect cardinality invariant를 가져야 하며, usable invariant가 없으면 해당 surface를 coverage gap으로 표시해야 한다. | Must |
| `FR-422` | configuration/crypto pack은 TLS, cookie, CORS, security header, JWT algorithm/key/issuer/audience, token lifecycle, debug/default setting과 sensitive exception disclosure를 target profile에 맞게 검증해야 한다. | Should |
| `FR-423` | audit pack은 privileged action, identity/authorization failure, secret/data access와 configuration change에 actor, target, result와 correlation event가 남는지 검증하고 sensitive value 및 log injection effect를 탐지해야 한다. | Could |
| `FR-424` | HTTP-edge pack은 dedicated proxy-origin Twin에서만 host/routing, ambiguous length/transfer framing과 normalization differential을 실행하고 shared ingress 또는 production network에서는 거부해야 한다. | Could |
| `FR-425` | cloud/serverless application pack은 disposable emulator 또는 격리된 test account에서 event source, function/service identity, object key/signed URL, outbound call과 metadata credential reachability를 graph와 canary로 검증해야 한다. | Could |
| `FR-426` | source-aware injection pack은 source→transform/sanitizer→sink 경로를 보존하는 local test harness를 만들고 interpreter feedback과 canary effect로 sanitizer-evasion candidate를 진화시킬 수 있어야 한다. | Should |
| `FR-427` | intermediary-differential pack은 WAF/API gateway/proxy/origin이 같은 request를 어떻게 decode·normalize·route하는지 독립 view로 비교하고 disagreement가 authorization 또는 sink bypass로 이어질 때만 finding candidate로 승격해야 한다. | Could |

### 8.5 Compound agent-project discovery

| ID | Requirement | Priority |
|---|---|---|
| `FR-451` | compound mode는 issue, PR, web content, tool result, file와 memory entry를 untrusted carrier로 주입할 수 있어야 한다. | Must |
| `FR-452` | compound mode는 carrier influence에서 agent plan, tool/API call, backend route/sink와 forbidden state까지의 graph path를 하나의 candidate로 연결해야 한다. | Must |
| `FR-453` | agent가 제공하는 trace는 reference evidence로만 저장하고 tool/API/process/database witness와 불일치할 때 independent witness를 우선해야 한다. | Must |
| `FR-454` | mutation은 wording뿐 아니라 role style, source provenance, actor, tenant, scope, tool schema/result, ordering, retry, failure와 cross-session timing을 다룰 수 있어야 한다. | Should |
| `FR-455` | compound finding은 project-only replay도 함께 수행해 agent influence가 필요한지, backend 취약점만으로 가능한지 구분해야 한다. | Must |
| `FR-456` | agent pack은 tool/server identity, namespace, description, schema, resource URI, registry endpoint와 capability digest를 connection/approval/execution 시점마다 snapshot하고 shadowing, puppet selection, malicious resource와 rug-pull drift를 mutation해야 한다. | Must |
| `FR-457` | memory pack은 raw evidence, derived claim, trust/role, writer principal, session과 expiry provenance가 write, summarization, embedding, retrieval, compaction과 inter-agent handoff에서 유지되는지 검증해야 한다. | Must |
| `FR-458` | memory attack은 injection과 activation을 분리하고 configurable session/time/tool-hop 뒤 sleeper effect 및 benign-memory utility를 paired replay해야 한다. | Should |
| `FR-459` | propagation pack은 canary instruction 또는 data가 agent output, message, RAG, email, repository와 memory를 통해 다른 principal/agent로 복제·재활성화되는 경로와 hop별 blast radius를 관측해야 한다. | Should |
| `FR-460` | execution-authority test는 동일 natural-language content에 authenticated actor, delegated scope, target resource와 trusted policy metadata를 독립적으로 바꿔 action이 문체/주장보다 execution metadata에 결속되는지 검증해야 한다. | Must |
| `FR-461` | contextual-flow pack은 개별적으로 허용된 source/recipient/purpose flow의 조합, cross-tool parasitic parameter와 derived claim이 선언된 privacy norm 또는 data-use policy를 위반하는지 검증해야 한다. Usable policy가 없으면 해당 flow를 coverage gap으로 표시해야 한다. | Should |
| `FR-462` | model-supply-chain research pack은 model/provider/adapter/prompt/policy digest를 고정하고 controlled backdoored fixture와 semantic-trigger corpus에서 tool/data-flow behavior differential을 관측해야 한다. Unknown black-box backdoor를 찾았다고 증거 없이 주장하지 않아야 한다. | Could |
| `FR-463` | traffic-side-channel research pack은 payload를 보지 못하는 observer 관점에서 destination, timing, size와 routing metadata만으로 canary task/trait class를 추론할 수 있는지 paired workload와 held-out evaluation으로 측정해야 한다. Campaign은 classifier, split, metric, baseline과 candidate threshold를 실행 전에 고정해야 한다. | Could |

### 8.6 Witness and state oracle

| ID | Requirement | Priority |
|---|---|---|
| `FR-501` | 시스템은 최소 HTTP/tool gateway, database audit, filesystem/process와 canary sink witness를 target process 밖에서 수집해야 한다. | Must |
| `FR-502` | agent approval·delegation을 검증하는 시나리오는 approver identity, granted scope, target action과 decision time을 독립 event로 기록해야 한다. | Must |
| `FR-503` | 각 witness event는 run ID, source, monotonic sequence, timestamp, build digest, redacted payload digest와 previous-event hash를 포함해야 한다. | Must |
| `FR-504` | state oracle은 HTTP 응답 문자열뿐 아니라 object ownership, row/file diff, process execution, outbound canary, browser effect와 approval state를 판정할 수 있어야 한다. | Must |
| `FR-505` | witness 손실, 순서 불일치 또는 snapshot digest 불일치는 vulnerability가 아니라 `error` 또는 `flaky`로 판정해야 한다. | Must |
| `FR-506` | witness mesh는 적용 surface에 따라 browser, identity provider, cache, queue, object storage, webhook, application/security audit, cloud audit와 CI artifact event를 수집할 수 있어야 한다. | Should |
| `FR-507` | differential oracle은 동일 operation을 actor, role, tenant, object, protocol 또는 timing만 바꿔 실행하고 response와 independent state의 차이를 비교해야 한다. | Must |
| `FR-508` | resource oracle은 latency 한 건이 아니라 target container의 CPU/memory, queue depth, worker count와 recovery를 관측하고 hard budget 도달 전에 실행을 중단해야 한다. | Should |
| `FR-509` | exception oracle은 error response와 함께 transaction, outbox, cache, file와 authorization state의 partial effect를 관측해야 한다. | Must |
| `FR-510` | coverage proof는 각 exercised surface에 사용한 attack pack version, mutations, principals, oracle, witness health와 결과를 연결해야 한다. | Must |
| `FR-511` | witness mesh는 tool capability snapshot, memory transformation lineage, inter-agent message parent와 propagation hop을 target self-report 밖의 receipt로 연결해야 한다. | Should |
| `FR-512` | contextual-flow oracle은 source, subject, data class, derived claim, recipient, purpose와 transmission principle을 비교하고 단순 문자열 유출과 허용된 개별 flow의 위험한 조합을 구분해야 한다. | Should |

### 8.7 Causality, reproduction and minimization

| ID | Requirement | Priority |
|---|---|---|
| `FR-601` | candidate는 동일 initial snapshot에서 benign baseline, attack과 counterfactual을 실행해야 한다. | Must |
| `FR-602` | `proven` 판정은 attack에만 forbidden predicate가 나타나고, 사전 설정한 반복 기준을 만족하며, authorization witness가 action을 허용하지 않았을 때만 가능해야 한다. | Must |
| `FR-603` | project-only candidate는 최소 2회 중 2회, 비결정적 agent가 포함된 candidate는 최소 3회 중 2회 이상 attack predicate가 재현되어야 하며, campaign은 이보다 엄격한 threshold만 설정할 수 있어야 한다. Evidence는 전체 시도와 실제 성공 횟수를 기록해야 한다. | Must |
| `FR-604` | minimizer는 prompt token만이 아니라 artifact, principal, state setup, request/tool step, permission과 mutation을 제거하며 predicate가 유지되는 최소 causal chain을 찾아야 한다. | Should |
| `FR-605` | fixed-build replay는 동일 benign task가 성공하는지와 attack predicate가 사라졌는지를 별도로 판정해야 한다. | Must |

### 8.8 Findings and evidence

| ID | Requirement | Priority |
|---|---|---|
| `FR-701` | proven finding은 title, severity rationale, affected build, attack precondition, minimized graph path, forbidden predicate, reproduction rate와 remediation hypothesis를 포함해야 한다. | Must |
| `FR-702` | evidence bundle은 authorization/build/snapshot digest, attack program, baseline·attack·counterfactual receipt, state diff, replay command와 redaction manifest를 포함해야 한다. | Must |
| `FR-703` | severity는 attacker prerequisite, required privilege, affected asset, state effect, cross-tenant/secret/RCE impact와 reproducibility에서 결정하고 LLM이 단독 결정하지 않아야 한다. | Must |
| `FR-704` | candidate, rejected, flaky와 error는 proven finding과 분리 출력하고 CI 차단 기본값에 포함하지 않아야 한다. | Must |
| `FR-705` | output은 versioned JSON과 사람이 읽는 Markdown을 제공해야 하며, fixed finding은 동일 ID와 lineage를 유지해야 한다. | Must |
| `FR-706` | report는 vulnerability finding과 별도로 coverage ledger, unsupported/blocked/error surface, source/runtime blind spot과 pack applicability를 첫 페이지에 요약해야 한다. | Must |
| `FR-707` | 시스템은 target 전체에 `secure` verdict를 발행하지 않고, 각 coverage claim을 build, surface, pack version과 evidence grade에 한정해야 한다. | Must |

### 8.9 Safety, privacy and execution control

| ID | Requirement | Priority |
|---|---|---|
| `FR-801` | network proxy는 exact origin과 owned canary sink 외의 egress를 기본 차단하고 redirect, DNS rebinding과 private metadata destination을 거부해야 한다. | Must |
| `FR-802` | campaign은 request, token, wall-clock, concurrency, response bytes, process time와 disk mutation budget을 가져야 한다. | Must |
| `FR-803` | destructive operation은 fixture resource로 제한하고 삭제·결제·실제 메시지 전송·배포·credential rotation을 기본 금지해야 한다. | Must |
| `FR-804` | runner는 authorization header, cookie, token, source secret과 개인정보를 evidence에서 기본 redaction하며 canary value는 digest와 label로 표현해야 한다. | Must |
| `FR-805` | 취소 또는 budget 초과 시 새 작업을 중단하고 진행 중 작업을 종료한 뒤 twin을 reset하거나 명시적 recovery-required 상태로 남겨야 한다. | Must |
| `FR-806` | 동일 attack step의 retry는 idempotency key와 attempt number를 기록하고 duplicate side effect를 별도 predicate로 관측해야 한다. | Should |
| `FR-807` | race/resource/cache/proxy/file-parser pack은 shared production infrastructure에서 실행할 수 없고 disposable Twin capability attestation이 없으면 거부해야 한다. | Must |
| `FR-808` | file payload는 inert canary corpus만 사용하고 malware, live exploit document와 host-executable binary를 생성하거나 외부 분석 서비스로 전송하지 않아야 한다. | Must |
| `FR-809` | credential lifecycle test는 fixture account/token만 사용하고 real MFA device, payment, email/SMS recipient 또는 third-party identity를 호출하지 않아야 한다. | Must |
| `FR-810` | protocol/client pack은 redirect, callback, DNS resolution과 connection upgrade 후에도 engagement egress policy를 재검증해야 한다. | Must |
| `FR-811` | cloud/serverless test는 manifest에 명시된 emulator 또는 isolated test account/resource prefix 밖의 API call과 mutation을 거부해야 한다. | Must |
| `FR-812` | propagation 및 sleeper campaign은 최대 agent/principal 수, propagation hop, session horizon, artifact write 수와 owned sink를 manifest에 고정하고 self-replicating payload를 Twin 밖으로 내보내지 않아야 한다. | Must |

### 8.10 CLI and integration contract

| ID | Requirement | Priority |
|---|---|---|
| `FR-901` | CLI는 `map`, `twin prepare`, `run project`, `run compound`, `replay`, `verify-fix` lifecycle을 명시적으로 구분해야 한다. | Must |
| `FR-902` | active 명령은 preview/dry-run에서 target, principals, capabilities, mutations, budgets와 expected forbidden predicate를 보여줘야 한다. | Must |
| `FR-903` | CI에서는 새 adaptive campaign이 아니라 승인된 evidence bundle의 deterministic replay를 기본 실행해야 한다. | Must |
| `FR-904` | schema version 불일치, stale build, stale fixture 또는 unsupported target construct를 명시적 error로 보고해야 한다. | Must |
| `FR-905` | CLI는 `discover`와 `coverage` 명령으로 surface inventory, applicable/missing pack, witness readiness와 blind spot을 active attack 전에 보여줘야 한다. | Must |
| `FR-906` | pack registry는 trust store의 활성 Ed25519 key로 registry signature를 검증하고, 각 declarative pack의 pack ID, schema/API version, supported target versions, capabilities, safety class와 canonical descriptor integrity digest를 검증해야 한다. 동적 executable pack loading은 별도 sandbox contract 전까지 허용하지 않는다. | Must |
| `FR-907` | operator는 target profile의 필수 surface와 최소 evidence grade를 policy로 선언할 수 있고 미충족 시 run을 coverage failure로 종료할 수 있어야 한다. | Must |
| `FR-908` | 기존 run과 비교할 때 새/제거/변경 surface, coverage regression, pack version drift와 finding lineage를 diff로 제공해야 한다. | Should |
| `FR-909` | CLI는 success `0`, proven finding `1`, validation/safety/execution error `2`, finding 수와 무관한 coverage failure `3`을 안정적인 exit-code contract로 사용해야 한다. | Must |

## 9. Data model

| Entity | Required identity and relationships |
|---|---|
| `Engagement` | engagement ID, authorization digest, owner, expiry, environment class |
| `TargetBuild` | repository digest, commit, dependency lock digest, runtime/model/tool/policy versions |
| `Principal` | principal ID, role, tenant, credentials fixture reference, delegated authority |
| `Asset` | asset ID, owner, tenant, classification, canary label |
| `GraphNode/Edge` | typed ID, source evidence, confidence, build digest |
| `Surface` | stable surface ID, protocol/type, entry point, principals, data/state dependencies, discovery sources |
| `TargetPack` | pack ID/version, API schema, capabilities, supported target versions, safety class, integrity digest |
| `CoverageCell` | target build, surface ID, pack, applicability, execution state, oracle/witness health, evidence grade |
| `DomainInvariant` | invariant ID, affected surface/state, precondition, allowed transition/value/cardinality, source and owner approval |
| `AttackProgram` | scenario ID, principals, preconditions, steps, mutations, predicates, budget |
| `Snapshot` | snapshot ID, component digests, creation/reset verification |
| `WitnessReceipt` | run ID, sequence, source, event type, payload digest, previous hash |
| `Run` | baseline/attack/counterfactual kind, snapshot, build, status, attempts |
| `Finding` | stable ID, state, graph path, oracle, impact, evidence bundle, lineage |

원본 credential과 실제 secret은 이 모델에 저장하지 않고 external fixture provider 또는 process environment reference로만 다룬다.

## 10. UX, roles, commands and states

초기 제품은 로컬 CLI와 artifact를 사용하며 웹 UI를 만들지 않는다.

```text
discover
  -> inventory-ready | discovery-error
coverage
  -> coverage-complete | coverage-incomplete
map
  -> graph-ready | map-error
twin prepare
  -> ready | fixture-error | containment-error
run project|compound
  -> preview -> authorized -> running
  -> candidate -> proving -> proven|rejected|flaky
  -> cancelled|budget-exhausted|error|recovery-required
replay
  -> reproduced|not-reproduced|stale|error
verify-fix
  -> fixed|still-vulnerable|utility-regression|error
```

권한:

- engagement owner만 trust store에 등록된 private key로 authorization manifest를 서명하거나 만료 manifest를 발급할 수 있다.
- operator는 manifest 범위 안에서 campaign을 실행할 수 있다.
- CI principal은 서명 또는 digest로 고정된 replay bundle만 실행할 수 있다.
- target agent는 engagement scope를 확대하거나 witness 설정을 변경할 수 없다.

## 11. Non-functional requirements

### Determinism and reproducibility

- schema validation, graph/surface identity, pack applicability, state oracle, receipt hashing과 finding classification은 같은 artifact에서 결정론적이어야 한다.
- model behavior가 비결정적일 때 반복 횟수, 성공 비율과 모델 설정을 함께 보고해야 한다.
- replay는 original build가 아니면 stale 상태를 표시하고 자동으로 동일 결과를 주장하지 않아야 한다.

### Isolation and security

- host process execution이 가능한 attack은 rootless container 이상에서만 수행한다.
- container escape 위험을 다루는 단계에서는 microVM을 별도 delivery gate로 검토한다.
- witness control plane과 evidence storage는 target process가 쓸 수 없는 경계에 둔다.
- egress proxy가 준비되지 않으면 SSRF, command execution과 agent exfiltration campaign을 시작하지 않는다.
- pack은 최소 권한 worker에서 실행하고 core trust store에 등록된 integrity digest와 API version이 일치하지 않으면 load하지 않는다.

### Reliability and recovery

- 일부 witness 또는 target component 실패를 정상적인 보안 실패로 오판하지 않는다.
- run cancellation, timeout과 crash 후 fixture integrity를 검증하며 불명확하면 자동 재사용하지 않는다.
- 동일 snapshot을 공유하는 campaign은 직렬 실행하거나 격리된 clone을 사용한다.

### Privacy and retention

- raw prompt, response, HTTP body와 database diff는 기본적으로 evidence에 포함하지 않는다.
- 보존 기간은 engagement manifest에 지정하며, 만료 시 evidence metadata와 승인된 redacted bundle 외 raw artifact를 제거할 수 있어야 한다.
- 외부 모델로 source, prompt 또는 evidence를 전송하려면 manifest에 provider와 data class를 명시적으로 허용해야 한다.

### Compatibility

- v2 JSON schema와 CLI의 backward compatibility는 제공하지 않는다.
- v2의 authorization, exact-origin, redirect, timeout, response cap과 redaction 안전 원칙은 v3 schema로 이관한다.
- 초기 source mapper는 TypeScript/Next.js/Supabase에 한정하되 universal runtime packs는 source language와 독립적으로 동작해야 한다.
- unsupported protocol, framework construct, witness와 pack capability를 조용히 무시하지 않고 coverage ledger에 기록한다.

## 12. Acceptance criteria

| ID | Observable criterion | Verification method | Maps to |
|---|---|---|---|
| `AC-101` | authorization manifest 또는 runtime acknowledgement 없이 active 명령을 실행하면 network와 target process event가 0건인 채 거부된다. | safety integration test | `FR-101`, `FR-102` |
| `AC-102` | production-class manifest는 요청 method와 capability에 관계없이 preview 이후 실행 전에 거부된다. | safety integration test | `FR-103` |
| `AC-103` | unknown/revoked key, 변조된 signature, 만료 또는 scope 밖 capability를 가진 manifest는 target 접근 전에 거부되고 유효한 test manifest만 통과한다. | manifest signature test | `FR-101`, `FR-105` |
| `AC-104` | 모든 run과 evidence bundle에서 검증된 manifest digest와 실제 target build digest를 조회할 수 있다. | artifact schema test | `FR-104` |
| `AC-201` | Next.js fixture의 route handler, server action, middleware, auth check, DB access와 dangerous sink가 graph에 source location과 함께 나타난다. | mapper golden test | `FR-201`–`FR-205` |
| `AC-202` | mapper가 auth check 누락을 추정해도 active proof 전에는 결과 상태가 `candidate`다. | mapper classification test | `FR-204` |
| `AC-203` | Supabase fixture의 RLS enablement, permissive/missing policy, storage policy와 service-role access가 관련 route/data edge에 연결되고 seeded policy gap candidate가 생성된다. | Supabase mapper golden test | `FR-203`, `FR-206` |
| `AC-204` | mixed-protocol fixture에서 browser route, REST/OpenAPI, GraphQL, WebSocket, gRPC, webhook, worker, queue, storage와 outbound integration이 surface inventory에 나타난다. | discovery golden test | `FR-207`–`FR-210` |
| `AC-205` | discovered surface 하나에 compatible pack 또는 required witness가 없으면 run은 finding 0개여도 `coverage-incomplete`이고 해당 blind spot을 식별한다. | coverage negative test | `FR-208`, `FR-210`, `FR-212` |
| `AC-206` | source가 없는 fixture도 traffic/schema/runtime evidence로 attackable surface를 만들며 white-box edge는 unsupported로 구분한다. | black-box runtime test | `FR-207`–`FR-212` |
| `AC-207` | dependency 또는 CI scanner 입력만으로는 proven finding을 만들지 않고 reachable runtime/build canary가 연결될 때만 causal candidate로 승격한다. | reachability classification test | `FR-211` |
| `AC-208` | benign multi-step fixture에서 observed state machine을 학습하고 seeded hidden transition을 underexplored candidate로 생성하되 observation이 없는 transition을 fact로 표시하지 않는다. | state-learning test | `FR-213`, `FR-214` |
| `AC-301` | 두 tenant와 네 principal fixture를 준비하고 reset 전후 DB·repo·filesystem digest가 기준 snapshot과 일치한다. | twin integration test | `FR-301`–`FR-304` |
| `AC-302` | public internet egress와 metadata IP 요청은 차단되고 owned canary sink만 관측된다. | network containment test | `FR-305`, `FR-801` |
| `AC-303` | dependency timeout, duplicate/out-of-order event와 partial transaction schedule을 주입하고 reset 뒤 clock·cache·queue·DB digest가 baseline으로 돌아온다. | deterministic fault test | `FR-306`–`FR-308` |
| `AC-304` | archive/parser canary가 별도 sandbox에서만 effect를 만들며 host path, process와 network에는 변화가 없다. | parser isolation test | `FR-309`, `FR-808` |
| `AC-400` | principal, precondition, carrier/source, mutation, forbidden predicate 또는 oracle이 누락된 attack program은 실행 전에 거부된다. | attack-program schema test | `FR-401`, `FR-409` |
| `AC-401` | user-A object ID를 user-B credential로 요청해 vulnerable fixture에서 cross-user canary가 관측되고 fixed fixture에서는 관측되지 않는다. | BOLA end-to-end test | `FR-402`–`FR-405` |
| `AC-402` | 일반 사용자가 admin route/server action을 호출하는 vulnerable fixture에서 state change가 관측되고 fixed fixture에서는 거부된다. | BFLA end-to-end test | `FR-404` |
| `AC-403` | agent-controlled URL이 vulnerable backend의 SSRF sink에 도달하면 owned canary receipt가 생성되고 real external destination은 차단된다. | compound SSRF end-to-end test | `FR-405`, `FR-451`–`FR-455` |
| `AC-404` | disposable filesystem 및 process fixture에서 path/command injection canary effect를 관측하되 host filesystem과 process에는 변화가 없다. | sandbox end-to-end test | `FR-405`, `FR-801`–`FR-803` |
| `AC-405` | workflow step의 actor, object, order와 idempotency key를 변형해 seeded approval/replay 취약점을 찾고 duplicate effect를 구분한다. | workflow integration test | `FR-403`, `FR-404`, `FR-806` |
| `AC-406` | stored XSS fixture가 isolated browser에서 canary DOM/network effect를 만들고 외부 navigation은 차단된다. | browser integration test | `FR-406` |
| `AC-407` | 동일 run budget에서 feedback scheduler가 고정된 seed 순회보다 최소 하나 이상의 새로운 seeded graph edge를 더 도달하거나, 그렇지 못한 비교 결과를 명시적으로 실패로 보고한다. | scheduler baseline experiment | `FR-407` |
| `AC-408` | LLM 제안 candidate가 deterministic oracle과 replay를 통과하지 못하면 model confidence와 관계없이 `proven`으로 전환되지 않는다. | adversarial model-output test | `FR-408` |
| `AC-409` | anonymous, valid, revoked와 다른-user session을 교차 적용해 seeded unauthenticated/session-mix-up fixture를 구분한다. | session test matrix | `FR-301`, `FR-403`, `FR-404` |
| `AC-410` | query/filter mutation이 fixture data scope를 넓히거나 secret canary를 노출하는 seeded backend에서 state oracle이 실제 row ownership과 disclosure를 검출한다. | query/data-flow end-to-end test | `FR-402`–`FR-405`, `FR-504` |
| `AC-411` | 허용되지 않은 role, owner 또는 lifecycle field를 요청 body에 추가해 seeded mass-assignment/state-transition fixture를 찾고 fixed fixture에서는 변경이 거부된다. | workflow end-to-end test | `FR-403`–`FR-405` |
| `AC-412` | OAuth/OIDC fixture에서 redirect/state/nonce/PKCE/audience/scope/account-link 변형이 각각 필요한 identity state와 witness를 사용하며 seeded token/identity confusion만 proven으로 구분한다. | federated identity matrix | `FR-409`, `FR-410` |
| `AC-413` | GraphQL fixture에서 node/edge authorization, alias/batch와 bounded complexity mutation을 실행해 cross-user data와 resource predicate를 구분한다. | GraphQL end-to-end test | `FR-411`, `FR-417` |
| `AC-414` | WebSocket과 gRPC fixture에서 handshake/origin, connection identity, method/message authorization, logout/revocation과 size/stream limit failure를 검출한다. | protocol end-to-end test | `FR-411`, `FR-417` |
| `AC-415` | upload fixture에서 filename/type/signature/archive/ownership mutation을 거쳐 parser 또는 public retrieval canary effect를 검출하고 cleanup 후 storage digest가 복원된다. | file-chain end-to-end test | `FR-413`, `FR-309` |
| `AC-416` | webhook → queue → worker fixture에서 invalid/replayed signature, actor-context loss, duplicate/out-of-order delivery와 dead-letter replay의 forbidden effect를 구분한다. | async-chain end-to-end test | `FR-415`, `FR-307` |
| `AC-417` | shared-cache fixture에서 attacker request가 victim response/state를 바꾸는 seeded key/normalization/stale-auth defect를 paired principal oracle로 검출한다. | cache isolation test | `FR-416`, `FR-507` |
| `AC-418` | two-actor barrier schedule이 seeded double-action/TOCTOU defect를 반복 재현하고 fixed fixture에서는 하나의 commit만 관측된다. | concurrency end-to-end test | `FR-308`, `FR-414` |
| `AC-419` | query/message/upload resource test가 선언된 hard budget 전에 seeded limit failure를 검출하고 target recovery를 확인하며 volumetric traffic을 생성하지 않는다. | bounded resource test | `FR-417`, `FR-508`, `FR-807` |
| `AC-420` | dependency timeout 또는 exception 뒤 partial DB/outbox/cache state나 fail-open authorization을 검출하고 단순 5xx와 구분한다. | exception/fallback test | `FR-418`, `FR-509` |
| `AC-421` | untrusted PR/artifact가 disposable CI runner의 canary build authority에 도달할 때만 delivery-chain candidate가 proven으로 승격된다. | CI reachability test | `FR-419`, `FR-211` |
| `AC-422` | scheduler가 identity+protocol, file+worker 또는 agent+backend pack을 조합한 seeded multi-pack chain을 단일 pack finding과 별도 lineage로 기록한다. | pack composition test | `FR-420` |
| `AC-423` | 가격·승인 순서·side-effect cardinality invariant가 있는 fixture는 seeded business-logic violation을 검출하고, invariant를 제거하면 finding 0개가 아니라 coverage gap이 된다. | domain-invariant test | `FR-421`, `FR-212` |
| `AC-424` | TLS/cookie/CORS/JWT/debug fixture에서 target profile과 맞지 않는 seeded cryptographic/configuration boundary를 검출하고 단순 header 존재 여부와 실제 policy failure를 구분한다. | configuration/crypto matrix | `FR-422` |
| `AC-425` | privileged action fixture에서 audit event 누락, actor/correlation 손실, sensitive token logging과 structured-log injection을 각각 관측한다. | audit integrity test | `FR-423`, `FR-506` |
| `AC-426` | isolated proxy-origin fixture의 seeded host/normalization/framing differential은 검출하지만 shared/production manifest에서는 network event 0건으로 거부된다. | HTTP-edge isolation test | `FR-424`, `FR-807` |
| `AC-427` | SQL/NoSQL/command/path/URL/template/header/XML/deserialization fixture에서 context가 맞는 mutation만 실행하고 canary state effect가 있는 seeded sink를 구분한다. | interpreter-context matrix | `FR-412`, `FR-405` |
| `AC-428` | serverless fixture에서 spoofed event actor, over-privileged function, cross-tenant object/signed URL과 metadata canary reachability를 구분하고 test account prefix 밖 호출은 거부한다. | serverless application-edge test | `FR-425`, `FR-811` |
| `AC-429` | SOAP/XML fixture에서 action/method authorization, schema/signature confusion, bounded entity expansion과 XXE canary effect를 구분하고 parser sandbox 밖 egress를 차단한다. | SOAP/XML end-to-end test | `FR-411`, `FR-412`, `FR-309` |
| `AC-430` | malicious MCP fixture가 benign tool과 유사한 name/metadata/schema로 selection을 가로채면 connection·approval·execution snapshot과 실제 gateway call이 shadowing path를 입증한다. | MCP shadowing/puppet test | `FR-456`, `FR-511` |
| `AC-431` | 승인 후 tool description/schema/resource URI 또는 server digest가 바뀌는 rug-pull fixture를 실행 전에 탐지하고 capability 재승인 없이는 호출하지 않는다. | capability-drift test | `FR-456` |
| `AC-432` | poisoned memory가 summarization, embedding, retrieval 또는 agent handoff에서 trust/role provenance를 잃으면 lineage witness가 최초 writer와 변환 지점을 식별한다. | memory-lineage test | `FR-457`, `FR-511` |
| `AC-433` | injection session과 분리된 후속 session에서만 활성화되는 sleeper fixture가 configured horizon 안에서 forbidden effect를 만들고 benign-memory baseline utility를 보존한다. | delayed-memory activation test | `FR-458` |
| `AC-434` | poisoned canary가 agent message → RAG/email/repository/memory를 통해 두 번째 agent에서 재활성화될 때 hop별 parent receipt와 blast radius가 기록되고 manifest hop에서 전파가 중단된다. | bounded propagation test | `FR-459`, `FR-511`, `FR-812` |
| `AC-435` | 동일 prompt의 자칭 authority와 문체를 유지한 채 authenticated actor/scope/target metadata를 바꾸면 action이 trusted execution metadata에만 따라야 하며 그렇지 않으면 authority-binding finding이 된다. | execution-authority differential | `FR-460` |
| `AC-436` | 개별적으로 허용된 두 data flow의 recipient/purpose를 섞거나 parasitic tool parameter로 다른 MCP session context를 요구하는 fixture에서 contextual-flow oracle이 policy violation을 검출한다. | contextual-integrity composition test | `FR-461`, `FR-512` |
| `AC-437` | local source→sanitizer→sink harness가 path를 유지하며 seeded sanitizer-evasion XSS/injection input을 찾아 browser/process canary effect로 확정한다. | path-persistent fuzzing test | `FR-426` |
| `AC-438` | WAF/gateway/origin fixture가 같은 encoded parameter 또는 request boundary를 다르게 해석할 때 각 parser view를 기록하고 실제 authorization/sink bypass가 있을 때만 candidate로 승격한다. | intermediary differential test | `FR-427` |
| `AC-439` | controlled backdoored agent fixture가 semantic trigger에서만 classified canary를 tool argument로 보내면 model/config digest와 paired behavior differential을 기록하고 clean fixture와 구분한다. | model-supply-chain research test | `FR-462` |
| `AC-440` | payload를 제거한 network metadata observer가 held-out canary workload에서 사전 등록한 metric/threshold로 baseline을 초과할 때만 side-channel candidate를 만들고 원 payload를 evidence에 저장하지 않는다. | network-metadata privacy test | `FR-463` |
| `AC-451` | PR indirect injection에서 agent → tool → backend → forbidden state 경로가 하나의 graph path와 receipt sequence로 연결된다. | compound chain end-to-end test | `FR-451`–`FR-455` |
| `AC-452` | target trace에서 생략한 tool call이 gateway witness에 있으면 finding evidence는 gateway event를 사용하고 불일치를 표시한다. | adversarial adapter test | `FR-453`, `FR-501`–`FR-503` |
| `AC-453` | role, provenance, tenant, retry 또는 cross-session timing 중 하나를 바꾼 mutation이 원본과 별도 graph transition 및 lineage로 기록된다. | compound mutation test | `FR-454` |
| `AC-501` | witness event를 제거하거나 순서를 변조하면 receipt 검증이 실패하고 finding은 `proven`이 아니라 `error`가 된다. | receipt integrity test | `FR-503`, `FR-505` |
| `AC-502` | HTTP 200 응답이어도 cross-tenant row, process effect 또는 egress canary가 관측되면 해당 state oracle이 실패를 검출한다. | state-oracle tests | `FR-504` |
| `AC-503` | browser, IdP, cache, queue, object storage 또는 webhook witness가 필요한 pack에서 해당 witness health가 없으면 proven 판정을 거부한다. | witness readiness matrix | `FR-506`, `FR-510` |
| `AC-504` | actor/tenant/protocol/timing 하나만 바꾼 paired execution에서 response가 같아도 independent state가 다르면 differential oracle이 violation을 검출한다. | relational oracle test | `FR-507` |
| `AC-505` | exception response 뒤 DB commit, outbox 누락 또는 stale cache 중 하나만 남는 seeded partial-effect를 exception oracle이 식별한다. | partial-state oracle test | `FR-509` |
| `AC-506` | capability, memory와 propagation receipt에서 parent 또는 transform provenance 하나를 제거하면 관련 agent finding은 `proven`이 아니라 `error` 또는 `coverage-incomplete`가 된다. | agent-provenance integrity test | `FR-511`, `FR-512` |
| `AC-601` | seeded vulnerability는 attack에서만 predicate가 나타나고 baseline/counterfactual에서는 나타나지 않을 때만 `proven`이 된다. | causal replay test matrix | `FR-601`–`FR-603` |
| `AC-602` | baseline에서도 같은 effect가 발생하면 candidate는 `rejected`, 반복 기준을 충족하지 못하면 `flaky`가 된다. | causal negative tests | `FR-602`, `FR-603` |
| `AC-603` | minimizer가 하나 이상의 불필요한 artifact 또는 step을 제거해도 predicate가 유지되며 원본과 최소 graph lineage가 보존된다. | minimizer integration test | `FR-604` |
| `AC-604` | fixed build에서 attack은 사라지지만 benign task가 실패하면 `fixed`가 아니라 `utility-regression`으로 판정된다. | fix verification test | `FR-605` |
| `AC-701` | proven finding bundle을 초기화된 twin에서 replay해 동일 predicate와 stable finding ID를 얻는다. | artifact replay test | `FR-701`–`FR-705` |
| `AC-702` | JSON schema가 모든 finding state를 구분하고 Markdown 결과에는 raw token, cookie, secret 또는 실제 canary value가 포함되지 않는다. | schema and redaction tests | `FR-704`, `FR-705`, `FR-804` |
| `AC-703` | finding이 0개인 run도 첫 페이지에서 exercised/not-applicable/unsupported/blocked/error surface와 pack/witness blind spot을 보여주며 전체 `secure` verdict를 출력하지 않는다. | report contract test | `FR-706`, `FR-707` |
| `AC-801` | budget 초과 또는 cancellation 후 새 step이 시작되지 않고 snapshot integrity 결과가 기록된다. | cancellation/limit test | `FR-802`, `FR-805` |
| `AC-802` | raw artifact retention이 만료되면 replay에 필요한 redacted bundle과 lineage만 남고 raw prompt, response와 DB diff는 제거된다. | retention lifecycle test | Privacy and retention |
| `AC-803` | race/resource/cache/parser pack을 production/shared target 또는 containment attestation 없는 Twin에서 실행하면 target event 0건으로 거부된다. | high-risk pack safety test | `FR-807` |
| `AC-804` | file/identity corpus에 executable malware, live credential, 실제 recipient와 외부 analyzer endpoint가 포함되면 schema validation 또는 preview에서 거부된다. | corpus safety test | `FR-808`, `FR-809` |
| `AC-805` | redirect, callback, WebSocket upgrade와 재해석된 DNS destination이 scope 밖이면 각 protocol client가 연결 전 또는 즉시 차단한다. | protocol egress test | `FR-810` |
| `AC-806` | cloud manifest의 account, region 또는 resource prefix를 벗어난 mutation은 provider/emulator call 전에 거부된다. | cloud scope safety test | `FR-811` |
| `AC-807` | propagation/sleeper fixture가 manifest의 agent, hop, session 또는 artifact-write budget을 넘기려 하면 새 전파가 중단되고 Twin 밖 sink에는 event가 없다. | propagation containment test | `FR-812` |
| `AC-901` | CLI lifecycle 각 명령은 stale schema/build/fixture를 명시적으로 거부하며 CI replay는 adaptive mutation을 실행하지 않는다. | CLI smoke and CI test | `FR-901`–`FR-904` |
| `AC-902` | `discover`와 `coverage`가 active attack 없이 inventory, applicable/missing pack, witness readiness와 blind spot을 출력한다. | CLI discovery smoke test | `FR-905` |
| `AC-903` | 변조 digest, incompatible API/schema, unsupported target version 또는 safety class가 맞지 않는 pack은 load되지 않는다. | pack registry integrity test | `FR-906` |
| `AC-904` | policy가 요구한 surface/evidence grade 하나를 충족하지 못하면 finding 수와 관계없이 coverage failure exit code가 발생한다. | coverage policy test | `FR-907` |
| `AC-905` | 두 build의 surface, coverage, pack version과 finding lineage 변화를 diff해 제거된 endpoint와 새 blind spot을 구분한다. | coverage regression test | `FR-908` |
| `AC-906` | 동일한 descriptor와 digest를 함께 변조해도 registry signature 검증이 실패하며, revoked registry signer도 load 전에 거부된다. | registry signature test | `FR-906` |

## 12.1 Research hypotheses from emerging attacks

2026 preprint 또는 아직 일반화가 충분히 검증되지 않은 공격은 기본 지원을 주장하지 않고 다음 가설과 중단 조건으로 관리한다.

| ID | Hypothesis | Falsification/stop criterion |
|---|---|---|
| `RH-201` | capability snapshot과 execution call을 비교하면 prompt-only test가 놓치는 MCP shadowing, puppet과 rug-pull chain을 안정적으로 입증한다. | 실제 gateway fixture에서 benign metadata update와 malicious selection/drift를 구분하지 못한다. |
| `RH-202` | memory transformation lineage와 delayed activation search가 same-session injection test보다 더 많은 persistent chain을 찾는다. | summarization/retrieval/handoff fixture에서 최초 poison source와 activation을 재현 가능하게 연결하지 못한다. |
| `RH-203` | bounded propagation graph가 single-agent test가 놓치는 multi-agent/RAG cascade를 찾으면서 Twin 밖 복제를 차단할 수 있다. | hop lineage가 불완전하거나 propagation containment test가 한 번이라도 실패한다. |
| `RH-204` | benign trace에서 학습한 observed state machine이 graph-only scheduling보다 적은 budget으로 hidden transition과 workflow deviation을 찾는다. | 동일 budget에서 unique witnessed transition 또는 proven chain이 증가하지 않는다. |
| `RH-205` | path-persistent local harness가 generic payload mutation보다 sanitizer-evasion finding의 precision과 replayability를 높인다. | source→sink path가 실제 runtime과 일치하지 않거나 concrete canary effect 증가가 없다. |
| `RH-206` | intermediary parser view differential이 단일 origin test가 놓치는 authorization/sink bypass를 발견한다. | parser disagreement가 실제 state effect로 이어지는 고유 chain을 만들지 못한다. |
| `RH-207` | contextual-flow oracle이 문자열 DLP가 놓치는 permitted-flow mixing과 cross-tool/session context theft를 구분한다. | domain privacy norm 없이는 안정적인 oracle을 구성할 수 없거나 benign flow 오탐이 허용 범위를 넘는다. |
| `RH-208` | controlled model-backdoor와 traffic-side-channel pack이 agent supply-chain 및 metadata privacy regression test로 실용적이다. | known fixture 밖에서 재현성이 없거나 target별 calibration 비용이 human review보다 크다. |

## 13. Success metrics and research gates

단일 종합 점수를 만들지 않는다.

- **Proven Chain Count**: independent oracle와 causal replay를 통과한 unique chain
- **Project-only / Compound Split**: backend 자체와 agent가 필요한 finding의 구분
- **Surface Inventory Completeness**: source, schema, traffic과 runtime에서 알려진 surface 중 stable ID로 inventory화된 비율
- **Applicable Pack Coverage**: 적용 가능하다고 판정된 surface-pack cell 중 실제 실행된 비율
- **Witnessed Surface Coverage**: 필요한 independent witness health와 state oracle을 확보한 exercised surface 비율
- **Blind-spot Burden**: unsupported, blocked, error와 unknown field/edge의 수 및 영향 data class
- **Cross-layer Edge Coverage**: agent와 project boundary를 가로지른 graph edge coverage
- **Authority Transition Coverage**: principal, tenant, role, delegation, approval 전환 coverage
- **Reproducibility**: 동일 snapshot에서 forbidden predicate가 반복되는 비율
- **Minimization Ratio**: 최초 candidate 대비 artifact/step 감소
- **Utility Preservation**: benign task 성공률
- **Evidence Completeness**: 필수 witness, digest와 replay artifact 충족률
- **Triage Cost**: 개발자가 재현, 원인 확인과 regression 전환에 쓰는 시간

Go gates:

1. seeded identity, authorization, injection, file, async, cache/race, resource/exception과 compound agent chain을 각각 정확히 구분한다.
2. source가 없는 target에서도 surface discovery, coverage ledger와 protocol-aware runtime attack을 수행한다.
3. 고정 payload baseline보다 같은 실행 예산에서 hand-written scenario 밖의 unique proven chain을 더 찾는다.
4. 서로 다른 두 implementation stack과 네 product archetype에서 mandatory surface의 unsupported/blocked 상태를 숨기지 않고 breadth fixture를 통과한다.
5. 실제 WIGTN 프로젝트 clone에서 generic response assertion이 놓친 project-only 또는 compound finding을 최소 하나 재현한다.
6. 개발자가 evidence bundle만으로 수정하고 fixed-build replay를 통과한다.

Stop gate:

- Phase 2 종료 시 hand-written fixture 밖의 새로운 proven chain을 발견하지 못하거나 독립 witness가 실제 effect를 안정적으로 입증하지 못하면 adaptive 독자 엔진 개발을 중단한다.
- 특정 pack이 두 개 이상의 대표 fixture와 실제 clone에서 unique state effect를 만들지 못하면 그 pack을 “지원” 목록에서 제거하고 inventory-only integration으로 내린다.
- breadth gate를 통과하기 전에는 “대부분의 제품을 커버한다”는 외부 주장을 하지 않는다.

## 14. Delivery outline

### Phase 0 — v3 contract and cutover

- v3 graph, surface, pack, coverage, attack program, scope, run, receipt와 evidence schemas
- signed pack registry와 safety class
- v2 schema backward compatibility 제거
- authorization, redaction, exact-origin와 request cap 안전 원칙 이관
- fixture-only CLI skeleton

Exit: schema golden tests, `AC-101`–`AC-104`, `AC-803`–`AC-805`, `AC-903` 통과.

### Phase 1 — Universal runtime core and Project Security Lab

- Next.js App Router/Supabase ground-truth fixture
- two-tenant/four-principal twin
- source/schema/traffic/runtime discovery와 coverage ledger
- route/auth/data/sink mapper 및 black-box HTTP/OpenAPI pack
- stateful HTTP runner와 DB/network/filesystem/process witness
- BOLA, BFLA, cross-tenant, mass assignment, SSRF, path/command injection과 workflow replay

Exit: `AC-201`–`AC-207`, `AC-301`, `AC-302`, `AC-400`–`AC-405`, `AC-408`–`AC-411`, `AC-501`, `AC-502`, `AC-601`, `AC-602`, `AC-703`, `AC-902`, `AC-904` 통과.

### Phase 2 — Causal search and evidence

- graph coverage/policy-distance scheduler
- benign-trace state learner와 underexplored-transition scheduler
- baseline/attack/counterfactual orchestrator
- minimizer
- evidence bundle, replay와 fixed-build verification
- multi-pack composition과 coverage/build regression

Exit: `AC-208`, `AC-407`, `AC-422`, `AC-603`, `AC-604`, `AC-701`, `AC-702`, `AC-801`, `AC-802`, `AC-901`, `AC-905`, `RH-204` 비교 및 adaptive discovery Go gate 통과.

### Phase 3 — Modern product attack packs

- isolated browser와 federated identity fixture
- GraphQL, WebSocket와 gRPC protocol fixtures
- file/object storage/parser sandbox
- webhook, queue, worker와 third-party integration fixture
- cache/proxy, concurrency, bounded resource와 exception/fallback fixture
- domain invariant와 configuration/cryptographic-boundary fixture
- source→sanitizer→sink path-persistent harness

Exit: `AC-303`, `AC-304`, `AC-406`, `AC-412`–`AC-420`, `AC-423`, `AC-424`, `AC-427`, `AC-437`, `AC-503`–`AC-505` 통과.

### Phase 4 — Compound Agent and Delivery Lab

- coding-agent adapter와 independent gateway witness
- PR/issue/web/tool/memory carrier
- role confusion, indirect injection, approval spoofing와 conjunctive trigger
- project-only vs agent-required causal separation
- disposable CI/artifact reachability pack
- privileged action audit-integrity pack
- MCP capability shadowing/rug-pull, memory lineage/sleeper와 bounded propagation
- execution metadata authority binding과 contextual-flow composition

Exit: `AC-403`, `AC-421`, `AC-425`, `AC-430`–`AC-436`, `AC-451`–`AC-453`, `AC-506`, `AC-807`, `RH-201`–`RH-203`, `RH-207`과 실제 WIGTN clone finding gate 통과.

### Phase 5 — Portability and real-target validation

- Express/Fastify/Nest/Hono와 Python source pack
- 수요와 ground truth가 확보된 뒤 Spring Boot와 Go source pack
- multi-tenant SaaS, file-processing, event-driven integration과 agentic developer platform breadth fixtures
- dedicated proxy-origin HTTP-edge fixture
- serverless/event/object-storage application-edge fixture
- SOAP/XML legacy web-service fixture
- WAF/gateway/origin parser-differential fixture
- controlled model-backdoor와 network-metadata privacy research fixtures
- human red-team blind comparison
- disclosure, retention과 recovery runbook

Exit: `AC-426`, `AC-428`, `AC-429`, `AC-438`–`AC-440`, `AC-806`, `RH-205`, `RH-206`, `RH-208`, 두 implementation stack·네 product archetype breadth gate, triage cost 개선과 responsible disclosure readiness.

## 15. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| pack 수 증가로 범위 팽창 | shallow scanner와 유지보수 붕괴 | universal core와 pack contract 분리, evidence gate 없는 pack은 inventory-only로 강등 |
| coverage theater | finding 0개를 secure로 오인 | coverage ledger, mandatory surface policy, unsupported/blocked/error를 first-class 결과로 표시 |
| target self-report 조작 | 잘못된 “입증” | independent gateway/DB/process/canary witness를 proven 조건으로 강제 |
| 비결정적 agent behavior | causality 과장 또는 flaky finding | paired snapshot, 반복 기준, counterfactual과 flaky 상태 분리 |
| fixture가 실제 프로젝트를 대표하지 않음 | benchmark 과적합 | Phase 2 이후 실제 WIGTN clone 및 human blind comparison 필수 |
| 공격의 production 유출 | 법적·운영 피해 | disposable default, exact scope, owned sink, deny egress, hard budget |
| 증거에 민감정보 포함 | 2차 유출 | data classification, digest 중심 evidence, default redaction과 retention |
| static mapper 오탐 | triage 비용 증가 | static 결과는 candidate 전용, active state proof 없이는 publish 금지 |
| Supabase RLS와 앱 권한의 이중 경계 | 원인 attribution 혼란 | app request와 DB audit를 함께 witness하고 project-only replay로 계층 분리 |
| 동시 실행으로 snapshot 오염 | 재현성 상실 | snapshot 단위 직렬 실행 또는 격리 clone, reset digest 검증 |
| protocol parser 또는 pack compromise | SPEAR control plane 침해 | least-privilege worker, signed registry digest, pack API/version 검증과 parser sandbox |
| resource/race test가 DoS로 변질 | 서비스 장애 | disposable-only attestation, bounded schedule, hard budget와 recovery oracle |
| source pack drift | framework update 뒤 false negative | supported version manifest, golden corpus와 unsupported-version coverage failure |

## 16. Assumptions and open decisions

### Assumptions

- `Assumption` 첫 실제 target은 WIGTN이 소유하고 disposable clone을 만들 수 있는 Next.js/Supabase 프로젝트다.
- `Assumption` 초기 campaign은 local 또는 전용 test environment에서 실행하며 production mutation은 지원하지 않는다.
- `Assumption` TypeScript source mapping과 runtime witness를 위해 현재의 zero-runtime-dependency 제약은 제거할 수 있다.
- `Assumption` 공격 성공은 real secret이나 외부 피해가 아니라 canary와 fixture state로 충분히 입증할 수 있다.

### Open decisions

- `Open question` source mapper의 P0 범위를 Next.js App Router에만 둘지 Express/Fastify까지 포함할지 Phase 1 시작 전에 product owner가 결정한다. 기본값은 Next.js only다.
- `Open question` Supabase local stack reset을 표준 twin으로 강제할지 generic Postgres adapter도 동시에 만들지 Phase 1 fixture spike 후 tech lead가 결정한다.
- `Open question` witness receipt를 hash-chain과 독립 저장소로 시작할지 authorization manifest와 별도로 software signature까지 포함할지 threat-model review에서 security owner가 결정한다. 기본값은 hash-chain이다.
- `Open question` host process execution fixture에 rootless container가 충분한지 microVM이 필요한지는 escape threat test 전에 security owner가 결정한다.
- `Open question` adaptive mutation에 사용할 model provider, data class와 campaign cost ceiling은 Phase 2 전에 engagement owner가 결정한다.
- `Open question` 실제 finding의 disclosure, raw artifact retention과 삭제 책임자는 Phase 4 pilot 전에 지정해야 한다.
- `Open question` Phase 3 pack 중 identity, file/async, GraphQL/WebSocket/gRPC와 cache/race를 어떤 순서로 배포할지는 실제 WIGTN surface inventory가 나온 뒤 security owner가 결정한다.
- `Open question` runtime pack이 요구하는 database/cache/queue witness를 sidecar proxy, native audit adapter 또는 test-only instrumentation 중 무엇으로 제공할지는 각 adapter spike에서 결정한다.
- `Open question` mobile/desktop client 내부와 cloud control plane을 별도 SPEAR product line으로 확장할지는 web/backend breadth gate 통과 전 결정하지 않는다.

## 17. External baselines

- OWASP ASVS 5.0.0과 WSTG v4.2: web/application control 및 versioned test 분류
- OWASP Top 10 2025과 API Security Top 10 2023: access control, supply chain, exceptional condition, resource consumption, sensitive flow와 unsafe API consumption 분류
- CWE Top 25 2025: XSS, SQL injection, CSRF, authorization, path/command injection, upload, deserialization, disclosure, SSRF와 resource-limit weakness 우선순위
- OWASP GraphQL, WebSocket, gRPC, OAuth2, File Upload와 Serverless cheat sheets: protocol/identity/parser/application-edge pack 설계 기준
- OWASP AISVS 1.0과 Agentic Top 10 2026: agent security 및 abuse-case 분류
- AgentDojo와 ToolSandbox: stateful tool environment와 security/utility 분리
- AgentFuzz: semantic·distance feedback을 이용한 directed search
- AttriGuard: counterfactual action attribution
- CVE-Bench와 CyberGym: 실제 exploit과 working PoC 기반 검증
- NIST NCCoE Agent Identity and Authorization draft: delegated identity, on-behalf-of와 tamper-resistant audit
- IEEE TSE/ACM TOSEM/MCPTox: MCP tool poisoning, shadowing/puppet, rug pull과 malicious resource lifecycle
- CoreCrisis, WDFuzz와 XSSky: state-machine learning, hierarchical directed scheduling과 path-persistent exploit confirmation
- Cross-MCP memory stealing, memory sleeper와 contextual-integrity research: transformed provenance, delayed activation과 permitted-flow composition
- USENIX Security 2026 network-level leakage: encrypted agent traffic metadata side-channel

세부 논문 성숙도, 새 gap과 반증 조건은 `docs/product/spear-v3-research-gap-addendum.md`에서 관리한다.

외부 분류는 metadata와 비교 기준이며 SPEAR finding을 자동으로 규정 준수 판정으로 바꾸지 않는다.
