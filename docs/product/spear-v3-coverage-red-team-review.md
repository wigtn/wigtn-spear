# SPEAR v3 universal coverage red-team review

검토 대상: `docs/product/spear-v3-prd.md`  
검토일: 2026-07-23  
검토 관점: “웬만한 web/API/backend 제품의 빈틈을 공격해 실제 effect로 입증할 수 있는가?”

> 2025–2026 논문 재검토로 추가된 MCP lifecycle, memory/provenance, propagation, learned-state, parser differential과 contextual-flow gap은 `spear-v3-research-gap-addendum.md`를 함께 본다.

## Executive verdict

`Inference` 최초 PRD는 WIGTN의 Next.js/Supabase 제품을 깊게 검증하는 데 적합했지만, 대부분의 현대 제품을 커버한다는 주장에는 부족했다.

`Inference` 이번 확장으로 architecture-level coverage envelope는 browser/web/API/backend/worker/integration/agent 제품군까지 넓어졌다. 하지만 이는 **제품 계약이 넓어진 것**이지 구현과 실전 탐지율이 입증된 것이 아니다. 두 implementation stack과 네 product archetype breadth gate를 통과하기 전에는 “대부분 커버”를 외부 주장할 수 없다.

## 1. External attack baseline

### Facts

- `Fact` [OWASP Top 10 2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)는 broken access control, injection 외에 software supply-chain failure와 mishandling of exceptional conditions를 주요 root-cause category로 포함한다.
- `Fact` [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)는 object/property/function authorization뿐 아니라 unrestricted resource consumption, sensitive business-flow abuse와 unsafe consumption of third-party APIs를 포함한다.
- `Fact` [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)는 stable v4.2를 제공하고 v5.0을 개발 중이며, attack surface mapping에서 authenticated/unauthenticated entry point, multi-step flow와 WebSocket을 식별하도록 요구한다.
- `Fact` [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)는 XSS, SQL injection, CSRF, missing/incorrect authorization, path/command injection, unrestricted upload, unsafe deserialization, disclosure, SSRF와 resource allocation without limits를 포함한다.
- `Fact` OWASP는 [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html), [WebSocket](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html), [gRPC](https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html), [OAuth2](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)와 [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)을 서로 다른 security surface로 다룬다.

## 2. Findings against the original PRD

### Blocker

#### `COV-B01` Finding이 없을 때 coverage를 증명할 수 없었다 — Resolved

- 영향 구간: Coverage claim, `FR-207`–`FR-212`, `FR-706`, `FR-707`, `FR-905`–`FR-908`
- `Fact` 기존 PRD는 finding state를 엄격히 정의했지만 어떤 route/protocol/workflow를 발견했고 실제로 공격했는지 전체 ledger가 없었다.
- `Inference` scanner가 모르는 endpoint를 검사하지 않고 finding 0개를 반환하는 것이 가장 위험한 false assurance다.
- 조치: surface마다 `discovered → mapped → attackable → exercised → witnessed` 상태와 `unsupported/blocked/error`를 강제하고 target 전체 `secure` verdict를 금지했다.

#### `COV-B02` Next.js/Supabase source mapper 없이는 다른 stack을 커버할 구조가 없었다 — Resolved

- 영향 구간: Universal runtime profile, Source-aware profiles, Target pack contract
- `Fact` 최초 PRD의 supported target은 TypeScript/Next.js/Supabase였다.
- 조치: source-independent browser/HTTP/OpenAPI/GraphQL/WebSocket/gRPC/event runtime core와 source pack을 분리했다. Source pack이 없어도 runtime attack은 가능하지만 white-box blind spot을 ledger에 남긴다.

### High

#### `COV-H01` 현대 identity lifecycle이 session actor swap 수준에 머물렀다 — Resolved

- 누락: OAuth/OIDC redirect, state/nonce/PKCE, issuer/audience/scope, account linking/recovery, MFA와 token revocation
- 조치: `FR-410`, `AC-412`, fake IdP/recipient fixture와 identity witness를 추가했다.

#### `COV-H02` REST 이외 protocol boundary가 빠져 있었다 — Resolved

- 누락: GraphQL node/edge and batching, WebSocket origin/session/message, gRPC method/metadata/stream
- 조치: `FR-411`, `AC-413`, `AC-414`와 protocol-aware replay를 추가했다.

#### `COV-H03` File upload 이후의 storage/parser/worker/retrieval chain이 빠져 있었다 — Resolved

- 누락: MIME/signature confusion, archive traversal/expansion, parser egress, object ownership, public active content
- 조치: `FR-309`, `FR-413`, `AC-304`, `AC-415`와 별도 parser sandbox를 추가했다.

#### `COV-H04` 비동기 제품의 identity와 side effect가 HTTP 응답 뒤에서 사라졌다 — Resolved

- 누락: webhook signature/replay, queue actor context, duplicate/out-of-order event, retry/dead-letter와 scheduled worker
- 조치: `FR-306`, `FR-307`, `FR-415`, `AC-303`, `AC-416` 및 queue/webhook witness를 추가했다.

#### `COV-H05` Race, cache, resource exhaustion과 exception/fallback path가 없었다 — Resolved

- 조치: deterministic concurrency barrier, cache/proxy differential, bounded resource oracle와 partial-state exception oracle을 `FR-308`, `FR-414`, `FR-416`–`FR-418`, `AC-417`–`AC-420`으로 추가했다.

#### `COV-H06` Business logic 자동화가 domain knowledge 없이 proven을 주장할 수 있었다 — Resolved with explicit limitation

- `Inference` 가격, 승인 순서, 재고, quota, 결제 cardinality 같은 invariant는 일반 payload에서 자동으로 알 수 없다.
- 조치: `FR-421`, `AC-423`이 schema/test/event/operator에서 usable invariant를 요구한다. Invariant가 없으면 finding 0개가 아니라 coverage gap이다.
- 잔여 한계: 모든 업무 invariant를 자동 발견한다는 주장은 하지 않는다.

#### `COV-H07` Configuration, crypto boundary와 audit integrity가 약했다 — Resolved

- 조치: TLS/cookie/CORS/JWT/token/debug/exception 설정 pack `FR-422`, privileged/security audit pack `FR-423`, `AC-424`, `AC-425`를 추가했다.

#### `COV-H08` Pack 자체가 새로운 supply-chain 및 parser 공격면이 된다 — Resolved at contract level

- 조치: signed registry digest, API/schema/target version, safety class, least-privilege worker와 parser sandbox를 `FR-906`, `AC-903`에 추가했다.
- 잔여 한계: 실제 sandbox escape 저항은 구현 threat test 전까지 입증되지 않았다.

### Medium

#### `COV-M01` HTTP edge/request desync는 일반 target에서 안전하게 자동화할 수 없다 — Isolated only

- 조치: `FR-424`, `AC-426`은 fully isolated proxy-origin Twin에서만 host/routing/framing differential을 허용한다.
- 제외: shared ingress 또는 production에 대한 request smuggling은 지원하지 않는다.

#### `COV-M02` Cloud/serverless 전체는 여전히 커버되지 않는다 — Explicit boundary

- 포함: application event source, function identity, object storage/signed URL, metadata/service credential reachability.
- 제외: 조직 전체 IAM graph, Kubernetes posture와 cloud control-plane exploitation.

#### `COV-M03` Native client와 memory-unsafe component는 여전히 blind spot이다 — Explicit boundary

- 포함: mobile/desktop product가 사용하는 web/API/backend.
- 제외: APK/IPA/native desktop 내부, firmware, browser engine, kernel과 native memory corruption.
- `Inference` 이 영역을 억지로 추가하면 현재 제품의 evidence model과 sandbox 범위가 붕괴한다.

#### `COV-M04` Source pack breadth는 지속적인 framework maintenance를 요구한다 — Staged

- P0: Next.js/Supabase
- P1: Express/Fastify/Nest/Hono, Python FastAPI/Django/Flask
- P2: Spring Boot, Go
- 통제: supported-version manifest와 unsupported-version coverage failure. 실제 ground truth가 없으면 새 source pack을 추가하지 않는다.

## 3. Coverage envelope after revision

| Product surface | Contract status | Evidence target |
|---|---|---|
| Browser/web UI | P1 | DOM/storage/cookie/network witness |
| REST/OpenAPI backend | P0 | HTTP + DB/process/state witness |
| Authentication/authorization/tenancy | P0 | paired principal + IdP/DB witness |
| OAuth/OIDC/JWT/MFA/recovery | P1 | fake IdP + token/identity witness |
| GraphQL/WebSocket/gRPC | P1 | protocol gateway + state witness |
| SOAP/XML web service | P2 | protocol/parser sandbox + state witness |
| File/object storage/parser | P1 | parser sandbox + storage/process/network witness |
| Webhook/queue/worker/scheduler | P1 | event/outbox/queue/state witness |
| Cache/concurrency/race | P1 | cache + commit-order witness |
| Resource/exception/fallback | P1 | container resource + transaction/outbox witness |
| Configuration/crypto boundary | P1 | protocol/config and token oracle |
| CI/artifact/supply-chain reachability | P2 | disposable runner + artifact witness |
| Cloud/serverless application edge | P2 | event/storage/cloud-audit witness |
| Audit/detection integrity | P2 | independent audit/log witness |
| Agent-project compound | P0 architecture, Phase 4 delivery | tool/API/process/data witness |
| Native mobile/desktop/firmware/kernel | Out of scope | 별도 제품 필요 |

## 4. Adversarial failure tests for SPEAR itself

SPEAR를 신뢰하려면 target뿐 아니라 scanner 자체를 다음 방식으로 공격해야 한다.

1. mapper가 endpoint를 누락하도록 dynamic registration과 generated route를 사용한다.
2. target이 self trace에서 privileged event를 제거하거나 순서를 조작한다.
3. witness 하나를 중단하고 나머지 trace만 정상처럼 반환한다.
4. stale snapshot, duplicate queue event와 partial DB commit을 섞는다.
5. malicious schema/OpenAPI/protobuf/archive로 pack parser를 공격한다.
6. redirect, DNS rebinding, WebSocket upgrade와 callback으로 scope를 빠져나가게 한다.
7. LLM이 높은 confidence의 거짓 exploit과 조작된 remediation을 제안하게 한다.
8. framework version을 pack support range 밖으로 바꾸고 silent false negative가 발생하는지 확인한다.
9. finding 0개지만 mandatory surface 하나가 unsupported인 target을 입력한다.
10. fixed build가 공격을 막는 대신 정상 business flow도 막도록 수정한다.

각 공격은 PRD의 `error`, `coverage-incomplete`, `flaky`, `rejected` 또는 `utility-regression`으로 종료되어야 하며 `proven` 또는 `secure`로 잘못 승격되면 blocker다.

## 5. Remaining opposing hypotheses

### `OH-COV-101` Pack breadth가 깊이를 희생한다

- 검증: pack별로 두 대표 fixture와 실제 clone에서 unique witnessed effect를 요구한다.
- 실패: response/header assertion만 제공하면 inventory-only로 강등한다.

### `OH-COV-102` Runtime witness 설치 비용이 human pentest보다 크다

- 검증: Twin 자동 준비율, 수동 configuration 수와 finding당 triage 시간을 측정한다.
- 실패: 제품마다 witness를 수작업 개발해야 하면 범용 제품이 아니라 expert harness다.

### `OH-COV-103` “대부분의 제품”은 검증 불가능한 마케팅 문구다

- 대응: 제품 수가 아니라 surface/protocol/state coverage와 blind-spot burden으로 주장 범위를 제한한다.
- gate: 두 stack·네 archetype breadth fixture 전에는 외부 breadth claim을 금지한다.

## 6. Final verdict and priorities

### Facts

- `Fact` PRD는 이제 web/API/backend/worker/integration/agent의 주요 현대 surface를 target-pack과 witness 계약으로 표현한다.
- `Fact` native client, memory-unsafe binary와 cloud control plane은 명시적으로 제외됐다.
- `Fact` 이 breadth는 아직 구현·실전 검증되지 않았다.

### Inference

- `Inference` 지금 설계는 “무엇이든 스캔한다”가 아니라 **대부분의 서비스형 제품을 같은 causal evidence core로 공격하고, 보지 못한 영역을 숨기지 않는 플랫폼**으로 발전할 수 있다.

### Prioritized change proposal

1. `P0` coverage ledger와 `coverage-incomplete`를 graph보다 먼저 구현한다.
2. `P0` universal HTTP/OpenAPI + paired identity/tenant + DB/network witness를 완성한다.
3. `P0` domain invariant contract와 exception/partial-state oracle을 구현한다.
4. `P1` 실제 WIGTN inventory가 많은 순서로 identity, file/async, browser/protocol, cache/race pack을 추가한다.
5. `P1` 각 pack을 두 fixture와 실제 clone에서 evidence gate로 승격 또는 강등한다.
6. `P2` delivery/cloud/audit/HTTP-edge는 core 깊이가 입증된 뒤 추가한다.
7. `Stop` breadth 때문에 proven chain 품질이나 witness 신뢰가 낮아지면 pack 수를 줄인다.
