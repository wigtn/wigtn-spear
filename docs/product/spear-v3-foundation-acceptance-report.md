# SPEAR v3 foundation acceptance report

- 기준 문서: `docs/product/spear-v3-prd.md`
- 검증일: 2026-07-23
- 대상 버전: `0.3.0`
- 전체 PRD 판정: **Partially satisfied**
- 이번 foundation slice 판정: **Satisfied**
- active causal HTTP + evidence slice 판정: **Partially satisfied** (fixture/library 수준)

## 실행 증거

```text
$ npm run check
typecheck: passed
tests: 91 passed, 0 failed
```

추가 smoke evidence:

- `attack validate`가 예제 attack program을 정상 검증했다.
- `discover`가 operator 1개 + OpenAPI 2개 surface를 passive inventory로 출력했다.
- `git diff --check`가 통과했다.
- `run project`가 실제 disposable HTTP fixture를 진짜 소켓으로 공격하고, proven
  finding에 대해 exit code `1` + 서명된 evidence bundle을, hardened fixture에 대해
  exit code `0` + non-proven bundle을 emit했다.
- `run project`가 `state-path` oracle을 **독립 HTTP 제어 채널**(공격 표면과 분리된
  owned control origin)로 witness해 BFLA를 proven/rejected로 판정했다.
- `twin prepare`가 제어 채널을 reset→snapshot→reset으로 구동해 baseline digest
  재현(disposable 무결성)을 검증했다.
- `replay`가 sealed bundle의 verdict를 receipts에서 결정적으로 재계산해 일치를
  확인했고, disposition을 위조한 bundle을 replay mismatch로 거부했다.
- `verify-fix`가 original(proven)+fixed(rejected) bundle을 비교해 benign-utility
  증명이 있을 때만 `fixed`(exit 0), 없으면 `utility-regression`(exit 1)을 반환했다.
- `evidence verify`가 서명된 causal bundle을 검증하고 proven finding에 대해 exit
  code `1`, tampered bundle에 대해 exit code `2`를 반환했다.
- `evidence render`가 signature 정보를 포함하고 raw canary/credential이 없는
  Markdown을 출력했다.

`test/fixtures/http-fixture.ts`는 두 tenant + item canary + admin reindex를 가진
실제 `http.Server` disposable fixture로, `vulnerable`/`fixed` 모드를 지원하고
Twin `StateController`(in-process reset/snapshot 제어 채널)를 겸한다.

## Acceptance matrix

| Criterion | Status | Evidence | Gap |
|---|---|---|---|
| `AC-101` | Satisfied | `src/authorization.ts:28-35`, `test/authorization.test.ts:35-38`, `test/authorization.test.ts:75-90` | foundation에는 실제 network client가 없으며 거부 전 callback event가 0임을 검증 |
| `AC-102` | Satisfied | `src/authorization.ts:33-35`, `test/authorization.test.ts:39-48` | production active run은 method/capability 분기 전에 거부 |
| `AC-103` | Satisfied | `src/authorization.ts:37-62`, `src/crypto.ts`, `test/authorization.test.ts:25-76` | unknown/revoked/tampered/expired/out-of-scope capability 검증 |
| `AC-104` | Satisfied | `src/run.ts:64-80`, `test/run-cli.test.ts:19-42` | preview artifact에 manifest/build/registry digest 기록 |
| `AC-204` | Partially satisfied | `src/discovery.ts`, `test/framework-mappers.test.ts`, `test/graphql.test.ts` | operator + OpenAPI + Next.js + Supabase + GraphQL(query/mutation) 정적 descriptor 매퍼. GraphQL은 HTTP runner로 실제 공격까지(BOLA E2E). browser/WS/gRPC/queue runtime discovery는 아직 없음 |
| `AC-205` | Satisfied | `src/coverage.ts:67-103`, `test/discovery-coverage.test.ts:55-81` | missing pack=`unsupported`, missing witness=`blocked`, 둘 다 coverage incomplete |
| `AC-206` | Partially satisfied | OpenAPI는 source 없이 surface를 생성 | traffic/runtime edge와 white-box edge 구분은 미구현 |
| `AC-400` | Satisfied | `src/validation.ts`의 `validateAttackProgram`, `test/registry-program.test.ts:47-66` | 모든 semantic field를 실행 전 검증 |
| `AC-703` | Partially satisfied | `src/coverage.ts:133-160`, `test/discovery-coverage.test.ts:39-53` | JSON ledger/blind spot과 no-`secure` 보장은 있음. report UI/첫 페이지는 없음 |
| `AC-803` | Partially satisfied | `src/run.ts:45-61`, `test/run-cli.test.ts:44-66` | high-risk pack은 disposable + Twin attestation을 요구. 실제 race/resource/parser runner event 검증은 없음 |
| `AC-804` | Satisfied | `src/safety.ts:135-192`, `test/safety-v3.test.ts` | executable/live-credential/real-recipient/external-analyzer corpus 거부 |
| `AC-805` | Satisfied | `src/safety.ts`, `src/pinning.ts`(`createPinnedDispatcher`), `src/http-runner.ts`, `test/hostname-pinning.test.ts`, `test/safety-v3.test.ts` | metadata/out-of-scope/DNS-rebinding 거부 + redirect scope 재검증. real run은 undici custom dispatcher로 소켓을 사전 resolve된 IP에 pin해 fetch 재-resolve TOCTOU를 차단(hostname target E2E). embedder-injected fetch 경로만 IP-리터럴로 제한 |
| `AC-901` | Satisfied (scoped) | `src/cli.ts`, `src/disposition.ts`, `test/run-project-cli.test.ts`, `test/replay-verify-fix.test.ts` | discover→coverage→twin prepare→run project→replay→verify-fix full CLI lifecycle. `replay`가 sealed bundle에서 verdict를 결정적으로 재계산(offline). live target을 재공격하는 CI replay와 hostname target은 로드맵 |
| `AC-902` | Satisfied | `src/cli.ts:194-205`, `src/cli.ts:240-244`, CLI smoke | discover/coverage는 network 또는 active attack 없이 동작 |
| `AC-903` | Partially satisfied | `src/registry.ts:29-60`, `src/validation.ts` pack validation, `test/registry-program.test.ts:15-46` | digest/signature/API/schema는 검증. target-version/safety mismatch는 coverage에서 제외되지만 전용 실행 테스트가 없음 |
| `AC-904` | Satisfied | `src/coverage.ts:105-131`, `src/cli.ts:194-205`, `test/run-cli.test.ts:91-126` | finding과 독립적인 coverage exit code `3` 검증 |
| `AC-905` | Partially satisfied | `src/diff.ts`, `test/discovery-coverage.test.ts:83-107` | surface, state, pack version diff 구현. finding lineage는 finding engine 전이라 없음 |
| `AC-906` | Satisfied | `src/registry.ts:29-52`, `test/registry-program.test.ts:22-45` | descriptor+digest 동시 변조와 revoked signer를 registry load 전에 거부 |

## Active causal HTTP + evidence slice

| Criterion | Status | Evidence | Gap |
|---|---|---|---|
| `AC-401` | Satisfied | `src/http-runner.ts`, `test/e2e-http.test.ts`, `test/run-project-cli.test.ts` | BOLA가 실제 `http.Server` fixture를 진짜 소켓(real fetch/DNS/TCP)으로 공격해 vulnerable에서 `proven`, fixed에서 `rejected`. `run project` CLI도 동일 경로 검증 |
| `AC-402` | Satisfied | `src/http-runner.ts`, `src/control-channel.ts`, `test/e2e-http.test.ts`, `test/control-channel.test.ts` | BFLA state effect가 real-socket E2E에서 `proven`/`rejected`, allowlisted `stateDiff`로만 disclose. state 관측이 공격 표면과 분리된 independent HTTP 제어 채널(`HttpControlStateController`)로도 검증됨 |
| `AC-601` | Partially satisfied | `src/http-runner.ts:358-373` | baseline/attack/counterfactual + replay threshold로 `proven`/`rejected`/`flaky`/`error` 판정 |
| `AC-602` | Partially satisfied | `src/witness.ts`, `test/evidence.test.ts` | monotonic sequence + payload/previous-event hash receipt chain. 단일 witness source |
| evidence integrity | Satisfied (scoped) | `src/evidence.ts`, `test/evidence.test.ts` | Ed25519 서명 bundle + content digest + redactedProgramDigest 독립 검증, redacted program/canary, digest-only state snapshot + allowlisted diff |

### 지원 attack family (동일 엔진, signed pack + fixture + program + witness)

엔진 코드 추가 없이 동일 causal 파이프라인으로 다음 4개 family를 vulnerable=proven /
fixed=rejected로 실증한다. 각각 disposable fixture + independent witness를 갖춘다.

| Family | Witness | Test |
|---|---|---|
| BOLA (object-level authz) | response-contains canary | `test/e2e-http.test.ts` |
| BFLA (function-level authz) | state-path over control channel | `test/e2e-http.test.ts`, `test/control-channel.test.ts` |
| Mass assignment (BOPLA) | state-path `adminCount` | `test/step-d-families.test.ts` |
| SSRF → owned canary sink | state-path `canarySinkHits` | `test/step-d-families.test.ts` |
| Idempotency duplicate-effect (BOPLA/workflow) | `state-path-delta-exceeds` | `test/oracle-families.test.ts` |
| Unauthorized non-numeric state change | `state-path-changed` (digest-redacted) | `test/oracle-families.test.ts` |
| Non-atomic partial commit | `partial-effect` | `test/oracle-families.test.ts` |
| GraphQL BOLA | response-contains over `/graphql` | `test/graphql.test.ts` |
| Workflow step-skip (ship without pay) | state-path `unpaidShipments` | `test/workflow-cache.test.ts` |
| Cache poisoning (cross-tenant cached body) | response-contains + per-request principal | `test/workflow-cache.test.ts` |
| Differential authz (BFLA, no marker) | `differential-access` (response equivalence) | `test/differential-oracle.test.ts` |
| SSRF outbound canary egress | `canary-egress` (owned sink sees the exact token) | `test/canary-egress.test.ts` |

oracle 평가는 `src/oracle.ts`로 분리(`evaluateOracle`), state diff의 비숫자 값은
digest로 redaction(Critical #3 / PRD 리뷰 m-6). oracle 종류: `response-contains`,
`state-path-increased`, `state-path-delta-exceeds`, `state-path-changed`,
`partial-effect`(비원자 commit 후 부분 효과, `test/oracle-families.test.ts`, AC-505/FR-509),
`differential-access`(두 principal 응답 동치로 authz 발산 검출, canary·상태변화 불요,
`test/differential-oracle.test.ts`, AC-504/FR-507),
`canary-egress`(owned sink이 정확한 run-scoped 토큰을 관측 — 카운터 증가가 아닌 실제 토큰
egress로 SSRF 증명, sink 값은 digest redaction, `test/canary-egress.test.ts`, FR-504/FR-810).

이 4개 외 family(GraphQL/WS/gRPC, path/command, agent/MCP/memory, race/parser 등)는
동일 계약(signed pack·applicability·fixture·witness·baseline/attack/counterfactual·
replay threshold·redacted evidence·cleanup·coverage ledger)을 요구하며 아직 미구현이다.

이번 slice에서 해소한 handoff Critical:

- **Critical #1 (evidence bundle 서명 부재)** → `EvidenceBundle.signature` Ed25519 서명 +
  `verifyEvidenceBundle(bundle, trustStore)` 도입. tamper는 content digest에서, 재계산 후
  forge는 signature에서 거부.
- **Critical #3 (raw state snapshot 유출)** → `SequenceReceipt`가 raw `beforeState`/
  `afterState` 대신 `beforeStateDigest`/`afterStateDigest` + oracle path allowlist diff만
  저장.

미해결로 남은 handoff 결함: Critical #2 (DNS/socket TOCTOU), High #4 (redacted-program
digest), #5 (surface inventory signature), #6-#9, Medium #11-#14.

## Runner hardening (handoff High findings)

| Finding | Status | Evidence |
|---|---|---|
| #4 redacted-program digest 독립 검증 | Resolved | `EvidenceBundle.redactedProgramDigest` + `verifyEvidenceBundle` 검증, `test/evidence.test.ts` |
| #5 surface inventory 얕은 검증 | Resolved | `validateSurfaceInventory`(stable-ID 재계산·중복·target 바인딩), `coverage.ts`, `test/inventory-hardening.test.ts` |
| #6 canary origin·repo path 정규화 | Resolved | `canonicalOriginHost`·absolute repo path, `test/manifest-hardening.test.ts` |
| #7 cookie jar 정교화 | Resolved | 복수 Set-Cookie·path/secure/expiry(`parseSetCookie`/`cookieHeader`), `test/cookie-jar.test.ts` |
| #8 cancellation | Resolved | `AbortSignal` + "cancel 후 새 step 0개", `test/cancellation.test.ts` |
| #9 witness/execution failure → structured error | Resolved | witness-chain·control-channel 실패를 `disposition: 'error'`로, `test/control-channel.test.ts` |

## Phase 2 종료 tranche (M1, `docs/product/spear-v3-next-spec.md` S1·S2·S3·S7·S8)

| 항목 | Status | Evidence |
|---|---|---|
| S1 finding-state schema + `report` (FR-704·706·707 / AC-702·703) | Satisfied | `src/report.ts`, `spear report`, `test/report.test.ts` — proven/candidate/rejected/flaky/error 분리, coverage-first, `secureVerdict:false`, redaction |
| S2 replay threshold 강제 (FR-603 / AC-601·602) | Satisfied | `validateCausalHttpAttackProgram`(deterministic all-success·nondeterministic 3/2), `test/replay-threshold.test.ts` |
| S3 causal minimizer (FR-604 / AC-603) | Satisfied | `src/minimizer.ts`, `run project --minimize`, `test/minimizer.test.ts` — 불필요 step 제거·predicate 유지·attack 비움 금지 |
| S7 retention lifecycle (FR-804 / AC-802) | Satisfied | `pruneEvidenceBundle`, `spear evidence prune`, `test/evidence.test.ts` — body digest화·재봉인·replay 유지 |
| S8 finding lineage diff (FR-908 / AC-905) | Satisfied | `diffFindings`(build-불변 lineageId), `spear diff --findings`, `test/report.test.ts` |

## Review findings disposition

| Review finding | Status | Disposition |
|---|---|---|
| `B-01` signed registry ambiguity | Satisfied | registry 전체 Ed25519 signature + pack canonical descriptor digest |
| `B-02` build digest source | Satisfied | CI/operator supplied SHA-256, manifest/profile exact match |
| `B-03` coverage-complete criteria | Satisfied | explicit policy, evidence grade, missing pack/witness failure |
| `H-01` oversized Phase 1 | Satisfied | foundation scope를 별도 선언하고 full Phase 1 완료를 주장하지 않음 |
| `H-02` mixed protocol gap | Partially satisfied | 현재 지원 범위를 operator/OpenAPI JSON으로 제한 |
| `H-03` pre-access authorization | Satisfied | run preparation의 첫 경계에서 authorization 검증 |
| `H-04` canonical signing | Satisfied | recursively sorted canonical JSON과 invalid-value rejection |
| `H-05` unsigned coverage trust | Satisfied | preview가 signed registry를 재검증하고 coverage를 내부 재계산 |

## 냉정한 release 판정

`0.3.0`은 **신뢰 가능한 v3 기반 + 실제 causal HTTP 공격 vertical**로 배포 가능하다.
BOLA·BFLA·mass assignment·SSRF 4개 family를 disposable fixture에서 실제 소켓으로
proven/rejected 실증하고, 서명된 증거·결정적 replay·fix 검증까지 CLI로 제공한다.
다만 "대부분의 제품을 커버한다"거나 "임의 hostname target을 공격한다"는 주장은
여전히 불가능하다.

첫 protocol vertical slice gate는 충족되었다:

1. disposable two-tenant fixture — ✅ `test/fixtures/http-fixture.ts`
2. exact-origin·IP-literal HTTP runner — ✅ `src/http-runner.ts`
3. BOLA/BFLA/BOPLA/SSRF attack programs — ✅ real-socket E2E
4. stateful HTTP witness·독립 제어 채널·canary provenance — ✅
5. vulnerable/fixed 양쪽 deterministic replay — ✅ `run project` proven/rejected
6. redirect/DNS/origin revalidation + IP-literal pinning으로 TOCTOU 차단 — ✅ (scoped)

handoff Critical(#1·#2·#3)과 High(#4–#9)는 모두 해소되었다(위 표 참조).

남은 확장(로드맵, 미구현):

- browser/WebSocket/gRPC/queue runtime discovery, agent/MCP·race/parser family
- live target을 재공격하는 CI deterministic replay(현재 `replay`는 offline verdict 재계산)
- HTTP 동시성(S4 paired/maxConcurrency 강제), stateful extraction(CSRF/object-id),
  browser/DB audit witness(FR-506)
