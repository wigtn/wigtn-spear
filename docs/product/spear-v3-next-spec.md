# SPEAR v3 — 다음 구현 세부명세

- 기준 문서: `docs/product/spear-v3-prd.md` (authoritative), `docs/product/spear-v3-foundation-acceptance-report.md`
- 작성일: 2026-07-24
- 대상 코드: 현재 `0.3.0` (77 tests green). **M1(S1·S2·S3·S7·S8)은 이미 구현·Satisfied**
  (acceptance report 참조). 이 문서의 나머지(S4~S12)가 다음 tranche의 **구현 가능한 설계**다.
- 원칙 (모든 항목이 반드시 보존): active access 전 authorization 검증 · signed
  registry/manifest · IP-literal origin pinning · disposable Twin · 독립 witness ·
  raw secret/canary redaction · `secure` verdict 금지 · finding 0개를 커버로 포장 금지 ·
  `proven`은 baseline/attack/counterfactual + deterministic replay threshold 필수.

## 0. 현재 상태 (baseline)

이미 구현되어 이 명세가 위에 쌓는 것:

- 모듈: `crypto` `authorization` `registry` `discovery` `coverage` `diff` `run`
  `validation` `safety` `twin` `control-channel` `witness` `disposition`
  `http-runner` `evidence` `cli` `types` `errors` `utils`
- CLI 16개: keygen, manifest/registry sign·verify, discover/map, coverage, diff,
  attack validate, run preview, twin prepare, run project, replay, verify-fix,
  evidence verify/render
- attack family 4종: BOLA, BFLA, mass assignment(BOPLA), SSRF→owned canary
- oracle 타입 2종: `response-contains`, `state-path-increased`
- 충족 FR(대표): FR-101~105, 205, 400, 401, 405, 605, 701·702(부분), 707, 801(scoped),
  804, 805(scoped), 902, 904, 906, 909; High #4~#9 해소.

## 1. Scope 및 우선순위

Phase 2(causal search·evidence) 종료 게이트를 먼저 닫고(S1~S8), 이후 Phase 3+
확장(S9~S12)으로 간다. S1~S8은 기존 엔진에 **직접 구현 가능**, S9~S12는 설계 결정이
필요해 open question을 명시한다.

| # | 항목 | PRD | 우선 | 규모 |
|---|---|---|---|---|
| S1 | finding state schema + report 산출물 | FR-704·705·706·707 / AC-702·703 | P0 | S |
| S2 | replay threshold 정책화(2/2·3/2) | FR-603 / AC-601·602 | P0 | S |
| S3 | causal minimizer | FR-604 / AC-603 | P0 | M |
| S4 | HTTP concurrency budget + paired 실행 | FR-802 / AC-801 | P1 | M |
| S5 | idempotency/retry duplicate-effect predicate | FR-806·414 / AC-405 | P1 | S |
| S6 | richer state oracle(differential·partial-effect) | FR-504·507·509 / AC-502·504·(505) | P1 | M |
| S6b | Twin fault 주입(FR-307) — S6 partial-effect 선행 | FR-307 / AC-505 | P1 | S |
| S7 | retention lifecycle(raw artifact expiry) | Privacy / AC-802 | P1 | S |
| S8 | finding lineage diff | FR-908 / AC-905 | P2 | S |
| S9 | hostname target socket pinning | FR-801·810 / AC-805 | P2 | M(의존성 결정) |
| S10 | protocol pack: GraphQL/WebSocket | FR-411 | P2 | L |
| S11 | interpreter/injection pack | FR-412·405 / AC-427 | P2 | L |
| S12 | compound agent/MCP/memory | FR-451~460 / AC-430~435·451~453 | P3 | XL |

---

## S1. Finding state schema + report 산출물 — FR-704·705·706·707, AC-702·703

**문제**: 현재 `run project`는 단일 run의 bundle만 낸다. PRD는 proven/candidate/
rejected/flaky/error를 **분리 출력**하고, finding 0개라도 첫 페이지에 coverage
ledger·blind spot·pack applicability를 요약하며 전체 `secure` verdict를 내지 않아야
한다(FR-706·707).

**설계**

새 타입 `types.ts`:

```ts
export interface CampaignReport {
  schemaVersion: '3.0';
  kind: 'campaign-report';
  target: TargetProfile['target'];
  generatedAt: string;
  // 첫 페이지 요약 — finding보다 먼저.
  coverage: {
    verdict: CoverageReport['verdict'];
    ledger: SurfaceCoverage[];
    blindSpots: CoverageReport['blindSpots'];
    packApplicability: Record<string, string[]>; // surfaceId -> pack ids (m-4)
  };
  findings: {
    proven: ProvenFinding[];
    candidate: CandidateFinding[];  // 아래 정의
    rejected: RunSummary[];
    flaky: RunSummary[];
    error: RunSummary[];
  };
  // 명시적: 전체 secure verdict 없음.
  secureVerdict: false;
  bundleRefs: Array<{ findingId?: string; runId: string; bundleId: string; disposition: CandidateDisposition }>;
}

export interface RunSummary {
  runId: string; programId: string; disposition: CandidateDisposition;
  attackSuccesses: number; attempts: number; reason: string;
}

// static/추론만으로 나온 것 — 확정 아님(FR-204).
export interface CandidateFinding {
  schemaVersion: '3.0'; state: 'candidate'; candidateId: string;
  surfaceId: string; family: string; rationale: string; provenance: 'static' | 'learned';
  confidence: 'low' | 'medium'; // LLM 단독 확정 금지
}
```

`ProvenFinding`에 FR-701 누락 필드 추가: `minimizedGraphPath: string[]`(S3),
`reproductionRate: number`.

**모듈**: `src/report.ts`
- `buildCampaignReport(coverage: CoverageReport, bundles: EvidenceBundle[], candidates: CandidateFinding[], trustStore): CampaignReport`
  — 각 bundle을 `verifyEvidenceBundle`로 재검증 후 disposition별 분류.
- `renderReportMarkdown(report): string` — 첫 섹션 = coverage 요약, 그 다음 findings.
  raw token/canary 미포함(`assertNoRawSecrets` 통과). `renderEvidenceMarkdown` 재사용.

**CLI**: `spear report --coverage <f> --bundles <dir|csv> --trust-store <f> [--candidates <f>] [--format json|md] [--output <f>]`
- 입력 bundle은 untrusted → 분류 전 `verifyEvidenceBundle`로 서명/digest/chain 검증.
  검증 실패(변조·revoked signer)는 **exit `2`**(현재 구현: verify가 throw → main catch가 2).
  verify 성공 전 `disposition`을 신뢰하지 않는다.
- exit: coverage-incomplete면 `3` 우선, 아니면 proven 있으면 `1`, 없으면 `0`. (M-5)

**테스트(AC-702·703)**: (a) 모든 finding state가 JSON에서 구분됨, (b) Markdown에
raw token/cookie/secret/canary 없음, (c) finding 0개 run도 coverage 요약·blind spot
출력하고 `secureVerdict:false`.

---

## S2. Replay threshold 정책화 — FR-603, AC-601·602 (구현됨, PRD 리뷰 M-1 반영)

**문제**: `minimumAttackSuccesses`/`repetitions`가 자유 입력이면 proven 기준이 약해진다.

**핵심 결정 (PRD 리뷰 M-1)**: `CausalHttpAttackProgram`은 **project-only·deterministic**
이므로 항상 **all-success(≥2/2)**. FR-603의 3/2 완화는 nondeterminism이 구조적인
compound/agent 프로그램 전용이며, HTTP 프로그램이 self-declared flag로 그 기준을 취할
수 없다.

**구현**: `validateCausalHttpAttackProgram`
- `execution.nondeterministic === true`이면 **거부**(HTTP는 deterministic).
- `repetitions >= 2`, `minimumAttackSuccesses === repetitions`(전량 성공) 강제.
- `nondeterministic` 필드는 미래 compound program 타입용으로 타입에 남기되 HTTP 검증기에서
  금지. compound 3/2 규칙은 compound program validator(S12)에서 별도 강제.

**테스트(AC-601·602)**: 2/2·3/3 통과, 3/2 deterministic 거부, HTTP `nondeterministic:true`
거부. baseline 발생 시 rejected, threshold 미달 시 flaky는 기존 커버.

---

## S3. Causal minimizer — FR-604, AC-603

**문제**: proven chain에서 불필요한 step/principal/mutation/setup을 제거해도 predicate가
유지되는 최소 causal chain을 찾아야 한다(현재 없음).

**설계**: `src/minimizer.ts`
- 입력: 재현 가능한 program + run 실행기(closure). delta-debugging(ddmin) 변형.
- 제거 후보: `execution.attack.requests[i]`, attack request의 개별 header, mutation
  단계. 각 후보 제거 → program 재실행 → 여전히 `proven`이면 제거 유지.
- 결정성: 제거 순서 고정(index asc), 무작위 없음. 예산: `maxTrials`(manifest budget
  하위, 기본 repetitions×후보수 상한).

```ts
export interface MinimizationResult {
  minimizedProgram: CausalHttpAttackProgram;
  removed: string[];              // 제거한 요소 라벨
  graphPath: string[];            // 남은 최소 carrier/step 경로 → ProvenFinding.minimizedGraphPath
  trials: number;
}
export async function minimizeCausalProgram(
  program, runInputsFactory, options
): Promise<MinimizationResult>
```

`run project`에 `--minimize` 플래그. minimizer 결과의 `graphPath`를 finding에 기록.

**안전**: minimizer는 attack step만 제거(추가 없음). budget 초과 시 현재까지 최소본
반환하고 `trials` 기록(silent cap 금지 — `log`).

**테스트(AC-603)**: baseline에 무의미 request 1개를 붙인 proven program → minimizer가
그 step을 제거하고 predicate 유지, 원본 lineage 보존.

---

## S4. HTTP concurrency budget 강제 + paired execution — FR-802, AC-801

**오너십(PRD 리뷰 M-6)**: S4 = paired/concurrent **실행 메커니즘** + concurrency budget
(AC-801). differential **oracle 판정**(FR-507/AC-504)은 S6가 소유하며 S4의 paired 결과를
소비한다. (§1 표의 FR-507/AC-504 중복 매핑은 S6로 단일화.)

**문제**: `manifest.safety.maxConcurrency`가 선언만 되고 강제 안 됨.

**설계**
- `StatefulHttpClient`에 세마포어(동시 in-flight ≤ maxConcurrency). 현재 sequence는
  순차라 위반 불가하지만, paired에서 두 principal 동시 실행 시 필요.
- 새 sequence 종류 `paired`: 같은 operation을 principal A/B로 동시 실행, 두 결과를
  differential oracle(S6)에 전달.
- budget: in-flight 카운터, `maxConcurrency` 초과 시 대기(throw 아님). request 총량
  budget은 기존대로.

**결정(PRD 리뷰 M-2)**: 완료 시각 기준 receipt 정렬은 receipt hash chain을 비결정적으로
만들어 replay/determinism(AC-501·701, NFR)을 깨뜨린다. → **correlation ID / logical send
order로 결정적 정렬**. sequence 내 request는 순차 유지, paired 두 sequence만 interleave하되
receipt는 고정 canonical merge order(예: principalId asc, 그다음 request index)로 append.

**테스트(AC-801)**: maxConcurrency=1에서 paired 요청이 직렬화됨; 같은 paired 공격을
반복 실행해도 receipt hash chain이 동일(결정적).

---

## S5. Idempotency/retry duplicate-effect predicate — FR-806, FR-414, AC-405

**문제**: 같은 attack step retry 시 duplicate side effect(중복 결제/중복 생성)를 별도
predicate로 관측해야 한다.

**설계**: 새 oracle kind.

```ts
| { kind: 'state-path-delta-exceeds'; witness: string; path: string; expected: number }
```
- attack sequence를 idempotency key 동일하게 N회 반복 → 상태 증가량이 `expected`(예: 1)
  초과면 duplicate-effect predicate 관측.
- `HttpRequestSpec`에 `idempotencyKey?: string`. retry는 `attempt` 번호와 key를
  receipt에 기록(FR-806).

**테스트**: 중복 방지 없는 fixture route에서 같은 key 2회 → delta 2 > 1 → proven;
idempotent fixture에서 delta 1 → rejected.

---

## S6. Richer state oracle — FR-504, FR-507, FR-509, AC-502·504·505

**문제**: oracle이 `response-contains`/`state-path-increased`뿐. FR-504는 object
ownership, row/file diff, process execution, outbound canary, differential, partial
effect까지 요구.

**설계**: oracle union 확장(`types.ts`), `predicateObserved`(http-runner)와 새
평가기 분리 모듈 `src/oracle.ts`.

```ts
export type CausalOracle =
  | { kind: 'response-contains'; ... }              // 기존
  | { kind: 'state-path-increased'; ... }           // 기존
  | { kind: 'state-path-changed'; witness; path; from?; to? }        // row/file diff
  | { kind: 'state-path-delta-exceeds'; witness; path; expected }    // S5
  | { kind: 'differential'; witness; comparePath; principals: [string,string] } // FR-507
  | { kind: 'partial-effect'; witness; committedPath; rolledBackPath }          // FR-509
  | { kind: 'canary-egress'; witness; sinkPath }    // outbound canary (SSRF 일반화)
```

- `evaluateOracle(oracle, ctx): boolean` — ctx = {observations, before, after, pairedResults?}.
- differential/partial-effect는 paired 또는 exception-injected run 필요(S4, Twin fault
  주입 FR-307). fault 주입은 control 채널 확장으로 뒤에.

**redaction(PRD 리뷰 m-6, Critical #3 불변식)**: 새 oracle의 `from`/`to` comparand와
row/file diff는 **절대 raw 값을 receipt에 저장하지 않는다**. 기존 digest +
oracle-path-allowlist 경로를 그대로 태워 label + digest만 남긴다(FR-804). oracle 평가는
in-memory raw 값으로 하되 저장은 digest.

**의존성(PRD 리뷰 M-3)**: `partial-effect` oracle은 Twin fault 주입(FR-307)이 선행이다.
→ FR-307 최소 deterministic fault-schedule을 S6에 포함하거나 M2 exit에서 AC-505를 빼고
M2b로 재매핑. 완료 전 AC-505를 M2 종료 기준으로 주장하지 않는다.

**open decision**: browser/DB audit witness(FR-506)는 새 witness adapter 필요. 이번
tranche는 HTTP+control-channel witness로 표현 가능한 oracle만(differential, delta,
changed, canary-egress).

**테스트(AC-502·504)**: HTTP 200이어도 cross-tenant state 변화 검출(state-path-changed);
actor만 바꾼 paired에서 differential. (AC-505는 FR-307 편입 후.)

---

## S7. Retention lifecycle — Privacy/retention, AC-802

**문제**: bundle은 redacted지만 raw artifact 만료 개념이 없다. AC-802: retention 만료
후 redacted bundle+lineage만 남고 raw prompt/response/DB diff 제거.

**설계**
- 현재 bundle은 이미 raw state를 저장하지 않음(digest+allowlisted diff). 남은 raw는
  `run.*.observations.body`(redacted text지만 최대 2KB 본문 유지).
- `EvidenceBundle`에 `retention: { rawExpiresAt: string; grade: 'full' | 'redacted-only' }`.
- `spear evidence prune --bundle <f> --trust-store <f>` — `rawExpiresAt` 경과 시
  observations.body를 digest로 대체하고 `grade: 'redacted-only'`로 재서명(재봉인).
  bundleDigest/signature 재계산, lineage(bundleId/finding ID) 보존.
- pruned bundle도 `replay`(offline verdict 재계산)는 가능해야 함 → replay는 body 원문이
  아니라 `predicateObserved` 플래그만 사용하므로 이미 호환.

**테스트(AC-802)**: prune 후 observations.body가 digest로 대체되고 replay/verify는
여전히 통과, finding ID 동일.

---

## S8. Finding lineage diff — FR-908, AC-905

**문제**: `diffCoverage`는 surface/state/pack만. finding lineage(같은 finding ID가
build 간 유지/신규/해소) 없음.

**설계**: `diff.ts`에 `diffFindings(from: CampaignReport, to: CampaignReport)`.
finding ID는 이미 `sha256(programId, buildDigest, predicate)` 기반 → build가 다르면
ID가 달라짐. lineage용 **build-불변 ID** 필요: `lineageId = sha256(programId, predicate)`.
`ProvenFinding.lineageId` 추가.

```ts
export interface FindingDiff {
  schemaVersion:'3.0'; kind:'finding-diff';
  fromBuildDigest:string; toBuildDigest:string;
  introduced: string[]; resolved: string[]; persisted: string[]; // lineageId
}
```

`spear diff --findings --from <report> --to <report>`.

**테스트(AC-905)**: 같은 취약점이 두 build에 있으면 persisted, 수정된 build에서 resolved.

---

## S9. Hostname target socket pinning — FR-801·810, AC-805 ✅ 구현됨 (2026-07-24)

**구현 결과**: 옵션 A 채택 — `undici` 런타임 의존성 추가(PRD §16 허용). `src/pinning.ts`
`createPinnedDispatcher`가 undici `Agent.connect.lookup`으로 pin된 IP만 반환, unpinned
host 거부. real run은 undici fetch + dispatcher로 hostname target을 소켓 pin해 공격
(`test/hostname-pinning.test.ts`). embedder-injected fetch만 IP-literal 유지. Twin control
origin은 IP-literal 유지. **아래 원문은 결정 배경 기록.**



**문제**: 현재 active origin은 IP-literal만(Critical #2 옵션3). hostname target을 실제
공격하려면 resolve된 IP로 소켓을 pin해야 한다.

**설계 / open decision (owner 결정 필요)**
- PRD §16 Assumption이 이미 "zero-runtime-dependency 제약은 제거할 수 있다"고 명시 →
  옵션 A의 "정책 포기" 비용은 대체로 사전 승인됨(m-2). 결정은 A 쪽으로 기운다.
- **옵션 A (권고)**: `undici`를 런타임 의존성으로 추가, `Agent({ connect: { lookup }})`로
  pin한 IP만 반환하는 custom lookup + Host/SNI 검증. `fetch(url, { dispatcher })`.
  undici는 Node 팀 제작·transitive dep 0.
- **옵션 B**: `net`/`tls` 직접 소켓 클라이언트. 의존성 없음, 그러나 redirect/chunked/TLS
  자체 구현(공격 표면·유지보수 비용).
- **옵션 C**: 현행 유지(IP-literal만), hostname은 계속 거부.

권고: 실제 hostname target 요구가 생기면 A. 그 전까지 C 유지. 결정 시 `DestinationGuard`
가 pin한 IP를 dispatcher lookup으로 강제하고, redirect/upgrade 후 재-pin(FR-810).

**테스트(AC-805)**: DNS rebinding fixture에서 resolve 변화 시 연결 전 차단; hostname
target이 pin된 IP로만 연결.

---

## S10. Protocol pack: GraphQL / WebSocket — FR-411, FR-810

**문제**: carrier가 HTTP REST만. GraphQL(operation/variable), WebSocket(upgrade+message)
carrier 필요.

**설계 (design sketch)**
- `SurfaceProtocol`에 이미 `graphql`/`websocket` 존재. runner를 protocol별 carrier로
  추상화: `interface Carrier { execute(sequence, principal, client): Promise<Observation[]> }`.
- GraphQL: POST `/graphql` body `{query, variables}`; oracle는 response-contains 또는
  state-path 재사용. principal/object/state graph 연결.
- WebSocket: upgrade 후 message 송수신, upgrade 직후 egress 재검증(FR-810).
- **핀닝(PRD 리뷰 M-4)**: Node 내장 `WebSocket`은 custom lookup/dispatcher socket pinning을
  노출하지 않아 S9의 IP pin을 지킬 수 없다. → WS carrier는 **IP-literal target으로 한정**
  (S9와 동일 자세)하거나 S9의 pinnable dispatcher(undici 기반)에 편입. "내장 WebSocket =
  zero-dep + safe"는 pinning 불변식과 양립 불가하므로 채택하지 않는다.
- **open decision**: WS witness 순서/타이밍의 결정성. 권고: message 송신 순서 고정,
  수신은 correlation ID로 매칭.

**테스트**: 기존 **AC-413(GraphQL)·AC-414(WebSocket/gRPC)** 재사용(m-1). GraphQL
BOLA(variable object id swap), WS message authz. 미커버 측면만 AC 신설.

---

## S11. Interpreter/injection pack — FR-412, FR-405, AC-427

**문제**: SQL/NoSQL/command/path/URL/template/header/XML injection을 context-aware
mutation + canary effect로 검증(현재 없음).

**설계 (design sketch)**
- Twin에 seeded sink 추가: fixture DB(canary row), disposable filesystem(canary path),
  sandbox process(canary marker), 각 sink hit을 control-channel state로 노출.
- oracle: `canary-egress`/`state-path-changed`(S6) 재사용 — sink에 canary가 도달하면
  proven. context matrix(SQL context, shell context, path context)는 mutation grammar를
  pack manifest에 선언(FR-409의 `mutationGrammar` 활용).
- **안전(FR-405·808)**: real secret/malware/external analyzer 금지 — 이미
  `validateAttackCorpus`가 강제.
- **hard prerequisite(PRD 리뷰 C-1)**: process/command sink는 반드시 **FR-309 sandbox
  (rootless container 이상, restricted outbound)** 안에서만 실행한다. host의 temp dir +
  whitelist command는 **host process 실행 = 불변식 위반**이므로 채택 금지. SPEAR는 현재
  sandbox S-item이 없으므로 S11 착수 전 "disposable sandbox runner"를 선행 S-item으로
  구축하고, PRD §16의 rootless-vs-microVM 결정을 hard predecessor로 둔다.
  sandbox 없으면 process/command family는 `blocked`/`coverage-incomplete`로 남긴다.
- SQL sink: in-memory canary-marker echo 또는 sandbox 내 disposable DB(의존성 결정 후).
  path sink: sandbox 내부 disposable path.

**테스트(AC-427)**: context 맞는 mutation만 sandbox seeded sink에 canary effect 생성,
잘못된 context는 rejected. sandbox 밖 egress/실행은 event 0건으로 거부(FR-807·309).

---

## S12. Compound agent / MCP / memory — FR-451~460, AC-430~435·451~453 (Phase 4, XL)

**문제**: `run compound` mode 전체 미구현. untrusted carrier(issue/PR/tool result/
memory) 주입 → agent plan → tool/backend → forbidden state 경로를 한 graph path로.

**설계 (high-level, 별도 상세 명세 필요)**
- 새 witness: tool gateway(FR-501), approval/delegation event(FR-502), memory lineage
  (FR-511). 모두 target self-report 밖 receipt.
- MCP pack: connection/approval/execution 시점마다 tool identity/schema/resource URI/
  server digest snapshot, rug-pull drift 탐지(승인 후 변경 시 재승인 없이는 호출 거부).
- memory pack: injection과 activation 분리, sleeper horizon, benign-memory utility
  paired replay.
- execution-authority differential(FR-460): 같은 NL content에 actor/scope/target
  metadata만 바꿔 action이 문체가 아니라 execution metadata에 결속되는지.
- **safety(FR-812)**: propagation hop/agent/session/artifact budget을 manifest에 고정,
  self-replicating payload Twin 밖 반출 금지.
- **open decision**: agent runtime을 무엇으로 fixture화할지(로컬 MCP stub server +
  scripted agent loop 권고). LLM 사용 시 판정은 deterministic oracle만(FR-408).

이 항목은 착수 전 별도 세부명세(`spear-v3-compound-spec.md`)를 요구한다.

---

## 2. 시퀀싱 / 마일스톤

- **M1 (Phase 2 종료)**: S1 → S2 → S3 → S7 → S8. Exit: AC-603·604·701·702·703·801·802·
  901·905. 산출물: `report`, minimizer, retention, finding lineage.
- **M2 (oracle 심화) — 구현 상태 (2026-07-24)**:
  - ✅ **S5** `state-path-delta-exceeds` + idempotency key (AC-405).
  - ✅ **S6** `state-path-changed`(비숫자 변화, digest redaction) (FR-504).
  - ✅ **S6b** `partial-effect` oracle + seeded 비원자 commit fixture (AC-505/FR-509).
    (전면적 FR-307 fault schedule(timeout/retry/out-of-order)은 별도 확장으로 남김 —
    exception/partial-commit fault는 AC-505 충족에 필요한 만큼 구현.)
  - ⏸ **S6 differential oracle(FR-507/AC-504)**: 별도 primitive 불필요로 판단. status-only
    differential은 baseline에서 오발동하고, "same object, actor만 다름"의 실질 판정은 이미
    causal baseline/attack/counterfactual(response-contains/state-path)이 differential로
    제공한다. 새 oracle 대신 기존 harness로 AC-504를 충족한다.
  - ⏸ **S4 concurrency/paired**: 결정적 concurrent execution은 race pack(FR-414/FR-807,
    high-risk, containment attestation + FR-307 fault schedule 선행) 소관으로 이동. 단독
    maxConcurrency 세마포어는 concurrent 실행 경로 없이는 dead code라 지금 넣지 않는다.
- **M3 (protocol·injection 확장)**: S9(결정 후) → S10 → S11. Exit: AC-427·805 확장 + 신설 AC.
- **M4 (compound)**: S12. 별도 명세 후 착수.

각 S는 독립 PR 단위. 모든 단계 종료 시 `npm run check` green + acceptance report의
해당 AC를 `Satisfied`로 갱신, HANDOFF 진행 로그 추가.

## 3. 공통 구현 규칙

- 새 artifact는 전부 `schemaVersion:'3.0'` + `kind` + 전용 validator. stored artifact는
  untrusted로 취급(변조 검증). 서명이 필요한 것은 Ed25519 + trust store.
- 새 oracle/carrier/pack은 §10 최종 판정 원칙의 10개 계약을 모두 통과해야 "지원"이다.
- exit code 계약(FR-909) 유지: 0 성공, 1 proven, 2 error, 3 coverage failure.
- 모든 신규 기능은 vulnerable+fixed fixture 쌍과 독립 witness 테스트를 동반한다.
- silent cap 금지: 예산/샘플링으로 커버를 줄이면 `log`로 남긴다.
