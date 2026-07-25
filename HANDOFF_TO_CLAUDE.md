# WIGTN SPEAR v3 — Claude handoff

작성 시각: 2026-07-23 (Asia/Seoul)  
저장소: `/Users/hyeonman/Desktop/kim/wigtn/wigtn-spear/wigtn-spear`

## 진행 로그

- **2026-07-25 Phase 4 이어서: project-only counterfactual 분리 FR-455 (`npm run check`: 118 passed).**
  - `AgentAttackProgram.projectOnly`(optional): agent 없이 동일 효과를 시도하는 직접 요청
    (`request` + `detection`: `canary-in-response`/`sink-egress`). `runAgentAttack`가 attack
    이후 실행해 `AgentRunResult.projectOnly`로 분류: `agent-required`(agent 경유만 효과 →
    진짜 AI 취약점) vs `backend-reachable`(백엔드 단독 가능 → misconfig). 직접 요청도
    scope/pin 강제, raw body 미저장(effect boolean+status만), program은 evidence에서 redact.
  - `validation.ts` projectOnly 검증(url/method/headers/body/detection; sink-egress는 sink 필수).
    fixture에 직접 `/config` 엔드포인트(`backendExposed`) 추가. `test/agent-injection.test.ts`에
    agent-required/backend-reachable 2케이스. **PR #15 브랜치 `feat/agent-attack-vertical`에 포함.**
  - 남음(우선순위): compound chain(injection→tool arg→기존 HTTP sink), MCP pack(FR-456),
    memory pack(FR-457/458), seed/mutation 생성기.

- **2026-07-25 Phase 4 이어서: agent CLI + hostname pinning + provider 프리셋 (`npm run check`: 116 passed).**
  - **`spear run agent`** CLI 추가(`src/cli.ts`): manifest/trust-store/profile/program +
    evidence 키 → 서명된 agent evidence bundle emit. proven=exit 1, error=exit 2, 그외 0.
    `validateAgentAttackProgram`(`src/validation.ts`): agent 프로그램은 구조적으로
    비결정적이므로 HTTP 규칙의 역 — `nondeterministic:true` 강제 + FR-603 완화 임계
    (repetitions≥3, minimumAttackSuccesses≥2). `test/run-agent-cli.test.ts` E2E(proven/rejected).
    예제 `examples/agent.program.json`.
  - **authorization 우선화**: `runAgentAttack`가 이제 raw manifest+trustStore+acknowledge를
    받아 `verifyAuthorization`(서명/scope/expiry/capability `run:agent`/build binding)을
    **네트워크 전에** 통과시킨 뒤에만 엔드포인트 접촉. `actualBuildDigest`는 target profile에서.
  - **hostname pinning(핵심)**: 실제 고객 엔드포인트는 hostname이므로, 기존 `src/pinning.ts`
    (`createPinnedDispatcher`)를 agent client에 연결. fetchImpl 미주입 시 origin을 `guard.pin`
    → undici pinned dispatcher로 연결 + 매 요청 `guard.revalidate`(DNS rebinding 차단).
    fetchImpl 주입 경로만 IP-literal 강제(http-runner와 parity). `src/agent/client.ts` 재작성.
  - **provider 프리셋**(`src/agent/providers.ts`): `openAiChatTarget`/`anthropicMessagesTarget`
    → `AgentTarget` 구성(bodyTemplate `{{message}}` + replyJsonPath). **API 키는 evidence에서
    redact**(`SECRET_HEADERS`: authorization/cookie/x-api-key/api-key)되고 env 주입 권장.
    `test/agent-providers.test.ts`(프리셋 유효성 + 키 미유출 실증).
  - **아직 남음(우선순위)**: project-only counterfactual 분리(FR-455) — agent 경유 필요
    vs backend 단독 구분; compound chain(injection→tool arg→기존 HTTP SSRF/BOLA sink);
    MCP pack(FR-456 shadowing/rug-pull); memory pack(FR-457/458 poisoning/sleeper).

- **2026-07-25 Phase 4 착수: agent injection attack vertical (`npm run check`: 112 passed).**
  - 배경: 고객사 authorized pentest 비즈니스(고객 AI/agent를 owned/authorized로 공격).
    실제 black-box agent 대상이라 fixture 순환논리 없이 발견 가능. 차별점은 payload가
    아니라 **증거 등급** — self-report(모델 텍스트)로 판정 안 하고 독립 witness가
    실제 effect를 관측했을 때만 `proven`(FR-408/FR-453).
  - 신규 `src/agent/`:
    - `types.ts` — `AgentTarget`(엔드포인트+body 템플릿+reply JSON path), `AgentSink`,
      `AgentAttackProgram`, `AgentRunResult`, oracle union.
    - `client.ts` — `callAgent`(소켓 전 `DestinationGuard` scope 검증, byte budget,
      redirect:error), `resetSink`/`sinkObserved`(owned witness 질의).
    - `oracle.ts` — `agent-canary-leak`(exact-match, proven급), `agent-tool-egress`
      (owned sink 관측, proven급), `agent-marker-compliance`(self-report, candidate 전용).
      `oracleEvidenceGrade`.
    - `run.ts` — `runAgentAttack`: baseline/attack×N/counterfactual + 3-of-2(FR-603),
      기존 `deriveCausalDisposition` 재사용. marker oracle은 명시적 거부. canary redaction
      + `assertNoRawSecrets`.
    - `evidence.ts` — `signAgentEvidence`/`verifyAgentEvidence`: canary-redacted Ed25519
      번들, redactedProgramDigest 무결성.
    - `probes.ts` — `PROBE_CATALOG`(direct extraction / role confusion / indirect
      tool-egress), 각 프로브가 자기 입증 oracle 선언.
  - fixture `test/fixtures/agent-fixture.ts`: 취약/수정 agent(+system-prompt secret,
    web-tool 시뮬레이션) + owned sink 서버. `test/agent-injection.test.ts`: leak
    proven/rejected, tool-egress proven(응답 아닌 sink이 입증)/rejected, marker 거부.
  - `src/index.ts`에 `./agent/index.js` barrel export. 설계·로드맵은
    `docs/product/agent-attack-design.md`.
  - **아직 남음(우선순위)**: CLI `run agent`(program JSON validation), 실 provider
    어댑터(OpenAI/Anthropic + MCP tool gateway witness; LLM은 seed/fixture 전용, 판정
    금지), project-only counterfactual 분리(FR-455), compound chain(injection→tool
    arg→기존 HTTP sink), MCP pack(FR-456), memory pack(FR-457/458).

- **2026-07-23 Step A 완료 (`npm run check`: 31 passed).**
  - Critical #1 해소: `EvidenceBundle`에 Ed25519 `signature` 추가.
    `createEvidenceBundle(run, program, signingKey, now)` /
    `verifyEvidenceBundle(bundle, trustStore)`. content digest + signature 이중 검증.
  - Critical #3 해소: `SequenceReceipt`가 raw `beforeState`/`afterState` 대신
    `beforeStateDigest` / `afterStateDigest` + oracle-path allowlist `stateDiff`만 저장.
  - Medium #15 해소: `test/evidence.test.ts` (bundle 서명 round-trip, event
    hash/removal/reorder tamper, content digest tamper, forge-after-reseal signature 거부,
    revoked key, Markdown redaction, verifyFix fixed/not-fixed/utility-regression).
  - CLI: `spear evidence verify` (proven=exit 1, tamper=exit 2), `spear evidence render`.
  - 아직 남음: Critical #2 (DNS/socket TOCTOU pinning), High #4-#9.

- **2026-07-24 Step B + Step C(run project) 진행 (`npm run check`: 35 passed).**
  - Step B: `test/fixtures/http-fixture.ts` — 실제 `http.Server` disposable fixture
    (two tenant, item canary, admin reindex, vulnerable/fixed 모드, Twin StateController 겸용).
    `test/e2e-http.test.ts` — injected mock이 아닌 **진짜 소켓**(real fetch/DNS/TCP)으로
    BOLA/BFLA를 vulnerable=proven / fixed=rejected 검증. → AC-401/AC-402 Satisfied 승격.
  - Step C: `spear run project` CLI 추가 — live target을 공격하고 서명된 evidence bundle을
    emit (proven=exit 1, non-proven=exit 0). `test/run-project-cli.test.ts`로 E2E 검증.
    `src/twin.ts`에 `ConstantStateController` 추가 (response-contains oracle 전용).
  - 제약: `run project`는 현재 `response-contains` oracle만 지원. `state-path` oracle은
    실제 Twin 제어 채널(`twin prepare`)이 필요해 명시적으로 거부한다.
  - 아직 남음: High #4-#9, `twin prepare` 제어 채널, `replay` / `verify-fix` CLI,
    Step D (Next.js/Supabase mapper, mass assignment, SSRF/path/command fixture, schema).

- **2026-07-24 Critical #2 (옵션 3: 스코프 제약으로 TOCTOU 차단, `npm run check`: 36 passed).**
  - 결정: zero-runtime-dep 유지. undici 의존성/손수 소켓 클라이언트 대신 active run의
    target origin을 **IP 리터럴로 강제**(hostname은 fetch가 재-resolve → TOCTOU라 거부).
  - `src/safety.ts` `assertPinnableActiveOrigins(manifest)` 추가, `runCausalHttpAttack`
    시작 시 호출. IPv4/IPv6/IP+port 허용, hostname 거부. `test/safety-v3.test.ts` 검증.
  - AC-805를 이 경계 안에서 **Satisfied (scoped)**로 승격.
  - 후속: hostname target을 실제 공격하려면 custom dispatcher/lookup socket pinning
    (undici 런타임 의존성 결정)이 필요 — 로드맵 항목으로 남김.

- **2026-07-24 Twin 제어 채널 + state-path oracle 지원 (`npm run check`: 40 passed).**
  - `src/control-channel.ts` `HttpControlStateController` — 공격 표면과 분리된 owned
    control origin에서 `snapshot`(GET)/`reset`(POST)으로 disposable state를 관측/복원.
    control origin도 IP-리터럴 + `manifest.safety.allowedControlOrigins` allowlist +
    metadata/DNS-rebinding 거부 + response byte budget을 강제.
  - types: `AuthorizationManifest.safety.allowedControlOrigins?`, `TwinDefinition.control`
    (`resetUrl`/`snapshotUrl`). validation/twin validation 확장.
  - `run project`: `state-path` oracle이면 `twin.control` 필수 → `HttpControlStateController`
    사용, 없으면 명확한 에러. `response-contains`는 여전히 `ConstantStateController`.
  - `twin prepare` CLI 신규: 제어 채널을 reset→snapshot→reset으로 구동해 baseline digest
    재현(disposable 무결성) preflight, `twin-preflight` artifact emit.
  - fixture: attack 서버 + **독립 control 서버(별도 포트)** 로 확장 → `/state`, `/reset`.
  - tests: state-path BFLA E2E(제어 채널) proven/rejected, `twin prepare` CLI,
    `run project` state-path CLI(서명 bundle), hostname control origin 거부.
  - 아직 남음: High #4-#9(concurrency, cookie jar, stateful extraction 등),
    `replay` / `verify-fix` CLI, Step D.

- **2026-07-24 Step C 마무리: `replay` + `verify-fix` CLI (`npm run check`: 44 passed).**
  - `src/disposition.ts` `deriveCausalDisposition`/`replayDisposition` — verdict 판정
    로직을 순수 함수로 추출. runner와 replay가 동일 로직을 공유(중복 제거).
  - `src/evidence.ts` `replayEvidenceBundle(bundle, trustStore)` — bundle 검증 후
    receipts에서 disposition/counter를 결정적으로 재계산해 recorded 값과 대조.
    불일치(위조된 disposition)면 거부. **offline**: live target 재공격 아님.
  - CLI: `spear replay`(proven=exit 1), `spear verify-fix --original --fixed
    [--benign-utility-passed]`(fixed=exit 0, 그 외=1). bundle의 `replayCommand`도 갱신.
  - tests: replay 일관성, disposition 위조 거부, verifyFix benign-utility 게이팅,
    replay/verify-fix CLI exit code.
  - Step C(twin prepare/run project/replay/evidence render/verify-fix)는 이제 완료.

- **2026-07-24 High #4-#9 runner 견고화 전부 해소 (`npm run check`: 61 passed).**
  - #4 `EvidenceBundle.redactedProgramDigest` — 저장된 redacted program을 독립 검증.
  - #5 `validateSurfaceInventory` — surface ID를 protocol/entryPoint/operation에서
    재계산해 불일치·중복·target 바인딩을 거부(coverage가 이걸 사용). `surfaceId`를
    validation.ts로 이동(discovery와 공유).
  - #6 `canonicalOriginHost` — canary/control origin 정규 exact-origin 강제 +
    repositoryPath absolute 강제.
  - #7 cookie jar — 복수 Set-Cookie(`getSetCookie`), path scoping, Secure,
    Max-Age<=0/과거 Expires 삭제. `parseSetCookie`/`cookieHeader` export.
  - #8 cancellation — `CausalHttpRunOptions.signal`, 매 sequence/request 전 abort 체크,
    fetch에 signal 전달. cancel/budget은 throw로 전파.
  - #9 witness/execution 실패 → `disposition: 'error'` 구조화(throw 대신). control
    channel fetch 실패도 `SpearExecutionError`로 감싸 error disposition. replay는
    error run을 특수 처리, `run project`는 error에 exit 2.
  - 아직 남음: Step D(Next.js/Supabase mapper, mass assignment, SSRF/path/command
    fixture, candidate schema 확장), live-target CI replay, hostname target(undici).

- **2026-07-24 Step D 착수: mass assignment + SSRF family (`npm run check`: 63 passed).**
  - `test/fixtures/http-fixture.ts` 확장: body 파싱 + `POST /profile`(mass assignment/
    BOPLA) + `POST /fetch`(SSRF→owned canary sink). 상태에 `adminCount`,
    `canarySinkHits` 추가(control /state·reset도 갱신).
  - `test/step-d-families.test.ts`: mass assignment(state-path `adminCount`)와
    SSRF(state-path `canarySinkHits`)를 control 채널 witness로 proven/rejected E2E.
    **엔진 코드 추가 0** — 기존 state-path + control-channel 파이프라인이 그대로 일반화됨.
  - 지원 family 현재 4종: BOLA, BFLA, mass assignment, SSRF-to-owned-canary.
  - 아직 남음: path/command·GraphQL/WS·agent/MCP family, live-target CI replay,
    hostname target(undici pinning).

- **2026-07-24 세부명세 작성 + Phase 2 종료 tranche(M1) 구현 (`npm run check`: 77 passed).**
  - 명세: `docs/product/spear-v3-next-spec.md` — 남은 로드맵(S1~S12)을 PRD FR/AC에
    매핑한 구현 가능 설계. M1=S1·S2·S3·S7·S8, M2=S4·S5·S6, M3=S9·S10·S11, M4=S12.
  - S1 `src/report.ts` `buildCampaignReport`/`renderReportMarkdown` + `spear report`:
    proven/candidate/rejected/flaky/error 분리, coverage-first, `secureVerdict:false`.
    `ProvenFinding`에 `lineageId`/`reproductionRate`/`minimizedGraphPath` 추가.
  - S2 `validateCausalHttpAttackProgram`: deterministic=all-success(≥2/2),
    nondeterministic=3/2 강제(FR-603).
  - S3 `src/minimizer.ts` delta-debug + `run project --minimize`: 불필요 attack step 제거.
  - S7 `pruneEvidenceBundle` + `spear evidence prune`: body digest화·재봉인, replay 유지.
  - S8 `diffFindings`(build-불변 lineageId) + `spear diff --findings`.
  - CLI 18개.

- **2026-07-24 PRD 리뷰 + 코드 리뷰 반영 (`npm run check`: 78 passed).**
  - PRD 리뷰(next-spec): M-1(이미 구현된 S2 결함) → `CausalHttpAttackProgram`은
    `nondeterministic:true` 거부, 항상 all-success(2/2) 강제. 나머지 C-1/M-2~M-6/m-1~m-6은
    미구현 S-item spec 결함이라 next-spec 문서에 반영.
  - 코드 리뷰: cookie path-match 경계 버그(`/admin`→`/administrator` 누출) → RFC 6265
    `pathMatches`로 수정 + 회귀 테스트. error 재throw 정규식·report exit 우선순위는 문서화.

- **2026-07-24 M2 착수: oracle 리팩터 + S5 + S6(changed) (`npm run check`: 80 passed).**
  - `src/oracle.ts` `evaluateOracle` 추출(refactor, http-runner에서 분리).
  - S5 `state-path-delta-exceeds` oracle + `HttpRequestSpec.idempotencyKey`(Idempotency-Key
    헤더) → idempotency replay duplicate-effect(FR-806/AC-405). fixture `POST /order`.
  - S6 `state-path-changed` oracle(비숫자 변화) + state diff 비숫자 값 digest redaction
    (m-6). fixture `POST /rotate`.
  - `test/oracle-families.test.ts`: 둘 다 proven/rejected + 원값 미유출 검증.
- **2026-07-24 M2 마무리: S6b partial-effect (`npm run check`: 81 passed).**
  - `partial-effect` oracle(`{committedPath, rolledBackPath}`): 비원자 commit 후 한 쪽만
    변경되면 violation. `evaluateOracle`에 추가, `oracleStatePath`→`oracleStatePaths`(다중
    경로 allowlist) 리팩터. fixture `POST /transfer`(seeded partial commit). AC-505/FR-509.
  - **M2 결론**: S5·S6·S6b 완료. **differential oracle(AC-504)은 미구현 결정** — status-only는
    baseline 오발동, 실질 differential은 기존 causal harness가 제공(중복). **S4 concurrency는
    race pack(FR-414/FR-807)으로 이동** — 결정적 concurrent 실행 + containment 필요.
  - oracle 5종: response-contains, state-path-increased/delta-exceeds/changed, partial-effect.
- **2026-07-24 M3 착수: GraphQL 프로토콜 지원 (`npm run check`: 84 passed).**
  - `surfacesFromGraphql`(query/mutation → `graphql` surface, mappingSource `graphql-schema`)
    + `discoverSurfacesFrom({graphql})` + CLI `--graphql`. `MappingSource`에 `graphql-schema` 추가.
  - fixture `POST /graphql`(node(id) query, vulnerable=cross-owner canary 노출).
  - `test/graphql.test.ts`: 매퍼 unit + GraphQL BOLA E2E(proven/rejected, canary redaction).
    GraphQL은 HTTP 위이므로 기존 HTTP runner + response-contains oracle 재사용(엔진 추가 0).
- **2026-07-24 추가 HTTP 계열 + per-request principal (`npm run check`: 86 passed).**
  - `HttpRequestSpec.asPrincipalId`: 한 sequence 안에서 request별 다른 Twin principal로
    실행(FR-403/404). executeSequence가 per-request 해결.
  - workflow step-skip(pay 없이 ship → `unpaidShipments` state-path, FR-414) fixture
    `POST /pay`·`/ship`. cache poisoning(cross-tenant 캐시 응답, FR-416) fixture `GET /me`
    + asPrincipalId로 A seed→B read. `test/workflow-cache.test.ts` proven/rejected.
  - 지원 family 9종(HTTP): BOLA/BFLA/BOPLA/SSRF/idempotency/config-change/partial-effect/
    workflow-skip/cache + GraphQL BOLA.

- **2026-07-24 S9: hostname target socket pinning — undici 도입 (`npm run check`: 87 passed).**
  - **런타임 의존성 `undici` 추가**(첫 런타임 dep, PRD §16 허용). transitive dep 0.
  - `src/pinning.ts` `createPinnedDispatcher(pins)`: undici `Agent`의 custom `connect.lookup`이
    사전 pin된 IP만 반환 → 소켓이 resolve된 IP에 고정, Host/SNI는 hostname 유지. unpinned
    host는 소켓 열기 전 거부. lookup은 `all:true`시 `[{address,family}]` 형식.
  - `DestinationGuard.pins` getter(live map). `StatefulHttpClient`은 fetchImpl 없을 때
    undici fetch + pinned dispatcher 사용, fetchImpl 주입 시 IP-literal 강제 유지.
  - `runCausalHttpAttack`: `assertPinnableActiveOrigins`는 fetchImpl 주입 경로에만 적용.
  - `test/hostname-pinning.test.ts`: hostname `app.fixture`를 loopback resolver로 pin해
    실제 undici fetch로 BOLA proven/rejected. **Critical #2 완전 해소, AC-805 Satisfied.**
  - Twin control origin은 여전히 IP-literal(owned infra, 보통 localhost).

- **자율 구현이 남은 나머지 (owner 결정/인프라 필요):**
  - **WebSocket/gRPC**: Node 내장 WebSocket은 client-only(WS **server** 없음) → `ws`/protobuf
    의존성 결정 필요. (이제 undici 있으니 WS client pinning은 가능하나 테스트용 WS server가 없음.)
    - **2026-07-24 결정: WebSocket e2e 실증은 명시적으로 다음으로 defer.** causal 엔진은
      HTTP/GraphQL로 이미 재사용 가능하므로 transport(연결·메시지)만 남았지만, fixture용 WS
      server(`ws` dev 의존성)와 undici WebSocket pinnable dispatcher 편입(M-4)이 선행 조건.
      우선순위 낮음 — owner가 재개 지시할 때 착수.
  - **injection/process pack(S11)**: FR-309 sandbox(rootless container) 인프라 선행 필요.
  - **compound agent/MCP/memory(Phase 4, FR-451~463)**: agent runtime/LLM 통합 필요.
  - **race pack**: 결정적 concurrent 실행 + FR-307 fault schedule + containment attestation.
  - **adaptive search(FR-407)·real-target 검증(Phase 5)**: PRD Go-gate 대상.

- **2026-07-25 Postman(v2.1) discovery 매퍼 (`npm run check`: 109 passed).**
  - HAR(캡처)에 이어 Postman(authored collection) 매퍼. `surfacesFromPostman`: `item[]` 재귀 walk
    (폴더 중첩), request의 method+URL(raw string 또는 `{path:[...]}`) 추출, path 변수(`:id`/`{{var}}`)를
    공유 `templatizePath`에서 `{id}`로 정규화(HAR과 수렴), auth block(non-noauth)·Authorization 헤더로
    principal 판정.
  - `MappingSource`에 `'postman'`, `DiscoverySources.postman`, CLI `--postman`.
    `templatizePath`를 `:x`/`{{x}}`도 처리하게 확장(HAR엔 무해). `test/postman-mapper.test.ts`.

- **2026-07-25 coverage policy 속성 기반 요구 `requiredDataClasses` (`npm run check`: 106 passed).**
  - policy가 surface를 명시적 ID로만 요구 가능했던 것(빌드마다 ID churn) 개선. `requiredDataClasses`:
    해당 data class를 가진 모든 surface는 (1) unsupported/blocked면 안 되고(hard gap), (2) grade floor
    (minimumEvidenceGrade) 충족해야 함. optional이라 back-compat.
  - `types.ts`(optional 필드), `validation.ts`(있을 때만 stringArray 검증),
    `coverage.ts`(matchedDataClasses → requiredByPolicy 확장 + unsupported/blocked 명시 unmet).
  - `test/coverage-policy-dataclass.test.ts`: 속성 선택으로 grade floor 적용/미적용, unsupported gap,
    back-compat.

- **2026-07-25 `response-header-contains` oracle + CORS misconfig family (`npm run check`: 103 passed).**
  - 응답 헤더에 금지 값이 있으면 forbidden(FR-504). CORS 오설정(공격자 Origin이 ACAO에 반영)·
    open redirect(Location에 외부 host)·헤더 인젝션 커버. 헤더명 case-insensitive, 값 substring.
  - `types.ts`/`oracle.ts`(observation.headers 조회)/`validation.ts`. `oracleStatePaths` `[]`.
  - fixture: `#json`에 extraHeaders 파라미터 추가, `/data` route가 Origin을 vuln 모드에선 무조건,
    fixed 모드에선 allowlist(`https://trusted.app`)만 ACAO에 반영. 공격 request는 `origin` 헤더
    주입(FORBIDDEN_HEADERS에 없음). counterfactual은 trusted origin이라 미반영.
  - `test/cors-misconfig.test.ts` proven(attacker origin 반영)/rejected(allowlist만).

- **2026-07-25 campaign report에 coverage↔evidence 교차 참조 추가 (`npm run check`: 101 passed).**
  - report가 coverage ledger와 evidence bundle을 각각 보여주기만 하고 교차 참조가 없던 것 개선.
    `CampaignReport.coverageSummary`: (1) 상태별 surface count(`byState`), (2) `attackableUnexercised`
    — state='attackable'인데 어떤 verified bundle도 안 친 surface id(bundle `attackProgram.carrier.entryPoint`
    ↔ `surface.entryPoint` 매칭). red-team "다음에 칠 것" to-do.
  - `renderReportMarkdown`에 "## Coverage summary" + "Attackable, not yet exercised" 섹션.
    `test/report.test.ts` 확장(byState·attackableUnexercised·markdown 검증).

- **2026-07-25 HAR discovery 매퍼 추가 (`npm run check`: 101 passed).**
  - 정적 descriptor 매퍼(OpenAPI/Next/Supabase/GraphQL)에 이어 **캡처 트래픽(HAR)** 매퍼.
    브라우저 devtools·프록시 export → 공격표면. red-team 워크플로(실트래픽 → surface)에 부합.
  - `surfacesFromHar`: `log.entries[].request`의 method+URL path 추출, path의 ID 세그먼트
    (숫자·UUID·24+ hex)를 `{id}`로 **템플릿화**해 폭발 방지, Authorization/Cookie 헤더 유무로
    principal 판정. 반복 캡처는 buildInventory `mergeSurface`로 병합.
  - `MappingSource`에 `'har-capture'` 추가(types/validation `MAPPING_SOURCES`). `DiscoverySources.har`,
    CLI `discover`/`map`에 `--har`. `test/har-mapper.test.ts`(템플릿화·병합·malformed 거부).
  - HAR은 target host로 스코프됐다고 가정(다른 매퍼처럼 descriptor 신뢰).

- **2026-07-25 stacked PR mis-merge 복구 + 브랜치 정리.** PR #4~#7이 auto-retarget 실패로
  중간 브랜치에만 머지되어 main엔 #3까지만 반영됐던 것을 단일 PR #8로 main에 통합(96 tests).
  이후 모든 dangling 브랜치 삭제 → 원격·로컬 main만 남김. **교훈: stacked PR는 머지 시
  head 브랜치 삭제 체크해야 GitHub가 다음 PR base를 자동 재지정.**

- **2026-07-25 `response-field-present` oracle + excessive-data-exposure family (`npm run check`: 98 passed).**
  - FR-504/OWASP API3(BOPLA 읽기측): 응답이 principal이 봐선 안 되는 필드를 구조적으로 노출하면
    forbidden. **JSON path 존재**로 판정 → 비밀 값을 몰라도 누출 탐지(값은 redaction). mass-assignment
    (쓰기측)의 읽기측 대응.
  - `types.ts`(`response-field-present` requestId/jsonPath, http-gateway witness), `oracle.ts`
    (`parseJson`+getPath 존재, 2xx 요구; `oracleStatePaths` `[]`), `validation.ts` 검증.
  - fixture: `/account` route가 `?include=secret` selector를 vuln 모드에서만 존중해 `apiKey`
    (=`ACCOUNT_SECRET` 캐너리) 노출. baseline/counterfactual은 selector 없어 필드 부재.
    `test/excessive-data-exposure.test.ts` proven/rejected + secret redaction 검증.

- **2026-07-24 PR #2 머지 후 `differential-access` oracle 추가 (`npm run check`: 89 passed).**
  - S6/FR-507/AC-504: 두 principal이 같은 operation을 발행해 unprivileged가 privileged와
    **동일한 2xx 응답**을 얻으면 forbidden(authz 발산, BFLA). canary·상태변화 없이 응답 동치만으로
    탐지하는 새 primitive.
  - `src/types.ts` CausalOracle union에 `differential-access`(privilegedRequestId/
    unprivilegedRequestId) 추가. `src/oracle.ts` `evaluateOracle`에 판정(양쪽 2xx + body 동일),
    `oracleStatePaths`는 `[]`(response-only, state diff 없음). `src/validation.ts`에 검증
    (두 requestId distinct, http-gateway witness 강제).
  - fixture 신규 route `GET /admin/report`: vulnerable=아무 actor나 동일 report, fixed=`admin`만
    200/그외 403. `test/differential-oracle.test.ts`로 proven(vuln)/rejected(fixed) 실증.
  - causal 매핑: 한 attack sequence 안에서 `asPrincipalId`로 priv(admin)/unpriv(user-b) 발행,
    counterfactual은 unpriv가 자기 소유 `/items/item-b` 요청(endpoint swap 제거)→응답 발산. 순차라 결정적.
  - **S4 concurrency semaphore는 보류**: sequence가 순차라 in-flight≤1, never-triggers여서 가치 낮음.
    paired race family 착수 시 함께 구현.
  - **WebSocket e2e는 명시적 defer**(owner 결정, 2026-07-24). `ws` dev 의존성 + undici WS pinnable
    dispatcher(M-4) 선행.

- **2026-07-24 `state-path-decreased` oracle + audit-tampering family (`npm run check`: 96 passed).**
  - monotonic 하향 위반(감사 로그 purge·잔고 underflow·버전 롤백) 탐지. 숫자 기반이라 redaction
    이슈 없음. `types.ts`/`oracle.ts`(after<before)/`validation.ts`(path+witness 그룹).
    `oracleStatePaths`는 default `[path]`로 이미 커버.
  - fixture: `#auditCount`(reset 시 3 seeded), `/audit/purge`(vuln=아무나→0, fixed=admin만/403).
    `test/audit-tampering.test.ts` proven(3→0)/rejected.

- **2026-07-24 evidence 강화 + CLI 정리 + retention 만료 강제 (`npm run check`: 94 passed).**
  - **강화(보안)**: canary-egress가 evidence bundle에 raw egress 토큰을 leak하던 것 차단.
    `sanitizedProgram`이 `oracle.canary` + 그 토큰을 담은 request path/body까지 redaction.
    `test/canary-egress.test.ts`가 bundle JSON에 raw 토큰 없음을 검증.
  - **CLI 정리**: `run project`가 `response-contains`만 constant Twin으로 하드코딩 → 응답전용
    `differential-access`가 불필요하게 control 요구. `oracleStatePaths(oracle).length===0`으로
    판별하도록 교체(원칙: state 경로 보는 oracle만 control 필요). help/README 정확화.
  - **retention 개선(S7 후속)**: `rawExpiresAt`가 장식이던 것 → 강제. `retentionDue(bundle,now)`
    + `evidence prune --if-expired`(경과 전·이미 pruned면 서명키 없이 no-op, cron 안전).
    `pruneEvidenceBundle` 멱등화(redacted-only 그대로 반환). 창 설정 `--retention-days`/
    `createEvidenceBundle(...,retentionDays)`. `test/evidence.test.ts`·`test/replay-verify-fix.test.ts`.

- **2026-07-24 `canary-egress` oracle 추가 (`npm run check`: 91 passed).**
  - FR-504/FR-810: owned sink이 **정확한 run-scoped canary 토큰**을 관측했으면 forbidden.
    기존 SSRF는 `state-path-increased`(canarySinkHits 카운터)로 우회 — "카운터가 늘었다"만
    보증, 무관 트래픽 false-positive 가능. canary-egress는 그 토큰이 실제 egress됐음을 증명.
  - `types.ts`에 `canary-egress`(sinkPath/canary) 추가. `oracle.ts` `evaluateOracle`:
    after의 sinkPath 값이 canary 포함 && before는 미포함. `oracleStatePaths`는 `[sinkPath]`.
    `validation.ts` 검증(sinkPath/canary/witness string).
  - fixture: `#canarySink` state 추가(`#state()`/`reset()` 반영), `/fetch` vulnerable이 probe
    URL을 sink에 기록. `CANARY_EGRESS` 상수. sink 값은 비숫자라 allowlistedStateDiff에서
    digest redaction → raw canary 미저장(테스트로 `!JSON.stringify(run).includes(CANARY_EGRESS)` 검증).
  - `test/canary-egress.test.ts`: proven(vuln)/rejected(fixed).

- **2026-07-24 Step D: Next.js/Supabase passive discovery 매퍼 (`npm run check`: 67 passed).**
  - `src/discovery.ts`: `surfacesFromNextRoutes`(route-handler/server-action/middleware),
    `surfacesFromSupabase`(table+RLS flag→rls-disabled state dep, storage bucket),
    `discoverSurfacesFrom(profile, {openApi,nextRoutes,supabase})` 통합 진입점.
    기존 `discoverSurfaces(profile, openApi?, now?)`는 back-compat 유지.
  - `MappingSource`에 `'next-app'|'supabase'` 추가(types/validation/inventory 검증 확장).
  - CLI `discover`/`map`에 `--next-routes`, `--supabase` 플래그. 실제 CLI로
    operator+next+supabase 병합 inventory 생성 확인.
  - `test/framework-mappers.test.ts`: 매핑 정확성 + 병합 inventory 유효성.
  - AC-204를 정적 descriptor 매퍼 범위로 확장(여전히 Partially satisfied; runtime
    discovery 없음).

## 1. 사용자 의도

사용자는 기존 SPEAR를 전부 갈아엎고 다음 제품을 원한다.

> 소유하거나 명시적으로 테스트 승인을 받은 프로젝트와 AI agent의 공격 표면을
> 찾아 실제 forbidden state/effect를 독립 witness로 입증하는 red-team system.
> 웹·백엔드·agent를 폭넓게 커버하되, finding 0개를 `secure`로 포장하지 않고
> 미지원 surface와 witness gap을 명시해야 한다.

기존 Judgement Day 2026 대회용 scenario/multimodal submission, authority spoof,
social-engineering 계열 코드는 폐기 대상이다. 현재 git에 보이는 대규모 삭제는
의도된 cutover다. **복원하거나 reset하지 말 것.**

TAC(Trusted Access for Cyber)는 신청하지 않는다. 사이드 프로젝트이며, 구현과
테스트는 owned/disposable/local fixture로 제한한다.

## 2. 권위 문서

1. `docs/product/spear-v3-prd.md` — authoritative PRD
2. `docs/product/spear-v3-implementation-readiness-review.md` — 구현 전 blocker 결정
3. `docs/product/spear-v3-foundation-acceptance-report.md` — 이전 foundation 검증.
   현재 구현 진척(21 tests)을 반영하지 않아 업데이트 필요
4. `docs/security/threat-model.md`
5. `docs/security/standards-baseline.md`

PRD 규모:

- 112 functional requirements
- 85 acceptance criteria
- Phase 0–4

전체 PRD는 아직 완료되지 않았다. 현재 상태를 “대부분 제품 커버” 또는 “full
Phase 1”로 표현하면 안 된다.

## 3. 현재 구현된 구조

### Foundation

- `src/crypto.ts`
  - recursively sorted canonical JSON
  - SHA-256 digest
  - Ed25519 sign/verify/key generation
- `src/authorization.ts`
  - acknowledgement, production reject, expiry, build, capability, key
    revocation/signature 검증
- `src/registry.ts`
  - signed registry
  - canonical pack descriptor digest
  - target version matching
- `src/discovery.ts`
  - operator fixture + OpenAPI 3.x JSON passive surface discovery
- `src/coverage.ts`
  - pack applicability, witness readiness, policy/evidence grade
  - `unsupported` / `blocked` / `attackable`
  - finding 수와 독립적인 `coverage-incomplete`
- `src/diff.ts`
  - surface/state/pack-version diff
- `src/run.ts`
  - run preview
  - signed registry를 다시 검증하고 coverage를 내부 재계산
  - stored unsigned coverage artifact를 권한 입력으로 신뢰하지 않음
  - high-risk pack은 disposable + Twin attestation 요구

### 새로 추가한 active vertical slice

- `src/safety.ts`
  - exact-origin target/canary guard
  - metadata IP 차단
  - redirect/callback/upgrade에 재사용 가능한 URL revalidation
  - DNS answer change 감지
  - inert file / fixture identity / `.test` recipient / owned analyzer corpus 검증
- `src/twin.ts`
  - four-principal/two-tenant definition 검증
  - unique asset canary
  - baseline snapshot, reset, digest 검증
- `src/witness.ts`
  - monotonic sequence
  - payload digest
  - previous-event hash
  - receipt-chain verification
- `src/http-runner.ts`
  - stateful principal headers와 cookie jar
  - mutating-method permission
  - request/wall-time/response-byte budget
  - manual redirect + scope 재검증
  - baseline / attack repetitions / counterfactual
  - response-canary 및 independent state-path oracle
  - `proven` / `rejected` / `flaky`
  - response body의 known canary와 credential pattern redaction
- `src/evidence.ts`
  - evidence bundle, stable finding ID, Markdown rendering, fix verification
  - **컴파일은 되지만 아직 전용 테스트 및 CLI 연결 없음**

### CLI

`src/cli.ts`에 현재 있는 명령:

- `keygen`
- `manifest sign`
- `registry sign`
- `registry verify`
- `discover` / `map`
- `coverage`
- `attack validate`
- `run preview`
- `diff`

아직 없는 명령:

- 실제 `run project`
- `run compound`
- `twin prepare`
- target replay
- evidence render/verify
- `verify-fix`
- CI deterministic replay

## 4. 현재 실행 증거

마지막 실행:

```text
$ npm run check
typecheck: pass
tests: 21 passed, 0 failed
```

현재 중요한 passing tests:

- signed authorization:
  - missing acknowledgement
  - production
  - expired
  - capability/build mismatch
  - unknown/revoked key
  - tampered signature
  - rejection 전 target callback 0회
- signed registry:
  - descriptor+digest 동시 변조
  - digest mismatch
  - revoked signer
- coverage:
  - missing pack=`unsupported`
  - missing witness=`blocked`
  - exit code 3
- active:
  - BOLA vulnerable=`proven`, fixed=`rejected`
  - BFLA vulnerable=`proven`, fixed=`rejected`
  - two attempts / two successes threshold
  - known canary가 result JSON에서 제거됨
- safety:
  - executable corpus
  - live credential
  - real recipient
  - external analyzer
  - out-of-scope origin
  - metadata IP
  - DNS answer change

테스트 파일:

- `test/authorization.test.ts`
- `test/registry-program.test.ts`
- `test/discovery-coverage.test.ts`
- `test/run-cli.test.ts`
- `test/safety-v3.test.ts`
- `test/causal-http.test.ts`

기본 확인 명령:

```bash
npm run check
git diff --check
node dist/src/cli.js help
```

## 5. 절대 보존할 결정

1. active access 전에 authorization 검증이 모두 끝나야 한다.
2. production active run은 초기 release에서 무조건 거부한다.
3. dynamic JavaScript pack loading은 sandbox contract 전까지 금지한다.
4. registry 전체 Ed25519 signature + pack descriptor digest를 함께 검증한다.
5. stored coverage JSON을 active authorization input으로 신뢰하지 않는다.
6. missing pack/witness를 finding 0개로 덮지 않는다.
7. `secure`, `safe`, whole-target `pass` verdict를 만들지 않는다.
8. `proven`은 baseline/attack/counterfactual + deterministic oracle + replay threshold가
   모두 있어야 한다.
9. raw credential, 실제 피해자, public recipient, executable malware를 fixture로
   사용하지 않는다.
10. 외부/제3자 live target에 자동 공격하지 않는다.

## 6. 현재 코드의 알려진 보안/설계 결함

아래를 먼저 고치기 전에는 active runner를 production-ready로 부르면 안 된다.

### Critical

1. **Evidence bundle은 digest만 있고 signature가 없다.**
   공격자가 내용을 바꾸고 digest를 다시 계산할 수 있다. authorization/registry와
   별도의 evidence signing key 또는 run attestation으로 bundle을 서명해야 한다.

2. **DNS pinning과 실제 socket 연결 사이 TOCTOU가 남는다.**
   `DestinationGuard`가 DNS 응답 변화를 감지하지만 global `fetch`가 다시 DNS를
   resolve한다. custom dispatcher/lookup, resolved-IP connection + Host/SNI 검증 등으로
   실제 connection destination을 pin해야 `AC-805`를 완전히 충족한다.

3. **State snapshot이 evidence result에 raw object로 남는다.**
   `beforeState`/`afterState`에 비밀이나 canary가 포함되면 현재 일반 credential regex만
   통과할 수 있다. default는 state digest + allowlisted diff만 저장하고 raw snapshot은
   encrypted/retention-controlled artifact로 분리해야 한다.

### High

4. `EvidenceBundle.attackProgramDigest`는 원본 program digest지만 저장 program은
   redacted copy다. 원본 없이 해당 digest를 독립 검증할 수 없다. sealed secret
   reference 또는 redacted-program digest를 별도 기록해야 한다.

5. surface inventory validation이 얕다. 저장 JSON의 surface ID/protocol/ledger를
   변조할 수 있다. stable ID 재계산, duplicate detection, target/build binding,
   inventory signature가 필요하다.

6. manifest의 repository path가 absolute/canonical인지 강제하지 않는다.
   canary origins도 target origins와 같은 canonical-origin validation을 받아야 한다.

7. cookie parser는 단순 `set-cookie` 한 개만 처리한다. expiry, domain, path, secure,
   same-site 및 복수 header를 다루는 fixture-safe cookie jar가 필요하다.

8. active runner에 `AbortController` 기반 cancellation과 “cancel 후 새 step 0개”
   검증이 없다.

9. witness failure를 항상 structured `error` result로 바꾸지 않고 일부는 throw한다.

10. 테스트 fixture는 실제 listener가 아니라 injected mock `fetch`와 in-memory state다.
    `AC-401`, `AC-402`의 library behavior는 입증하지만 진짜 process/network E2E라고
    주장하면 안 된다.

### Medium

11. HTTP runner의 concurrency는 아직 없다.
12. stateful extraction(CSRF/object ID/idempotency key) 문법이 없다.
13. finding lineage가 coverage diff에 없다.
14. report의 retention lifecycle, raw artifact expiry가 없다.
15. evidence.ts 전용 tamper/redaction/fix tests가 아직 없다.

## 7. 바로 이어서 할 작업

### Step A — 현재 새 코드 봉합

1. `test/evidence.test.ts` 추가
   - receipt event 제거/순서 변경/hash 변조
   - bundle 변조
   - Markdown raw token/canary 미포함
   - fixed / not-fixed / utility-regression
2. evidence bundle Ed25519 signature 도입
3. raw state 대신 digest + allowlisted state diff
4. `npm run check`

### Step B — 실제 fixture/process

1. Node 또는 Next.js disposable fixture process 추가
2. vulnerable/fixed mode
3. two tenant / anonymous / user-A / user-B / privileged
4. BOLA:
   - B session + A object
   - vulnerable canary observation
   - fixed 403/no state effect
5. BFLA:
   - user session + admin operation
   - vulnerable state increment
   - fixed deny
6. independent control/witness channel
7. reset 후 DB/filesystem/state digest 동일성

### Step C — CLI와 artifact

1. `twin prepare`
2. `run project`
3. `replay`
4. `evidence render`
5. `verify-fix`
6. exit codes:
   - 0 success
   - 1 proven finding
   - 2 validation/safety/execution error
   - 3 coverage failure

### Step D — Phase 1 나머지

- Next.js route/server action/middleware mapper
- Supabase migrations/RLS/storage/service-role mapper
- mass assignment
- query/data-scope mutation
- SSRF owned-canary fixture
- disposable path/command effect
- workflow/idempotency replay
- candidate/proven/rejected/flaky/error schemas

그 이후에만 Phase 2 scheduler, agent/MCP/memory/compound, GraphQL/WS/gRPC,
browser/file/async/cache/race/resource/parser/cloud 연구 pack으로 확장한다.

## 8. Acceptance 상태

현재 확실히 만족한 핵심:

- `AC-101`–`AC-104`
- `AC-205`
- `AC-400`
- `AC-401` library-level fixture
- `AC-402` library-level fixture
- `AC-601` / `AC-602`의 기본 causal 판정
- `AC-804`
- `AC-902`
- `AC-904`
- `AC-906`

부분 만족:

- `AC-204`, `AC-206`
- `AC-301`
- `AC-302`
- `AC-501`, `AC-502`
- `AC-702`, `AC-703`
- `AC-803`, `AC-805`
- `AC-901`, `AC-903`, `AC-905`

나머지는 대부분 `Not satisfied`다. acceptance report를 갱신할 때 status 문자열은
반드시 다음 네 개만 사용한다.

- `Satisfied`
- `Partially satisfied`
- `Not satisfied`
- `Not verifiable`

## 9. Git/worktree 주의

- worktree는 대규모 dirty 상태다.
- 이전 monorepo/plugin/contest 파일 약 300개의 삭제는 사용자 승인된 폐기다.
- 새 `src/`, `test/`, `docs/`, `examples/`는 대부분 untracked로 보일 수 있다.
- `git reset --hard`, `git checkout --`, 광범위 restore 금지.
- 아직 commit/push/PR을 요청받지 않았다.
- private key 파일(`*.pem`, `*.key`)은 `.gitignore`에 추가되어 있다.

## 10. 최종 제품 판정 원칙

기능 이름이나 payload 목록으로 지원을 주장하지 않는다.

하나의 attack family를 “지원”이라고 부르려면 최소한:

1. signed pack
2. applicability mapping
3. vulnerable fixture
4. fixed fixture
5. independent witness
6. baseline/attack/counterfactual
7. deterministic replay threshold
8. redacted, integrity-protected evidence
9. cleanup/reset proof
10. coverage ledger

를 모두 통과해야 한다.
