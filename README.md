# SPEAR

SPEAR는 소유하거나 명시적으로 테스트를 승인받은 제품과 AI agent의 공격 가능
표면을 찾아, 실제 금지 상태/효과를 **독립 witness로 입증**하는 security
attack-verification system입니다.

`0.3.0`은 v3 cutover 기반 위에 **실제 causal HTTP 공격 vertical**을 얹은
릴리스입니다. 서명된 권한 → surface discovery → pack 적용성 → coverage →
disposable Twin 공격 → baseline/attack/counterfactual causal 판정 → 서명된 증거
번들 → 결정적 replay → fix 검증까지 CLI로 이어집니다.

SPEAR는 target 전체에 `secure`/`safe` 판정을 내리지 않습니다. finding이 0개여도
compatible pack이나 witness가 없으면 결과는 `coverage-incomplete`입니다.

## 현재 구현된 것

**권한·무결성**

- Ed25519 authorization manifest, key revocation/expiry/capability/build 검증
- production active-run 거부와 runtime acknowledgement 강제
- Ed25519 signed pack registry와 canonical descriptor SHA-256 검증
- stored coverage를 신뢰하지 않고 run 준비 시 registry/coverage 재검증

**발견·coverage**

- operator fixture, OpenAPI 3.x JSON, Next.js(route-handler/server-action/
  middleware), Supabase(table RLS·storage), GraphQL 정적 descriptor 매퍼,
  HAR 캡처 트래픽·Postman(v2.1) 매퍼(path id·변수 템플릿화, 폴더 재귀, 중복 병합)
- surface stable-ID 재계산·중복·target 바인딩 검증(변조 감지)
- compatible/missing pack, missing witness, blind spot, evidence grade ledger
- explicit coverage policy: 속성 기반 `requiredDataClasses`(특정 data class surface는
  attackable+grade floor 강제, ID churn에 강함), protocol/surface/witness 요구
- surface/coverage/pack-version diff, coverage 실패 전용 exit code `3`

**active causal 공격**

- exact-origin HTTP runner: 실제 run은 undici custom dispatcher로 소켓을 사전
  resolve된 IP에 pin(hostname target도 DNS-rebinding TOCTOU 차단), metadata 차단,
  redirect scope 재검증, 요청/시간/바이트 budget, cookie jar, cancellation
- 두 tenant disposable Twin과 독립 HTTP 제어 채널(reset/snapshot, 무결성 재현)
- baseline / attack / counterfactual + deterministic replay threshold로
  `proven` / `rejected` / `flaky` / `error` 판정
- 지원 attack family: BOLA, BFLA, mass assignment(BOPLA), SSRF→owned canary sink,
  idempotency 중복효과, config 변경, 비원자 partial-effect, workflow step-skip,
  cache poisoning, GraphQL BOLA, differential authz(canary·상태변화 없이 두 principal
  응답 동치로 BFLA 검출), SSRF canary-egress(owned sink이 정확한 토큰 관측), audit-log
  tampering(monotonic 하향 위반), excessive data exposure(응답 금지 필드 구조적 노출),
  CORS 오설정(공격자 origin이 ACAO에 반영) — 각각 vulnerable/fixed fixture로 proven/rejected 실증

**agent 공격 (Phase 4 착수)**

- black-box agent 어댑터(엔드포인트 + body 템플릿 + reply JSON path), 소켓 전
  authorization scope 검증. baseline/attack/counterfactual + 3-of-2 반복 임계
- proven급 oracle 4종: `agent-canary-leak`(심어둔 canary가 응답에 정확히 등장 →
  데이터/시스템프롬프트 유출), `agent-tool-egress`(owned sink이 canary를 관측 →
  tool 호출이 프로세스 밖으로 실제 유출), `agent-backend-state`(owned witness가 권한
  백엔드 상태변화를 관측 → confused deputy/excessive agency), `agent-gateway-egress`
  (owned 프록시 chokepoint가 임의 목적지로 나가는 exfil을 관측 → black-box egress).
  candidate 전용 `agent-marker-compliance`(self-report)는 causal proof 경로에서 명시적 거부
- canary redaction + Ed25519 서명 agent evidence bundle. 취약/수정 agent + owned
  sink fixture로 proven/rejected 실증. 설계는 `docs/product/agent-attack-design.md`
- `spear run agent` CLI(authorization→검증→서명 번들, proven=exit 1). 실제 고객
  hostname 엔드포인트도 undici socket pinning으로 DNS-rebinding 안전. OpenAI/Anthropic
  provider 프리셋(API 키는 evidence에서 redact)
- project-only counterfactual(FR-455): 효과가 agent 경유만 되는지(`agent-required`)
  backend 단독으로도 되는지(`backend-reachable`) 분류. indirect injection carrier
  (FR-451): 악성 지시를 agent가 읽는 untrusted 데이터에 심어 데이터 경유 injection 입증
- MCP pack(FR-456): tool listing을 승인/실행 시점 snapshot해 rug-pull(digest drift)·
  shadowing(이름 충돌)을 결정적 판정. memory pack(FR-457/458): 오염 항목 주입→sleeper
  세션→나중 세션 activation 분리로 memory poisoning 입증
- 벤치마크 스코어카드 하네스: 프로브 corpus를 campaign으로 돌려 proven/candidate/rejected
  집계 + independent-witness proven vs reply-only proven 분리(정직성). 냉정한 역량 상한은
  [capability assessment](./docs/product/agent-attack-capability-assessment.md) 참고
- gateway/proxy witness(`agent-gateway-egress`): 에이전트 egress를 프록시로 통과시켜
  임의 목적지 exfil을 관측(owned sink 불필요, black-box). mutation 엔진 + 적응형 exploit
  탐색(`searchAgentAttack`, FR-407): seed가 실패해도 통하는 변형을 스스로 탐색(판정은 witness)
- 공개 corpus ingestion(`parseInjecAgent`): InjecAgent(MIT, 1,054케이스)를 프로브로 변환.
  corpus의 성공 라벨은 hint로 강등하고 **우리 witness로 ground truth 재도출** — "손으로 짠
  seed"를 필드 축적으로 대체. `corpusCaseToProgram`으로 runnable AgentAttackProgram 생성

**증거·수명주기**

- Ed25519 서명 evidence bundle(content digest + redacted-program digest),
  canary/credential redaction, raw state 대신 digest + allowlisted diff
- `replay`: sealed bundle의 verdict를 receipts에서 결정적으로 재계산(offline)
- `verify-fix`: original(proven)+fixed 번들 비교, benign-utility 증명 시에만 `fixed`

## 아직 구현되지 않은 것

- browser/WebSocket/gRPC/queue runtime 자동 mapping
- agent: corpus ingestion 확장(garak Apache-2.0/AgentDojo MIT), attacker-LLM 루프
  (PAIR/TAP/Crescendo), 실제 LLM 라이브 실증, MCP/memory/corpus CLI+서명 번들, agent
  tool-state fuzzer(프론티어) (agent 공격 엔진 7종·`run agent` CLI·provider 프리셋·hostname
  pinning·project-only(FR-455)·indirect carrier(FR-451)·confused deputy(LLM06)·MCP(FR-456)·
  memory(FR-457/458)·gateway egress witness·mutation+adaptive search(FR-407)·InjecAgent
  ingestion·벤치마크 하네스는 구현됨)
- race/parser/cloud 등 추가 project attack family
- live target을 재공격하는 CI deterministic replay
- HTTP 동시성(paired/maxConcurrency 강제), browser/DB audit witness oracle

`지원`이라고 부르려면 signed pack · applicability · vulnerable/fixed fixture ·
independent witness · baseline/attack/counterfactual · replay threshold ·
redacted·integrity-protected evidence · cleanup/reset · coverage ledger를 모두
통과해야 합니다.

## 설치와 검증

```bash
npm ci
npm run check          # typecheck + 87 tests
node dist/src/cli.js help
```

Node.js 22 이상이 필요합니다.

## 빠른 시작 (passive → preview)

```bash
# 1) 로컬 signing key와 trust store (private key는 커밋 금지)
node dist/src/cli.js keygen --key-id local-owner-2026 \
  --private-key ./local-owner.pem --trust-store ./trust-store.json

# 2) manifest와 registry 서명
node dist/src/cli.js manifest sign --input ./examples/authorization.unsigned.json \
  --private-key ./local-owner.pem --key-id local-owner-2026 --output ./authorization.json
node dist/src/cli.js registry sign --input ./examples/registry.unsigned.json \
  --private-key ./local-owner.pem --key-id local-owner-2026 --output ./registry.json

# 3) 네트워크 없이 surface 발견 (OpenAPI/Next.js/Supabase/GraphQL/HAR/Postman 병합 가능)
node dist/src/cli.js discover --profile ./examples/target.profile.json \
  --openapi ./examples/openapi.json [--har ./capture.har.json] --output ./inventory.json

# 4) explicit policy로 coverage 평가
node dist/src/cli.js coverage --inventory ./inventory.json \
  --profile ./examples/target.profile.json --registry ./registry.json \
  --trust-store ./trust-store.json --policy ./examples/coverage.policy.json

# 5) attack program 계약과 무접촉 run preview 검증
node dist/src/cli.js attack validate --program ./examples/attack.program.json
node dist/src/cli.js run preview --manifest ./authorization.json \
  --trust-store ./trust-store.json --profile ./examples/target.profile.json \
  --inventory ./inventory.json --registry ./registry.json \
  --policy ./examples/coverage.policy.json --acknowledge-authorization
```

## active causal run

상태를 관측하는 oracle(state-path 계열·partial-effect·canary-egress)은 공격 표면과
분리된 owned control 채널(`twin.control`)이 필요합니다. 응답만 보는 oracle
(response-contains·differential-access)은 constant Twin으로 동작합니다. 먼저 disposable
무결성을 검증한 뒤 공격하고, 증거를 재검증합니다.

```bash
# 제어 채널이 reset→snapshot→reset으로 baseline digest를 재현하는지 확인
node dist/src/cli.js twin prepare --manifest ./authorization.json --twin ./twin.json

# 공격 실행 → 서명된 evidence bundle (proven이면 exit 1)
node dist/src/cli.js run project --manifest ./authorization.json \
  --trust-store ./trust-store.json --profile ./target.profile.json \
  --inventory ./inventory.json --registry ./registry.json \
  --policy ./coverage.policy.json --program ./program.json --twin ./twin.json \
  --evidence-private-key ./evidence.pem --evidence-key-id evidence-2026 \
  --acknowledge-authorization --output ./bundle.json

# 증거 검증·렌더·결정적 replay
node dist/src/cli.js evidence verify --bundle ./bundle.json --trust-store ./evidence-trust.json
node dist/src/cli.js evidence render --bundle ./bundle.json --trust-store ./evidence-trust.json
node dist/src/cli.js replay --bundle ./bundle.json --trust-store ./evidence-trust.json

# 수정 후 재실행한 번들과 비교 (benign-utility 증명 시에만 fixed)
node dist/src/cli.js verify-fix --original ./bundle.json --fixed ./bundle.fixed.json \
  --trust-store ./evidence-trust.json --benign-utility-passed

# retention 만료 강제 (창 경과 전·이미 pruned면 no-op → cron/CI 안전)
node dist/src/cli.js evidence prune --bundle ./bundle.json --trust-store ./evidence-trust.json \
  --evidence-private-key ./evidence.pem --evidence-key-id evidence-2026 --if-expired
```

raw response body 보존 창은 기본 30일이며 `run project --retention-days <n>`으로 조정합니다.
경과 후 `evidence prune --if-expired`가 body를 digest로 대체하고 `redacted-only`로 재봉인하지만,
replay/verify는 sealed predicate 플래그만 쓰므로 그대로 통과합니다.

실제 run은 undici dispatcher로 소켓을 사전 resolve된 IP에 pin하므로 hostname
target도 안전합니다(DNS rebinding 차단). embedder가 자체 `fetch`를 주입하는 경우엔
pin을 보장할 수 없어 IP-literal origin만 허용합니다. Twin control origin은 여전히
IP-literal입니다.

## Exit codes

- `0`: 성공(검증/출력 OK, coverage 충족, 또는 verify-fix `fixed`)
- `1`: proven finding 존재(run project / evidence verify / replay)
- `2`: 입력·서명·safety·실행 오류
- `3`: finding 수와 무관한 coverage policy failure

## 설계 원칙

- authorization 검증은 어떤 target access보다 먼저 일어난다.
- pack ID나 heuristic이 아니라 서명·descriptor integrity·API/version/safety class로
  load 여부를 결정한다.
- `unsupported`(pack 부재)와 `blocked`(witness 부재)를 구분한다.
- passive mapping과 causal proof를 같은 증거 등급으로 취급하지 않는다.
- payload나 confidence만으로 finding을 `proven`으로 올리지 않는다. `proven`은
  baseline/attack/counterfactual + deterministic oracle + replay threshold를 모두
  요구한다.
- raw credential·실제 피해자·public recipient·executable malware를 fixture로
  쓰지 않으며, 외부/제3자 live target을 자동 공격하지 않는다.

제품 요구사항은 [SPEAR v3 PRD](./docs/product/spear-v3-prd.md), 현재 구현 판정은
[foundation acceptance report](./docs/product/spear-v3-foundation-acceptance-report.md)를
참고하십시오.
