# SPEAR v3 구현 준비도 리뷰

- 리뷰 기준: `docs/product/spear-v3-prd.md`
- 판정일: 2026-07-23
- 판정: **Conditional Go**
- 구현 승인 범위: **Phase 0 + Phase 1 foundation slice**

## 결론

PRD의 제품 방향은 유효하다. 특히 단순 취약점 스캐너가 아니라 authorization,
surface inventory, attack program, witness, coverage ledger를 하나의 증거 체계로
묶은 선택은 차별성이 있다.

다만 PRD 전체를 한 번에 구현하면 "많이 지원하지만 입증하지 못하는" 도구가 된다.
이번 cutover는 아래 기반만 구현하고, 나머지는 `unsupported` 또는
`coverage-incomplete`로 정직하게 보고한다.

1. Ed25519 서명 authorization manifest와 trust store
2. 서명 pack registry와 pack descriptor integrity
3. attack-program contract validation
4. operator fixture 및 OpenAPI JSON 기반 passive discovery
5. surface inventory, coverage policy, blind spot, diff
6. manifest/build/registry digest를 포함하는 실행 preview

네트워크 공격 실행, 브라우저 크롤링, GraphQL/protobuf/WebSocket runtime probe,
DB/filesystem/process witness, Twin orchestration은 이 slice의 완료 범위가 아니다.

## Blocker 검토와 결정

### B-01 Pack registry의 "signed" 의미가 불명확하다 — 해결

Phase 0은 signed registry를 요구하지만 `FR-906`은 integrity digest만 명시한다.
digest만으로는 공격자가 descriptor와 digest를 함께 바꾸는 것을 막지 못한다.

결정:

- registry 전체를 Ed25519로 서명한다.
- registry signer도 authorization과 동일한 trust-store 형식을 사용한다.
- 각 pack은 canonical descriptor의 SHA-256 digest를 별도로 가진다.
- foundation에서는 declarative descriptor만 읽고 외부 JavaScript를 동적 실행하지
  않는다.

### B-02 Build digest의 생성 주체가 없다 — 해결

`FR-101`, `FR-104`는 build digest를 요구하지만 범용 재현 방식은 정하지 않았다.

결정:

- 초기 버전은 CI/operator가 계산한 `sha256:<64 hex>` 값을 manifest와 target
  profile에 각각 넣는다.
- runner는 두 값의 exact match를 검증한다.
- 저장소 상태에서 digest를 자동 생성하는 기능은 공급망 provenance 설계와 함께
  후속 단계에서 다룬다.

### B-03 `coverage-complete`의 기본 기준이 없다 — 해결

pack이 하나 적용 가능하다는 사실은 공격이 수행되거나 효과가 관측됐다는 의미가
아니다.

결정:

- coverage complete는 명시적 target policy가 정한 필수 protocol, surface,
  witness, 최소 evidence grade를 모두 만족할 때만 가능하다.
- passive discovery 결과는 최대 `attackable`까지만 올라간다.
- policy가 없거나 빈 policy이면 "전체 제품이 안전하다"는 결론을 만들지 않는다.
- 결과 vocabulary는 `coverage-complete` / `coverage-incomplete`만 사용하고
  `secure`, `safe`, `pass`를 target verdict로 사용하지 않는다.

## High findings

### H-01 Phase 1 exit criteria가 단일 구현 단계로는 과대하다

Phase 1은 protocol discovery, stateful witness, authz, SSRF, injection, workflow,
HTTP request smuggling까지 동시에 요구한다. 독립적인 fixture와 oracle이 없는
상태에서 병렬 구현하면 false confidence가 발생한다.

조치: foundation slice 이후 protocol adapter를 하나씩 추가하고 각 adapter가
vulnerable/fixed fixture와 causal witness를 함께 통과할 때만 지원 목록에 올린다.

### H-02 Mixed-protocol discovery와 현재 입력 포맷의 간극

`AC-204` 전체를 만족하려면 browser, schema, traffic, runtime source를 병합하는
공통 provenance model이 먼저 필요하다.

조치: 이번 slice는 operator surface와 OpenAPI JSON만 실제 지원한다. 다른 protocol은
operator가 inventory에 선언할 수 있으나 자동 발견으로 주장하지 않는다. OpenAPI
YAML도 아직 지원하지 않는다.

### H-03 Active 명령 이전의 무접촉 보장이 코드 경계로 강제돼야 한다

인가 검증이 HTTP client 안쪽에 있으면 일부 DNS/network event가 먼저 발생할 수 있다.

조치: authorization, acknowledgement, environment, capability, build digest, registry
검증을 run preparation의 첫 단계로 둔다. foundation의 preview/discovery/coverage는
network client를 포함하지 않는다.

### H-04 Canonical signing 규칙이 없었다

JSON 직렬화 방식이 다르면 정상 서명이 실패하고, 일부 구현은 서로 다른 문서를 같은
것으로 간주할 수 있다.

조치: signature 필드를 제외하고 object key를 재귀적으로 정렬한 UTF-8 JSON을
canonical payload로 정의한다. number는 유한값만 허용하며 `undefined`, function,
symbol, bigint, 순환 참조를 거부한다.

### H-05 저장된 unsigned coverage artifact를 run이 신뢰하면 policy를 우회할 수 있다

초기 구현안은 `run preview`가 이전 coverage JSON을 입력으로 받았다. 이 구조에서는
공격자가 pack safety class, ledger 또는 verdict를 바꿀 수 있다.

조치: 저장된 coverage report를 run의 권한 입력으로 사용하지 않는다. preview는
inventory, policy와 signed registry를 다시 받아 registry signature/digest를
검증하고 coverage를 프로세스 안에서 재계산한다.

## Medium findings

### M-01 Coverage state와 evidence grade를 분리해야 한다

`attackable`은 준비 상태이고 `witnessed`는 실행 증거다. 하나의 enum으로 정책을
비교하면 의미가 섞인다.

조치: surface state와 evidence grade를 별도 필드로 저장한다.

### M-02 Unsupported와 blocked를 구분해야 한다

호환 pack이 없으면 `unsupported`, pack은 있으나 witness가 없으면 `blocked`다.
두 경우 모두 coverage incomplete지만 개선 방법이 다르다.

### M-03 CLI exit code가 제품 계약이어야 한다

결정:

- `0`: 요청된 검증/출력이 성공했고 coverage policy도 충족
- `1`: 향후 proven finding이 존재
- `2`: 입력, 서명, safety 또는 실행 오류
- `3`: finding 수와 무관한 coverage policy failure

## 구현 Gate

이번 slice의 완료 조건은 다음과 같다.

- unknown/revoked key, tampered signature, expiry, production, missing
  acknowledgement, capability/build mismatch를 target access 전에 거부한다.
- pack descriptor 또는 registry 변조를 거부한다.
- 불완전한 attack program을 거부한다.
- OpenAPI JSON과 operator surface를 안정적인 ID로 병합한다.
- missing pack과 missing witness를 각각 `unsupported`, `blocked`로 표시한다.
- coverage failure가 exit code `3`을 반환한다.
- 출력 artifact에 manifest, build, registry digest가 남는다.
- 어떤 결과도 전체 target에 `secure` 판정을 내리지 않는다.

이 gate를 통과해도 SPEAR v3 전체 Phase 0 또는 Phase 1 완료로 표기하지 않는다.
