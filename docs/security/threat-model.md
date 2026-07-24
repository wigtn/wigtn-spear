# SPEAR threat model

## Trust boundaries

- Trace와 adapter 응답은 테스트 대상이 제공한 데이터이며 독립적으로 신뢰하지 않는다.
- Contract, campaign, scope, attack plan은 운영자가 검토한 로컬 파일로 가정하지만 크기와 형식은 검증한다.
- 프로젝트와 agent adapter는 공격 대상이므로 응답 body, header, redirect를 신뢰하지 않는다.
- `SPEAR_ADAPTER_TOKEN`은 프로세스 환경에서만 읽고 결과·오류·증거에 기록하지 않는다.

## Safety invariants

1. 능동 네트워크 실행은 authorization scope와 실행 시점 동의를 모두 요구한다.
2. scope에 기록된 정확한 origin을 벗어나지 않는다.
3. 원격 host는 scope와 CLI 양쪽에서 허용해야 한다.
4. project mutating method는 scope와 CLI 양쪽에서 허용해야 한다.
5. redirect는 따라가지 않는다.
6. 요청 수, timeout, response bytes를 제한한다.
7. 셸 명령과 사용자 코드를 실행하지 않는다.
8. 결과 증거에서 인증 정보와 일반적인 secret 형식을 마스킹한다.

## Known limitations

- 대상 adapter가 trace event를 누락하거나 위조하면 현재 버전만으로 탐지할 수 없다.
- HTTP assertion은 인증·테넌트 fixture를 운영자가 올바르게 설계해야 의미가 있다.
- 로컬 loopback 서비스가 다른 내부 서비스로 프록시하는 경우 SPEAR는 그 내부 동작을 볼 수 없다.
- `authorization`은 법적 권한을 암호학적으로 증명하지 않는다. 운영자의 명시적 책임 확인과 실행 실수를 줄이는 안전장치다.
- 이 도구는 sandbox가 아니다. 테스트 대상 서비스와 agent는 별도 격리 환경에서 실행해야 한다.
