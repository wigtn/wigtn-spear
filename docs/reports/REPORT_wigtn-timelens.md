# WIGTN-SPEAR Security Scan Report: wigtn-timelens

> **Target**: https://github.com/wigtn/wigtn-timelens
> **Deployed**: https://timelens-852253134165.asia-northeast3.run.app/
> **Scan Date**: 2026-03-13
> **Tool**: WIGTN-SPEAR v0.1.0 (17 modules loaded)
> **Mode**: SAFE (read-only, no network)
> **Duration**: 744ms

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 20 |
| MEDIUM | 20 |
| LOW | 51 |
| **TOTAL** | **95** |

**Grade: FAIL**

---

## CRITICAL (4건)

### C-1. Supply Chain Typosquat -- package-lock.json (3건)

| File | Line | Rule ID |
|------|------|---------|
| `package-lock.json` | 1493 | `sc-typosquat-popular-npm` |
| `package-lock.json` | 2428 | `sc-typosquat-popular-npm` |
| `package-lock.json` | 6999 | `sc-typosquat-popular-npm` |

**Module**: Spear-08 (Supply Chain Analyzer)

**Description**: lockfile에 유명 npm 패키지와 이름이 거의 동일한 의심 패키지가 존재. 타이포스쿼팅 공격을 통해 악성 패키지가 설치되었을 가능성.

**Risk**: 공격자가 유명 패키지 이름을 미세하게 변형한 악성 패키지를 npm에 등록하고, 개발자가 실수로 설치하면 백도어/데이터 탈취 코드가 실행됨.

**MITRE ATT&CK**: T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

**Remediation**:
- lockfile의 해당 라인 확인하여 실제 패키지명 검증
- `npm audit` 실행으로 알려진 취약점 확인
- 패키지 레지스트리(npmjs.com)에서 패키지 publish 날짜, 다운로드 수 확인

### C-2. SSRF -- src/back/lib/geo/places.ts:151

| File | Line | Rule ID |
|------|------|---------|
| `src/back/lib/geo/places.ts` | 151 | `ssrf-fetch-user-input` |

**Module**: Spear-14 (SSRF Tester)

**Description**: `fetch()`가 사용자 제어 가능한 URL 파라미터를 검증 없이 호출. Server-Side Request Forgery(SSRF) 공격 가능.

**Risk**: 공격자가 URL 파라미터를 조작하여 내부 네트워크(GCP metadata `169.254.169.254`, 내부 서비스)에 접근하거나, Cloud Run의 서비스 계정 토큰을 탈취할 수 있음. **배포 환경(GCP Cloud Run)에서 특히 위험**.

**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)

**Remediation**:
- URL allowlist 적용 (허용된 도메인만 fetch)
- 내부 IP 대역 차단 (`10.x`, `172.16-31.x`, `192.168.x`, `169.254.x`)
- URL 파싱 후 호스트 검증

---

## HIGH (20건)

### H-1. Env Exfiltration -- 하드코딩된 시크릿 (3건)

| File | Line | Rule ID |
|------|------|---------|
| `.env.example` | 1 | `env-dotenv-hardcoded-secrets` |
| `.github/cloudbuild.yaml` | 65 | `env-dotenv-hardcoded-secrets` |
| `.github/workflows/deploy.yml` | 85 | `env-dotenv-hardcoded-secrets` |

**Module**: Spear-03 (Env Exfiltration Simulator)

**Description**: `.env.example`, CI/CD 설정 파일에 placeholder가 아닌 실제 시크릿 값이 하드코딩됨.

**Risk**: GitHub 레포가 public이면 시크릿이 전세계에 노출. private이더라도 레포 접근 권한이 있는 모든 사람이 시크릿을 볼 수 있음.

**Remediation**:
- `.env.example`에는 `YOUR_KEY_HERE` 같은 placeholder만 사용
- CI/CD에서는 GitHub Secrets 또는 GCP Secret Manager 사용
- 이미 노출된 키는 즉시 rotation

### H-2. Dependency Confusion (2건)

| File | Line | Rule ID |
|------|------|---------|
| `package.json` | 14 | `dep-confusion-single-char-diff` |
| `mobile/package.json` | 28 | `dep-confusion-single-char-diff` |

**Module**: Spear-05 (Dependency Confusion Checker)

**Description**: 패키지명이 유명 npm 패키지와 1글자만 다름. Dependency Confusion 공격에 악용될 수 있는 패키지명.

**Risk**: 공격자가 동일 이름의 악성 패키지를 public npm에 등록하면, 내부 레지스트리 미설정 시 악성 버전이 설치됨.

**MITRE ATT&CK**: T1195.002

**Remediation**:
- `@scope/` prefix 사용 (예: `@wigtn/timelens`)
- `.npmrc`에 `registry` 명시적 설정
- `package.json`에 `publishConfig.registry` 추가

### H-3. CI/CD SHA 미핀닝 -- deploy.yml (5건)

| File | Line | Rule ID |
|------|------|---------|
| `.github/workflows/deploy.yml` | 37, 41, 47, 55, 59 | `cicd-pin-branch-ref` |

**Module**: Spear-11 (CI/CD Pipeline Exploiter)

**Description**: GitHub Actions에서 `actions/checkout@v4`, `google-github-actions/auth@v2` 등을 태그로 참조. 태그는 mutable하므로 공격자가 액션 레포를 침해하면 악성 코드가 CI에서 실행됨.

**Risk**: Supply chain 공격으로 CI/CD 파이프라인 전체가 침해됨. 빌드 결과물에 백도어 삽입, 시크릿 탈취 가능.

**MITRE ATT&CK**: T1195 (Supply Chain Compromise)

**Remediation**:
```yaml
# Before (취약)
- uses: actions/checkout@v4

# After (안전)
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

### H-4. SSRF Decimal IP Bypass (8건)

| File | Line | Rule ID |
|------|------|---------|
| `package-lock.json` | 5740, 5741, 9420, 9445, 9446 | `ssrf-decimal-ip` |
| `mobile/package-lock.json` | 3751, 3830, 3831 | `ssrf-decimal-ip` |

**Module**: Spear-14 (SSRF Tester)

**Description**: lockfile 내 패키지에서 Decimal/Octal IP 표기법 발견. SSRF IP 필터 우회에 사용되는 패턴.

**Remediation**: 해당 패키지의 소스 코드 확인, 의심스러운 경우 대체 패키지 사용

### H-5. Social Engineering -- Hex-Encoded Execution (2건)

| File | Line | Rule ID |
|------|------|---------|
| `src/web/lib/audio/capture.ts` | 53 | `soceng-hidden-hex-string-exec` |
| `mobile/lib/audio/playback.ts` | 44 | `soceng-hidden-hex-string-exec` |

**Module**: Spear-19 (Social Engineering Code Analyzer)

**Description**: Hex-encoded 또는 char-code 기반 문자열 실행 패턴 탐지. 난독화된 악성 코드를 숨기는 기법.

**Risk**: 코드 리뷰에서 육안으로 발견하기 어려운 난독화된 악성 코드가 실행될 수 있음.

**Remediation**: 해당 코드 라인 직접 확인하여 정상 로직인지 검증

---

## MEDIUM (20건)

### M-1. CI/CD Mutable Tag (5건)

| File | Line | Rule ID |
|------|------|---------|
| `.github/workflows/deploy.yml` | 37, 41, 47, 55, 59 | `cicd-pin-mutable-tag` |

**Module**: Spear-11

**Description**: GitHub Actions가 semver 태그(`@v4`)로 참조됨. 태그는 이동 가능하여 다른 코드를 가리킬 수 있음.

### M-2. CI/CD Official Action 미핀닝 (5건)

| File | Line | Rule ID |
|------|------|---------|
| `.github/workflows/deploy.yml` | 36, 40, 46, 54, 58 | `cicd-pin-official-tag` |

**Module**: Spear-11

**Description**: 공식 Actions도 SHA 핀닝 권장.

### M-3. Container -- Root User (3건)

| File | Line | Rule ID |
|------|------|---------|
| `Dockerfile` | 8, 21, 49 | `container-no-user-directive` |

**Module**: Spear-12 (Container Security Auditor)

**Description**: Dockerfile에 `USER` 지시자가 없어 컨테이너가 root로 실행됨.

**Risk**: 컨테이너 탈출 공격 시 호스트 시스템에 root 권한 획득.

**Remediation**:
```dockerfile
RUN addgroup --system app && adduser --system --ingroup app app
USER app
```

### M-4. Missing publishConfig (2건)

| File | Line | Rule ID |
|------|------|---------|
| `package.json` | 4 | `dep-confusion-publish-config-missing` |
| `mobile/package.json` | 42 | `dep-confusion-publish-config-missing` |

**Module**: Spear-05

**Description**: private 패키지에 `publishConfig.registry`가 없어 실수로 public npm에 퍼블리시될 수 있음.

### M-5. Private IP Hardcoding (1건)

| File | Line | Rule ID |
|------|------|---------|
| `mobile/constants/config.ts` | 5 | `ssrf-private-ip-192` |

**Module**: Spear-14

**Description**: `192.168.x.x` 대역 하드코딩. 개발용 IP가 프로덕션에 남아있을 수 있음.

### M-6. Slopsquatting 의심 (4건)

| File | Line | Rule ID |
|------|------|---------|
| `package.json` | 37 | `spear-17/slopsquatting` |
| `mobile/package.json` | 31, 33, 35 | `spear-17/slopsquatting` |

**Module**: Spear-17 (LLM Output Exploiter)

**Description**: 하이픈이 4개 이상인 패키지명이 AI 환각으로 생성된 패키지일 가능성. 단, `@radix-ui/react-scroll-area`, `react-native-gesture-handler` 등은 **실제 존재하는 유명 패키지로 오탐(false positive)**.

---

## LOW (51건)

### L-1. Supply Chain -- Suspiciously New Packages (47건)

| File | Rule ID |
|------|---------|
| `package-lock.json` (23건) | `sc-typosquat-zero-day-package` |
| `mobile/package-lock.json` (24건) | `sc-typosquat-zero-day-package` |

**Module**: Spear-08

**Description**: `0.0.1` 또는 `1.0.0` 버전의 패키지가 유명 패키지 이름 패턴을 사용. 대부분은 정상 패키지의 초기 버전이므로 오탐 가능성 높음.

### L-2. Container -- Missing HEALTHCHECK (4건)

| File | Rule ID |
|------|---------|
| `Dockerfile` (4건) | `container-dockerfile-no-healthcheck`, `container-healthcheck-missing` |

**Module**: Spear-12

**Description**: Dockerfile에 `HEALTHCHECK` 지시자 없음. 컨테이너 헬스 모니터링 불가.

---

## Module Activation Summary

| Module | Findings | Status |
|--------|----------|--------|
| Spear-01: Secret Scanner | 0 | rules 미연결 |
| Spear-02: Git History Miner | 0 | rules 미연결 |
| Spear-03: Env Exfiltration | 3 | HIGH 3 |
| Spear-04: MCP Poisoning | 0 | MCP 설정 정상 |
| Spear-05: Dep Confusion | 5 | HIGH 2 / MEDIUM 2 / LOW 1 |
| Spear-06: Prompt Injection | 0 | 프롬프트 인젝션 패턴 없음 |
| Spear-08: Supply Chain | 50 | CRITICAL 3 / LOW 47 |
| Spear-10: Agent Manipulator | 0 | AI 에이전트 설정 정상 |
| Spear-11: CI/CD Exploiter | 15 | HIGH 5 / MEDIUM 10 |
| Spear-12: Container Audit | 7 | MEDIUM 3 / LOW 4 |
| Spear-13: Cloud Credential | 0 | 클라우드 키 노출 없음 |
| Spear-14: SSRF Tester | 9 | CRITICAL 1 / HIGH 8 |
| Spear-15: IDE Audit | 0 | IDE 확장 설정 없음 |
| Spear-16: Webhook Scanner | 0 | 웹훅 노출 없음 |
| Spear-17: LLM Exploiter | 4 | MEDIUM 4 (오탐 포함) |
| Spear-19: Social Engineering | 2 | HIGH 2 |
| Spear-21: Distillation | 0 | 증류 공격 패턴 없음 |

## Top 3 Action Items

1. **[CRITICAL] SSRF 수정** -- `src/back/lib/geo/places.ts:151`의 `fetch()` URL 검증 추가. GCP Cloud Run 환경에서 metadata 서버 접근으로 서비스 계정 토큰 탈취 가능.

2. **[CRITICAL] Supply Chain 검증** -- `package-lock.json`의 typosquat 의심 패키지 3건 수동 검증. npmjs.com에서 패키지 실체 확인.

3. **[HIGH] CI/CD 핀닝** -- `.github/workflows/deploy.yml`의 모든 Actions를 SHA 해시로 핀닝. 현재 태그 참조는 supply chain 공격에 취약.

---

*Generated by WIGTN-SPEAR v0.1.0 | 17 modules | 744ms | 2026-03-13*
