# Standards baseline

기준일: 2026-07-23

SPEAR의 rule ID는 규정 준수 판정이 아니라 테스트 분류와 추적을 위한 metadata다. 정확한 requirement ID가 확보되지 않은 경우 상위 표준 이름만 기록하며, 임의의 세부 ID를 만들지 않는다.

## AI agent

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/): goal hijack, tool misuse, identity/privilege abuse, memory poisoning, insecure inter-agent communication, cascading failures 등을 위협 분류에 사용한다.
- [OWASP AISVS 1.0](https://owasp.org/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/): 2026-06-24 공개된 검증 가능한 AI 보안 요구사항을 contract 및 acceptance test 설계의 기준으로 사용한다.
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/): 향후 독립 trace collector adapter의 호환 기준으로 사용한다. 입력·출력 message는 민감정보를 포함할 수 있으므로 기본 수집 대상으로 간주하지 않는다.
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices): 최소 권한, scope elevation, SSRF, session, local server sandboxing과 명시적 privilege grant를 MCP 시나리오 설계 기준으로 사용한다.

## Project security

- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/): 웹/API 공격 assertion의 통제 기준으로 사용한다. 세부 requirement를 매핑할 때 `v5.0.0-<requirement>` 형식을 사용한다.
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/): broken access control, security misconfiguration, supply-chain/integrity failure, injection, authentication과 exceptional-condition 분류에 사용한다.
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/): object/property/function authorization, resource consumption, sensitive business flow, SSRF와 unsafe third-party API consumption 분류에 사용한다.
- [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/): stable web security test 분류와 versioned test ID에 사용한다. 개발 중인 latest/5.0 문서는 gap discovery에 참고하되 release ID로 고정하지 않는다.
- [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html): XSS, SQL injection, CSRF, authorization, path/command injection, upload, deserialization, disclosure, SSRF와 resource-limit weakness corpus 우선순위에 사용한다.

## Protocol and execution packs

- [OWASP OAuth2 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html): OAuth/OIDC client, redirect, PKCE, token replay, audience/scope와 privilege restriction 시나리오에 사용한다.
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html): node/edge authorization, batching, depth/complexity, introspection과 resolver injection 시나리오에 사용한다.
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html): origin, authentication lifecycle, message authorization/injection과 bounded resource 시나리오에 사용한다.
- [OWASP gRPC Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html): method authorization, metadata identity, message/stream limit, reflection과 error disclosure 시나리오에 사용한다.
- [OWASP Web Service Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html): SOAP/XML transport, message integrity/confidentiality, schema/content validation, entity/resource와 endpoint security 시나리오에 사용한다.
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html): filename, type/signature, storage, retrieval, archive/parser와 authorization 시나리오에 사용한다.
- [OWASP Serverless/FaaS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html): event identity, least privilege, function invocation, secrets와 execution-context 시나리오에 사용한다.
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/): flow control, pipeline identity, poisoned execution, dependency/artifact integrity와 credential hygiene 분류에 사용한다.

## Implementation rule

- Top 10은 위협 분류이며 검증 표준 자체가 아니다.
- AISVS/ASVS mapping은 assertion이 실제 요구사항 전체를 검증할 때만 세부 ID를 사용한다.
- 외부 표준이 업데이트되어도 SPEAR의 실행 schema를 자동 변경하지 않는다. mapping metadata를 버전별로 갱신한다.
