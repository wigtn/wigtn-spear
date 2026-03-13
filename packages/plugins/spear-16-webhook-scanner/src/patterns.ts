/**
 * SPEAR-16: Webhook & API Endpoint Scanner -- Pattern Definitions
 *
 * Defines 31 detection patterns across five categories:
 *
 *   - webhook_url        -- Hardcoded webhook URLs that could be abused
 *   - api_key_url        -- API keys embedded in URLs or query parameters
 *   - missing_auth       -- API endpoints without authentication middleware
 *   - insecure_endpoint  -- Endpoints with security misconfigurations
 *   - cors_miscfg        -- CORS misconfiguration allowing unauthorized access
 *
 * Each pattern includes MITRE ATT&CK mappings for enterprise threat classification.
 *
 * MITRE references used:
 *   T1071     -- Application Layer Protocol
 *   T1190     -- Exploit Public-Facing Application
 *   T1552     -- Unsecured Credentials
 *   T1567     -- Exfiltration Over Web Service
 *   T1562     -- Impair Defenses
 *   T1557     -- Adversary-in-the-Middle
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type WebhookCategory =
  | 'webhook_url'
  | 'api_key_url'
  | 'missing_auth'
  | 'insecure_endpoint'
  | 'cors_miscfg';

export interface WebhookPattern {
  id: string;
  name: string;
  description: string;
  category: WebhookCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── Webhook URL Patterns ──────────────────────────────────────

const webhookUrlPatterns: WebhookPattern[] = [
  {
    id: 'webhook-slack-url',
    name: 'Hardcoded Slack Webhook URL',
    description: 'Slack incoming webhook URL hardcoded in source code',
    category: 'webhook_url',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]+/,
    severity: 'high',
    mitre: ['T1567', 'T1552'],
    remediation: 'Move Slack webhook URLs to environment variables or a secrets manager.',
  },
  {
    id: 'webhook-discord-url',
    name: 'Hardcoded Discord Webhook URL',
    description: 'Discord webhook URL hardcoded in source code',
    category: 'webhook_url',
    pattern: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,19}\/[\w-]+/,
    severity: 'high',
    mitre: ['T1567', 'T1552'],
    remediation: 'Move Discord webhook URLs to environment variables or a secrets manager.',
  },
  {
    id: 'webhook-teams-url',
    name: 'Hardcoded Microsoft Teams Webhook',
    description: 'Microsoft Teams webhook URL hardcoded in source code',
    category: 'webhook_url',
    pattern: /https:\/\/[a-zA-Z0-9-]+\.webhook\.office\.com\/webhookb2\/[a-f0-9-]+/,
    severity: 'high',
    mitre: ['T1567', 'T1552'],
    remediation: 'Move Teams webhook URLs to environment variables or a secrets manager.',
  },
  {
    id: 'webhook-generic-url',
    name: 'Hardcoded Generic Webhook URL',
    description: 'Generic webhook URL hardcoded in source code',
    category: 'webhook_url',
    pattern: /(?:webhook|hook|callback|notify)(?:_url|Url|URL)?\s*[=:]\s*['"`]https?:\/\/[^'"`\s]+/i,
    severity: 'medium',
    mitre: ['T1567'],
    remediation: 'Store webhook URLs in configuration or environment variables, not source code.',
  },
  {
    id: 'webhook-github-url',
    name: 'Hardcoded GitHub Webhook Secret',
    description: 'GitHub webhook URL or secret hardcoded in source code',
    category: 'webhook_url',
    pattern: /(?:GITHUB_WEBHOOK_SECRET|github.*webhook.*secret)\s*[=:]\s*['"`][^'"`]+['"`]/i,
    severity: 'high',
    mitre: ['T1552'],
    remediation: 'Move GitHub webhook secrets to environment variables.',
  },
  {
    id: 'webhook-stripe-url',
    name: 'Hardcoded Stripe Webhook Secret',
    description: 'Stripe webhook signing secret hardcoded in source code',
    category: 'webhook_url',
    pattern: /whsec_[a-zA-Z0-9]{24,}/,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Move Stripe webhook secrets to environment variables or a secrets manager.',
  },
  {
    id: 'webhook-twilio-url',
    name: 'Hardcoded Twilio Webhook Configuration',
    description: 'Twilio webhook callback URL hardcoded in source code',
    category: 'webhook_url',
    pattern: /(?:statusCallback|voiceUrl|smsUrl|webhookUrl)\s*[=:]\s*['"`]https?:\/\/[^'"`\s]+/i,
    severity: 'medium',
    mitre: ['T1567'],
    remediation: 'Store Twilio webhook URLs in configuration or environment variables.',
  },
  {
    id: 'webhook-sendgrid-url',
    name: 'Hardcoded SendGrid Event Webhook',
    description: 'SendGrid event webhook URL or API key in source code',
    category: 'webhook_url',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Move SendGrid API keys to environment variables.',
  },
];

// ─── API Key in URL Patterns ───────────────────────────────────

const apiKeyUrlPatterns: WebhookPattern[] = [
  {
    id: 'webhook-apikey-query-param',
    name: 'API Key in Query Parameter',
    description: 'API key passed as URL query parameter exposing it in logs and referrers',
    category: 'api_key_url',
    pattern: /(?:https?:\/\/[^'"`\s]*[?&])(?:api_?key|apikey|access_?token|auth_?token|secret_?key)\s*=\s*[a-zA-Z0-9_-]{8,}/i,
    severity: 'high',
    mitre: ['T1552'],
    remediation: 'Pass API keys in request headers (Authorization, X-API-Key) instead of URL query parameters.',
  },
  {
    id: 'webhook-bearer-hardcoded',
    name: 'Hardcoded Bearer Token',
    description: 'Bearer token hardcoded in source code',
    category: 'api_key_url',
    pattern: /(?:Authorization|auth(?:orization)?_?header)\s*[=:]\s*['"`]Bearer\s+[a-zA-Z0-9._-]{20,}['"`]/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Move bearer tokens to environment variables or a secrets manager.',
  },
  {
    id: 'webhook-basic-auth-url',
    name: 'Basic Auth Credentials in URL',
    description: 'Basic authentication credentials embedded in URL',
    category: 'api_key_url',
    pattern: /https?:\/\/[a-zA-Z0-9._-]+:[^@\s]{4,}@[a-zA-Z0-9.-]+/,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Remove credentials from URLs. Use environment variables and proper authentication headers.',
  },
  {
    id: 'webhook-aws-key-url',
    name: 'AWS Key in Endpoint URL',
    description: 'AWS access key embedded in API endpoint URL',
    category: 'api_key_url',
    pattern: /(?:https?:\/\/[^'"`\s]*)?(?:AKIA|ASIA)[A-Z0-9]{16}/,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Use IAM roles or AWS SDK credential chain instead of embedding access keys.',
  },
  {
    id: 'webhook-gcp-key-url',
    name: 'GCP API Key in URL',
    description: 'Google Cloud API key embedded in endpoint URL',
    category: 'api_key_url',
    pattern: /(?:https?:\/\/[^'"`\s]*[?&]key=)AIza[A-Za-z0-9_-]{35}/,
    severity: 'high',
    mitre: ['T1552'],
    remediation: 'Use service accounts and OAuth2 instead of API keys in URLs.',
  },
  {
    id: 'webhook-private-key-inline',
    name: 'Private Key Inline in Endpoint Config',
    description: 'Private key material embedded near endpoint configuration',
    category: 'api_key_url',
    pattern: /(?:-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)/,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Move private keys to secure key stores. Never embed key material in source code.',
  },
];

// ─── Missing Auth Patterns ─────────────────────────────────────

const missingAuthPatterns: WebhookPattern[] = [
  {
    id: 'webhook-no-auth-middleware',
    name: 'Endpoint Without Auth Middleware',
    description: 'Express/Fastify route handler without authentication middleware',
    category: 'missing_auth',
    pattern: /(?:app|router)\s*\.(?:post|put|delete|patch)\s*\(\s*['"`]\/(?:api|webhook|hook|callback|notify)[^'"`]*['"`]\s*,\s*(?:async\s+)?\(?(?:req|ctx)\b/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Add authentication middleware before route handlers. Use JWT, API key validation, or signature verification.',
  },
  {
    id: 'webhook-no-signature-verify',
    name: 'Missing Webhook Signature Verification',
    description: 'Webhook endpoint without payload signature verification',
    category: 'missing_auth',
    pattern: /(?:app|router)\s*\.post\s*\(\s*['"`]\/(?:webhook|hook|callback)[^'"`]*['"`][\s\S]{1,200}(?:req\.body|ctx\.request\.body)(?![\s\S]{0,200}(?:verify|signature|hmac|sha256|crypto))/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Verify webhook payload signatures using HMAC-SHA256 before processing.',
  },
  {
    id: 'webhook-no-rate-limit',
    name: 'Missing Rate Limiting',
    description: 'API endpoint without rate limiting middleware',
    category: 'missing_auth',
    pattern: /(?:app|router)\s*\.(?:get|post|put|delete)\s*\(\s*['"`]\/api\/[^'"`]+['"`][\s\S]{1,100}(?:async\s+)?\((?:req|ctx)\b(?![\s\S]{0,300}(?:rateLimit|rateLimiter|throttle|limiter))/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Add rate limiting middleware to API endpoints to prevent abuse.',
  },
  {
    id: 'webhook-no-csrf-protection',
    name: 'Missing CSRF Protection',
    description: 'Form-handling endpoint without CSRF token validation',
    category: 'missing_auth',
    pattern: /(?:app|router)\s*\.post\s*\(\s*['"`]\/(?!api\/)(?!webhook)[^'"`]+['"`][\s\S]{1,200}(?:req\.body)(?![\s\S]{0,200}(?:csrf|_csrf|csrfToken|xsrf))/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Add CSRF protection middleware for form-handling endpoints.',
  },
  {
    id: 'webhook-open-redirect',
    name: 'Unvalidated Redirect Endpoint',
    description: 'Endpoint that redirects to user-controlled URL without validation',
    category: 'missing_auth',
    pattern: /(?:res\.redirect|ctx\.redirect)\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z]+|(?:url|redirect|next|goto|return_to)\b)/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Validate redirect URLs against an allowlist. Never redirect to unvalidated user input.',
  },
];

// ─── Insecure Endpoint Patterns ────────────────────────────────

const insecureEndpointPatterns: WebhookPattern[] = [
  {
    id: 'webhook-http-only',
    name: 'HTTP-Only Endpoint',
    description: 'API endpoint configured for HTTP without HTTPS',
    category: 'insecure_endpoint',
    pattern: /(?:listen|createServer|serve)\s*\([\s\S]{0,100}(?:http\.createServer|port\s*[=:]\s*80\b|protocol\s*[=:]\s*['"`]http['"`])/i,
    severity: 'medium',
    mitre: ['T1557'],
    remediation: 'Enable HTTPS/TLS. Use HSTS headers and redirect HTTP to HTTPS.',
  },
  {
    id: 'webhook-debug-endpoint',
    name: 'Debug Endpoint Exposed',
    description: 'Debug or diagnostic endpoint exposed in production',
    category: 'insecure_endpoint',
    pattern: /(?:app|router)\s*\.(?:get|post|all)\s*\(\s*['"`]\/(?:debug|diagnostics|health-check-full|_internal|__debug|phpinfo|server-status|actuator(?:\/[a-z]+)?)[^'"`]*['"`]/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Remove or restrict access to debug endpoints in production. Use environment-based guards.',
  },
  {
    id: 'webhook-graphql-introspection',
    name: 'GraphQL Introspection Enabled',
    description: 'GraphQL schema introspection enabled exposing full API schema',
    category: 'insecure_endpoint',
    pattern: /introspection\s*:\s*true|(?:__schema|__type)\s*\{/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Disable GraphQL introspection in production. Enable only in development environments.',
  },
  {
    id: 'webhook-verbose-errors',
    name: 'Verbose Error Responses',
    description: 'API returns stack traces or internal errors to clients',
    category: 'insecure_endpoint',
    pattern: /(?:res\.(?:json|send)|ctx\.body)\s*\([\s\S]{0,50}(?:err\.stack|error\.stack|stackTrace|stack_trace|err\.message)/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Return generic error messages to clients. Log detailed errors server-side only.',
  },
  {
    id: 'webhook-sql-injection-sink',
    name: 'SQL Injection in Endpoint',
    description: 'API endpoint with unsanitized user input in SQL queries',
    category: 'insecure_endpoint',
    pattern: /(?:query|execute)\s*\(\s*(?:`[^`]*\$\{(?:req\.|ctx\.)|['"`]\s*\+\s*(?:req\.|ctx\.))/i,
    severity: 'critical',
    mitre: ['T1190'],
    remediation: 'Use parameterized queries or an ORM. Never concatenate user input into SQL strings.',
  },
];

// ─── CORS Misconfiguration Patterns ────────────────────────────

const corsMiscfgPatterns: WebhookPattern[] = [
  {
    id: 'webhook-cors-wildcard',
    name: 'CORS Wildcard Origin',
    description: 'CORS configuration allows any origin (*) with credentials',
    category: 'cors_miscfg',
    pattern: /(?:Access-Control-Allow-Origin|allowOrigin|cors.*origin)\s*[=:]\s*['"`]\*['"`]/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Set specific allowed origins instead of wildcard. Never use * with credentials: true.',
  },
  {
    id: 'webhook-cors-reflected-origin',
    name: 'CORS Reflected Origin',
    description: 'CORS origin reflected from request header without validation',
    category: 'cors_miscfg',
    pattern: /(?:Access-Control-Allow-Origin|res\.(?:set|header))\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*(?:req\.headers?\.origin|req\.get\s*\(\s*['"`]origin['"`]\s*\))/i,
    severity: 'critical',
    mitre: ['T1190'],
    remediation: 'Validate the Origin header against an allowlist. Never reflect arbitrary origins.',
  },
  {
    id: 'webhook-cors-credentials-wildcard',
    name: 'CORS Credentials with Wildcard',
    description: 'CORS allows credentials with permissive origin configuration',
    category: 'cors_miscfg',
    pattern: /(?:credentials\s*:\s*true|Access-Control-Allow-Credentials\s*[=:]\s*['"`]?true)[\s\S]{1,200}(?:origin\s*[=:]\s*['"`]?\*|origin\s*[=:]\s*true)/i,
    severity: 'critical',
    mitre: ['T1190'],
    remediation: 'Never combine Access-Control-Allow-Credentials: true with wildcard origin.',
  },
  {
    id: 'webhook-cors-methods-all',
    name: 'CORS All Methods Allowed',
    description: 'CORS configuration allows all HTTP methods',
    category: 'cors_miscfg',
    pattern: /(?:Access-Control-Allow-Methods|allowMethods|methods)\s*[=:]\s*['"`]\*['"`]/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Restrict allowed methods to only those needed (GET, POST, etc.).',
  },
  {
    id: 'webhook-cors-headers-all',
    name: 'CORS All Headers Allowed',
    description: 'CORS configuration allows all request headers',
    category: 'cors_miscfg',
    pattern: /(?:Access-Control-Allow-Headers|allowHeaders|allowedHeaders)\s*[=:]\s*['"`]\*['"`]/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Restrict allowed headers to specific headers needed by the application.',
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 31 webhook and API endpoint security detection patterns.
 */
export const ALL_WEBHOOK_PATTERNS: readonly WebhookPattern[] = [
  ...webhookUrlPatterns,
  ...apiKeyUrlPatterns,
  ...missingAuthPatterns,
  ...insecureEndpointPatterns,
  ...corsMiscfgPatterns,
];

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: WebhookCategory): WebhookPattern[] {
  return ALL_WEBHOOK_PATTERNS.filter((p) => p.category === category);
}

/**
 * Pattern count by category (for logging/reporting).
 */
export function getPatternCounts(): Record<WebhookCategory, number> {
  const counts: Record<WebhookCategory, number> = {
    webhook_url: 0,
    api_key_url: 0,
    missing_auth: 0,
    insecure_endpoint: 0,
    cors_miscfg: 0,
  };

  for (const p of ALL_WEBHOOK_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}
