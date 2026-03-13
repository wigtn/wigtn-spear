/**
 * SPEAR-14: Network Recon & SSRF Tester -- Pattern Definitions
 *
 * Defines 27 detection patterns across five categories:
 *
 *   - ssrf_sink          -- Functions that accept URLs and make outbound requests
 *   - internal_ip        -- Hardcoded internal/private IP addresses
 *   - metadata_access    -- Cloud metadata endpoint access patterns
 *   - dns_rebinding      -- DNS rebinding vulnerability patterns
 *   - url_parsing        -- URL parsing flaws that enable SSRF bypass
 *
 * Each pattern includes MITRE ATT&CK mappings for enterprise threat classification.
 *
 * MITRE references used:
 *   T1090     -- Proxy
 *   T1190     -- Exploit Public-Facing Application
 *   T1552     -- Unsecured Credentials
 *   T1557     -- Adversary-in-the-Middle
 *   T1567     -- Exfiltration Over Web Service
 *   T1071     -- Application Layer Protocol
 *   T1018     -- Remote System Discovery
 *   T1046     -- Network Service Discovery
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type SsrfCategory =
  | 'ssrf_sink'
  | 'internal_ip'
  | 'metadata_access'
  | 'dns_rebinding'
  | 'url_parsing';

export interface SsrfPattern {
  id: string;
  name: string;
  description: string;
  category: SsrfCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── SSRF Sink Patterns ────────────────────────────────────────

const ssrfSinkPatterns: SsrfPattern[] = [
  {
    id: 'ssrf-fetch-user-input',
    name: 'Fetch with User-Controlled URL',
    description: 'fetch() called with user-controlled URL parameter without validation',
    category: 'ssrf_sink',
    pattern: /fetch\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z]+|(?:url|uri|target|endpoint|href|link|redirect|callback|webhook)\b)/i,
    severity: 'critical',
    mitre: ['T1190', 'T1567'],
    remediation: 'Validate and allowlist URLs before passing to fetch(). Block internal IPs and metadata endpoints.',
  },
  {
    id: 'ssrf-axios-user-input',
    name: 'Axios with User-Controlled URL',
    description: 'axios.get/post called with user-controlled URL parameter',
    category: 'ssrf_sink',
    pattern: /axios\.(?:get|post|put|delete|patch|request)\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z]+|(?:url|uri|target|endpoint|href|link)\b)/i,
    severity: 'critical',
    mitre: ['T1190', 'T1567'],
    remediation: 'Validate URLs before passing to axios. Implement URL allowlisting and block private IP ranges.',
  },
  {
    id: 'ssrf-http-request-user-input',
    name: 'HTTP Request with User-Controlled URL',
    description: 'http.request or https.request called with user-controlled options',
    category: 'ssrf_sink',
    pattern: /https?\.(?:request|get)\s*\(\s*(?:req\.(?:query|body|params)|(?:url|uri|target|options)\b)/i,
    severity: 'critical',
    mitre: ['T1190', 'T1567'],
    remediation: 'Validate URL parameters before making HTTP requests. Implement SSRF protections.',
  },
  {
    id: 'ssrf-urllib-user-input',
    name: 'Python urllib with User Input',
    description: 'Python urllib.request.urlopen called with user-controlled URL',
    category: 'ssrf_sink',
    pattern: /(?:urllib\.request\.urlopen|urllib2\.urlopen|requests\.(?:get|post|put|delete|head|patch))\s*\(\s*(?:request\.(?:GET|POST|args|form)|(?:url|uri|target)\b)/i,
    severity: 'critical',
    mitre: ['T1190', 'T1567'],
    remediation: 'Validate and sanitize URLs before passing to urllib/requests. Block internal network access.',
  },
  {
    id: 'ssrf-curl-user-input',
    name: 'cURL with User-Controlled URL',
    description: 'PHP curl_exec or curl_setopt with user-controlled URL',
    category: 'ssrf_sink',
    pattern: /curl_setopt\s*\(.*CURLOPT_URL\s*,\s*\$(?:_GET|_POST|_REQUEST|url|uri|target)/i,
    severity: 'critical',
    mitre: ['T1190', 'T1567'],
    remediation: 'Validate URLs before passing to cURL. Implement URL allowlisting.',
  },
  {
    id: 'ssrf-got-user-input',
    name: 'Got/Needle with User-Controlled URL',
    description: 'got or needle HTTP client called with user-controlled URL',
    category: 'ssrf_sink',
    pattern: /(?:got|needle)\s*(?:\.\s*(?:get|post|put|delete|patch))?\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z]+|(?:url|uri|target|endpoint)\b)/i,
    severity: 'critical',
    mitre: ['T1190', 'T1567'],
    remediation: 'Validate URLs before passing to HTTP client libraries.',
  },
  {
    id: 'ssrf-redirect-unvalidated',
    name: 'Unvalidated Redirect URL',
    description: 'HTTP redirect using user-controlled URL without validation',
    category: 'ssrf_sink',
    pattern: /(?:res\.redirect|redirect|location\.href)\s*(?:\(|=)\s*(?:req\.(?:query|body|params)\.[a-zA-Z]+|(?:url|uri|redirect_url|return_url|next|callback)\b)/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Validate redirect URLs against an allowlist. Use relative paths instead of full URLs.',
  },
];

// ─── Internal IP Patterns ──────────────────────────────────────

const internalIpPatterns: SsrfPattern[] = [
  {
    id: 'ssrf-private-ip-10',
    name: 'Private IP Range 10.x.x.x',
    description: 'Hardcoded private IP address in the 10.0.0.0/8 range',
    category: 'internal_ip',
    pattern: /(?:https?:\/\/|['"`])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/,
    severity: 'medium',
    mitre: ['T1018'],
    remediation: 'Remove hardcoded internal IP addresses. Use service discovery or DNS names.',
  },
  {
    id: 'ssrf-private-ip-172',
    name: 'Private IP Range 172.16-31.x.x',
    description: 'Hardcoded private IP address in the 172.16.0.0/12 range',
    category: 'internal_ip',
    pattern: /(?:https?:\/\/|['"`])172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?/,
    severity: 'medium',
    mitre: ['T1018'],
    remediation: 'Remove hardcoded internal IP addresses. Use configuration or environment variables.',
  },
  {
    id: 'ssrf-private-ip-192',
    name: 'Private IP Range 192.168.x.x',
    description: 'Hardcoded private IP address in the 192.168.0.0/16 range',
    category: 'internal_ip',
    pattern: /(?:https?:\/\/|['"`])192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?/,
    severity: 'medium',
    mitre: ['T1018'],
    remediation: 'Remove hardcoded internal IP addresses. Use service discovery.',
  },
  {
    id: 'ssrf-localhost-access',
    name: 'Localhost Access Pattern',
    description: 'Code accessing localhost or 127.0.0.1 which may indicate SSRF target',
    category: 'internal_ip',
    pattern: /(?:fetch|axios|http|request|got|needle|urllib|curl)\s*[.(]\s*['"`]?https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/i,
    severity: 'low',
    mitre: ['T1018'],
    remediation: 'Ensure localhost access is intentional and not user-controlled.',
  },
  {
    id: 'ssrf-link-local-ip',
    name: 'Link-Local IP Range 169.254.x.x',
    description: 'Access to link-local IP range often used for cloud metadata services',
    category: 'internal_ip',
    pattern: /169\.254\.\d{1,3}\.\d{1,3}/,
    severity: 'high',
    mitre: ['T1552', 'T1018'],
    remediation: 'Block access to 169.254.0.0/16 range. This is commonly used for cloud metadata endpoints.',
  },
];

// ─── Cloud Metadata Access Patterns ────────────────────────────

const metadataPatterns: SsrfPattern[] = [
  {
    id: 'ssrf-aws-metadata',
    name: 'AWS Metadata Endpoint Access',
    description: 'Access to AWS EC2 instance metadata endpoint at 169.254.169.254',
    category: 'metadata_access',
    pattern: /169\.254\.169\.254(?:\/(?:latest|meta-data|user-data|iam))?/,
    severity: 'critical',
    mitre: ['T1552', 'T1190'],
    remediation: 'Block access to 169.254.169.254. Use IMDSv2 with required token headers.',
  },
  {
    id: 'ssrf-gcp-metadata',
    name: 'GCP Metadata Endpoint Access',
    description: 'Access to GCP metadata endpoint at metadata.google.internal',
    category: 'metadata_access',
    pattern: /metadata\.google\.internal/i,
    severity: 'critical',
    mitre: ['T1552', 'T1190'],
    remediation: 'Block access to metadata.google.internal. Validate Metadata-Flavor header.',
  },
  {
    id: 'ssrf-azure-metadata',
    name: 'Azure Metadata Endpoint Access',
    description: 'Access to Azure Instance Metadata Service at 169.254.169.254/metadata',
    category: 'metadata_access',
    pattern: /169\.254\.169\.254\/metadata/,
    severity: 'critical',
    mitre: ['T1552', 'T1190'],
    remediation: 'Block access to Azure IMDS. Validate Metadata: true header requirement.',
  },
  {
    id: 'ssrf-alibaba-metadata',
    name: 'Alibaba Cloud Metadata Access',
    description: 'Access to Alibaba Cloud metadata endpoint',
    category: 'metadata_access',
    pattern: /100\.100\.100\.200/,
    severity: 'critical',
    mitre: ['T1552', 'T1190'],
    remediation: 'Block access to Alibaba Cloud metadata endpoint at 100.100.100.200.',
  },
  {
    id: 'ssrf-kubernetes-api',
    name: 'Kubernetes API Server Access',
    description: 'Direct access to Kubernetes API server or service account tokens',
    category: 'metadata_access',
    pattern: /(?:https?:\/\/)?(?:kubernetes\.default\.svc|10\.96\.0\.1|kubernetes\.default)/i,
    severity: 'high',
    mitre: ['T1552'],
    remediation: 'Use proper service accounts and RBAC instead of direct API server access.',
  },
  {
    id: 'ssrf-consul-metadata',
    name: 'Consul/Vault Internal Access',
    description: 'Access to internal Consul or Vault service endpoints',
    category: 'metadata_access',
    pattern: /(?:https?:\/\/)?(?:consul|vault)(?:\.service\.consul)?(?::\d+)?\/v1\//i,
    severity: 'high',
    mitre: ['T1552'],
    remediation: 'Restrict access to Consul/Vault endpoints. Use ACLs and token authentication.',
  },
];

// ─── DNS Rebinding Patterns ────────────────────────────────────

const dnsRebindingPatterns: SsrfPattern[] = [
  {
    id: 'ssrf-dns-no-pin',
    name: 'Missing DNS Pinning',
    description: 'URL resolution without DNS pinning allows DNS rebinding attacks',
    category: 'dns_rebinding',
    pattern: /(?:dns\.(?:resolve|lookup)|getaddrinfo)\s*\(.*(?:req\.|user|input|param)/i,
    severity: 'high',
    mitre: ['T1557', 'T1190'],
    remediation: 'Implement DNS pinning. Resolve the hostname once and validate the IP before making the request.',
  },
  {
    id: 'ssrf-ttl-zero',
    name: 'Zero TTL DNS Response',
    description: 'Accepting DNS responses with zero TTL enables rapid rebinding',
    category: 'dns_rebinding',
    pattern: /(?:ttl|cacheTtl|minTtl)\s*[=:]\s*0/i,
    severity: 'medium',
    mitre: ['T1557'],
    remediation: 'Enforce a minimum DNS cache TTL. Do not accept TTL=0 responses.',
  },
  {
    id: 'ssrf-double-fetch',
    name: 'Double Fetch Vulnerability',
    description: 'URL resolved twice allowing TOCTOU DNS rebinding',
    category: 'dns_rebinding',
    pattern: /(?:new\s+URL\s*\(.*\)[\s\S]{1,100}fetch\s*\(|resolve.*[\s\S]{1,100}request\s*\()/i,
    severity: 'high',
    mitre: ['T1557', 'T1190'],
    remediation: 'Resolve the URL once, validate the IP, and use the resolved IP for the request.',
  },
];

// ─── URL Parsing Patterns ──────────────────────────────────────

const urlParsingPatterns: SsrfPattern[] = [
  {
    id: 'ssrf-url-scheme-bypass',
    name: 'URL Scheme Bypass',
    description: 'URL validation that does not check scheme allows file://, gopher://, dict://',
    category: 'url_parsing',
    pattern: /(?:file|gopher|dict|ftp|ldap|tftp)\s*:\/\//i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Validate URL scheme is http or https only. Block file://, gopher://, and other dangerous schemes.',
  },
  {
    id: 'ssrf-ipv6-bypass',
    name: 'IPv6 Address SSRF Bypass',
    description: 'IPv6 localhost representation used to bypass SSRF filters',
    category: 'url_parsing',
    pattern: /(?:\[::\]|(?:0{4}:){5}(?:0{4}|ffff):\d|(?:0x7f|0177)\.)/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Validate both IPv4 and IPv6 addresses. Block ::1, [::], and IPv4-mapped IPv6 addresses.',
  },
  {
    id: 'ssrf-decimal-ip',
    name: 'Decimal IP Notation Bypass',
    description: 'Decimal or octal IP notation used to bypass SSRF IP filters',
    category: 'url_parsing',
    pattern: /(?:https?:\/\/)?(?:0x[0-9a-f]{8}|2130706433|\d{8,10})\b/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Normalize IP addresses before validation. Reject non-standard IP notations.',
  },
  {
    id: 'ssrf-url-auth-bypass',
    name: 'URL Authentication Bypass',
    description: 'URL with embedded credentials or @ symbol used to bypass hostname checks',
    category: 'url_parsing',
    pattern: /https?:\/\/[^@]+@(?:169\.254|10\.|172\.(?:1[6-9]|2\d|3[01])|192\.168|localhost|127\.0\.0\.1)/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Strip credentials from URLs before validation. Parse the hostname after removing userinfo.',
  },
  {
    id: 'ssrf-ssrf-redirect-chain',
    name: 'Open Redirect to SSRF Chain',
    description: 'Open redirect that could be chained with SSRF to access internal resources',
    category: 'url_parsing',
    pattern: /(?:redirect|return_to|next|goto|url)\s*=\s*https?%3A%2F%2F(?:169\.254|10\.|172\.|192\.168|localhost|127\.0\.0\.1)/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Validate redirect targets against an allowlist. Never redirect to internal IP ranges.',
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 27 SSRF and network recon detection patterns.
 */
export const ALL_SSRF_PATTERNS: readonly SsrfPattern[] = [
  ...ssrfSinkPatterns,
  ...internalIpPatterns,
  ...metadataPatterns,
  ...dnsRebindingPatterns,
  ...urlParsingPatterns,
];

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: SsrfCategory): SsrfPattern[] {
  return ALL_SSRF_PATTERNS.filter((p) => p.category === category);
}

/**
 * Pattern count by category (for logging/reporting).
 */
export function getPatternCounts(): Record<SsrfCategory, number> {
  const counts: Record<SsrfCategory, number> = {
    ssrf_sink: 0,
    internal_ip: 0,
    metadata_access: 0,
    dns_rebinding: 0,
    url_parsing: 0,
  };

  for (const p of ALL_SSRF_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}
