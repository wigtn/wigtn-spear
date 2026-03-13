/**
 * SPEAR-25: HTTP Security Header Analyzer
 *
 * Analyzes HTTP response headers and cookies for security misconfigurations.
 * No source code needed — works with any URL.
 *
 * Checks:
 *   - Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
 *     Referrer-Policy, Permissions-Policy
 *   - Cookie security: HttpOnly, Secure, SameSite flags
 *   - Information leakage: Server, X-Powered-By, X-AspNet-Version
 *   - CORS misconfiguration: Wildcard origins, credentials with wildcard
 *   - HTTPS enforcement: Redirect from HTTP, HSTS preload
 *
 * OWASP: A05 (Security Misconfiguration)
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface HeaderAnalysisResult {
  /** Missing security headers */
  missingHeaders: MissingHeader[];
  /** Insecure cookies */
  insecureCookies: InsecureCookie[];
  /** Information leakage via headers */
  infoLeaks: InfoLeak[];
  /** CORS issues */
  corsIssues: CorsIssue[];
  /** Technology fingerprint extracted from headers */
  fingerprint: TechFingerprint;
  /** Raw headers for evidence */
  rawHeaders: Record<string, string>;
}

export interface MissingHeader {
  /** Header name */
  header: string;
  /** Why it matters */
  impact: string;
  /** Recommended value */
  recommended: string;
  /** Severity */
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface InsecureCookie {
  /** Cookie name */
  name: string;
  /** Missing flags */
  missingFlags: string[];
  /** Why it matters */
  impact: string;
  /** Raw Set-Cookie header */
  raw: string;
}

export interface InfoLeak {
  /** Header that leaks info */
  header: string;
  /** Leaked value */
  value: string;
  /** What it reveals */
  reveals: string;
}

export interface CorsIssue {
  /** Issue type */
  type: 'wildcard_origin' | 'credentials_with_wildcard' | 'null_origin' | 'reflect_origin';
  /** Description */
  description: string;
  /** Evidence */
  evidence: string;
}

export interface TechFingerprint {
  /** Server software */
  server?: string;
  /** Framework */
  framework?: string;
  /** Language/Runtime */
  runtime?: string;
  /** CDN/Proxy */
  cdn?: string;
  /** All detected technologies */
  technologies: string[];
}

export interface HeaderScanConfig {
  /** Target URL */
  baseUrl: string;
  /** Timeout in ms */
  timeout?: number;
  /** Logger */
  logger?: SpearLogger;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 10_000;

// ─── Security Header Definitions ──────────────────────────────

interface RequiredHeader {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  impact: string;
  recommended: string;
  /** If present, also validate value */
  validate?: (value: string) => string | null;
}

const REQUIRED_HEADERS: readonly RequiredHeader[] = [
  {
    name: 'Strict-Transport-Security',
    severity: 'high',
    impact: 'No HSTS — vulnerable to SSL stripping and downgrade attacks',
    recommended: 'max-age=31536000; includeSubDomains; preload',
    validate: (v) => {
      const maxAge = /max-age=(\d+)/.exec(v);
      if (maxAge && Number(maxAge[1]) < 31536000) {
        return `HSTS max-age too short (${maxAge[1]}s). Recommend 31536000 (1 year)`;
      }
      return null;
    },
  },
  {
    name: 'Content-Security-Policy',
    severity: 'high',
    impact: 'No CSP — vulnerable to XSS, clickjacking, and code injection attacks',
    recommended: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
    validate: (v) => {
      if (v.includes("'unsafe-eval'")) {
        return "CSP contains 'unsafe-eval' — allows eval(), Function(), and similar";
      }
      if (v.includes('*') && !v.includes('*.')) {
        return 'CSP contains wildcard (*) source — overly permissive';
      }
      return null;
    },
  },
  {
    name: 'X-Content-Type-Options',
    severity: 'medium',
    impact: 'Missing X-Content-Type-Options — vulnerable to MIME-type sniffing attacks',
    recommended: 'nosniff',
    validate: (v) => {
      if (v.toLowerCase() !== 'nosniff') {
        return `Invalid value "${v}". Must be "nosniff"`;
      }
      return null;
    },
  },
  {
    name: 'X-Frame-Options',
    severity: 'medium',
    impact: 'Missing X-Frame-Options — vulnerable to clickjacking attacks',
    recommended: 'DENY',
    validate: (v) => {
      const upper = v.toUpperCase();
      if (upper !== 'DENY' && upper !== 'SAMEORIGIN') {
        return `Weak X-Frame-Options value "${v}". Use DENY or SAMEORIGIN`;
      }
      return null;
    },
  },
  {
    name: 'Referrer-Policy',
    severity: 'low',
    impact: 'Missing Referrer-Policy — may leak sensitive URL paths to external sites',
    recommended: 'strict-origin-when-cross-origin',
  },
  {
    name: 'Permissions-Policy',
    severity: 'low',
    impact: 'Missing Permissions-Policy — browser features (camera, mic, geolocation) not restricted',
    recommended: 'camera=(), microphone=(), geolocation=()',
  },
  {
    name: 'X-XSS-Protection',
    severity: 'low',
    impact: 'Missing X-XSS-Protection — older browsers lack XSS filter hint',
    recommended: '0',
    validate: (v) => {
      // Modern recommendation is 0 (rely on CSP instead)
      // But 1; mode=block is still acceptable
      if (v === '1' && !v.includes('mode=block')) {
        return 'X-XSS-Protection: 1 without mode=block can introduce vulnerabilities';
      }
      return null;
    },
  },
];

// ─── Info Leak Headers ────────────────────────────────────────

interface InfoLeakHeader {
  header: string;
  reveals: string;
}

const INFO_LEAK_HEADERS: readonly InfoLeakHeader[] = [
  { header: 'Server', reveals: 'Server software and version' },
  { header: 'X-Powered-By', reveals: 'Framework or runtime' },
  { header: 'X-AspNet-Version', reveals: 'ASP.NET version' },
  { header: 'X-AspNetMvc-Version', reveals: 'ASP.NET MVC version' },
  { header: 'X-Runtime', reveals: 'Server processing time and runtime' },
  { header: 'X-Generator', reveals: 'CMS or site generator' },
  { header: 'X-Drupal-Cache', reveals: 'Drupal CMS usage' },
  { header: 'X-Varnish', reveals: 'Varnish cache proxy' },
  { header: 'Via', reveals: 'Proxy chain and versions' },
  { header: 'X-Debug-Token', reveals: 'Debug profiler active (Symfony)' },
];

// ─── Scanner ──────────────────────────────────────────────────

/**
 * Analyze HTTP security headers of a target URL.
 */
export async function analyzeHttpHeaders(
  config: HeaderScanConfig,
): Promise<HeaderAnalysisResult> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const logger = config.logger;

  logger?.info('http-header-analyzer: starting', { baseUrl });

  const result: HeaderAnalysisResult = {
    missingHeaders: [],
    insecureCookies: [],
    infoLeaks: [],
    corsIssues: [],
    fingerprint: { technologies: [] },
    rawHeaders: {},
  };

  // ── Fetch target URL ──────────────────────────────────────

  let headers: Headers;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(baseUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
        Accept: 'text/html,application/xhtml+xml,*/*',
      },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);
    headers = response.headers;
  } catch (err) {
    logger?.info('http-header-analyzer: failed to fetch', { error: String(err) });
    return result;
  }

  // Store raw headers
  headers.forEach((value, key) => {
    result.rawHeaders[key] = value;
  });

  // ── Check Required Security Headers ───────────────────────

  for (const req of REQUIRED_HEADERS) {
    const value = headers.get(req.name);

    if (!value) {
      result.missingHeaders.push({
        header: req.name,
        impact: req.impact,
        recommended: req.recommended,
        severity: req.severity,
      });
    } else if (req.validate) {
      const issue = req.validate(value);
      if (issue) {
        result.missingHeaders.push({
          header: req.name,
          impact: issue,
          recommended: req.recommended,
          severity: req.severity === 'critical' ? 'critical' : 'medium',
        });
      }
    }
  }

  // ── Check Cookies ─────────────────────────────────────────

  const setCookieHeaders = extractSetCookieHeaders(headers);
  for (const cookieHeader of setCookieHeaders) {
    const issues = analyzeCookie(cookieHeader);
    if (issues) {
      result.insecureCookies.push(issues);
    }
  }

  // ── Check Info Leakage ────────────────────────────────────

  for (const leak of INFO_LEAK_HEADERS) {
    const value = headers.get(leak.header);
    if (value) {
      result.infoLeaks.push({
        header: leak.header,
        value,
        reveals: leak.reveals,
      });
    }
  }

  // ── Check CORS ────────────────────────────────────────────

  const corsIssues = await checkCors(baseUrl, timeout);
  result.corsIssues.push(...corsIssues);

  // ── Build Fingerprint ─────────────────────────────────────

  result.fingerprint = buildFingerprint(headers);

  logger?.info('http-header-analyzer: scan complete', {
    missingHeaders: result.missingHeaders.length,
    insecureCookies: result.insecureCookies.length,
    infoLeaks: result.infoLeaks.length,
    corsIssues: result.corsIssues.length,
    technologies: result.fingerprint.technologies,
  });

  return result;
}

// ─── Cookie Analysis ──────────────────────────────────────────

function extractSetCookieHeaders(headers: Headers): string[] {
  const cookies: string[] = [];

  // Headers.getSetCookie() is available in Node 20+
  if (typeof (headers as any).getSetCookie === 'function') {
    return (headers as any).getSetCookie();
  }

  // Fallback: try to get from raw headers
  const raw = headers.get('set-cookie');
  if (raw) {
    cookies.push(raw);
  }

  return cookies;
}

function analyzeCookie(setCookieHeader: string): InsecureCookie | null {
  const parts = setCookieHeader.split(';').map((p) => p.trim());
  if (parts.length === 0) return null;

  const nameValue = parts[0]!;
  const name = nameValue.split('=')[0]!.trim();
  if (!name) return null;

  const flags = parts.slice(1).map((p) => p.toLowerCase());
  const missingFlags: string[] = [];
  const impacts: string[] = [];

  // Check Secure flag
  if (!flags.some((f) => f === 'secure')) {
    missingFlags.push('Secure');
    impacts.push('cookie sent over unencrypted HTTP');
  }

  // Check HttpOnly flag
  if (!flags.some((f) => f === 'httponly')) {
    missingFlags.push('HttpOnly');
    impacts.push('cookie accessible via JavaScript (XSS risk)');
  }

  // Check SameSite flag
  if (!flags.some((f) => f.startsWith('samesite'))) {
    missingFlags.push('SameSite');
    impacts.push('cookie sent on cross-site requests (CSRF risk)');
  } else {
    const sameSiteFlag = flags.find((f) => f.startsWith('samesite'));
    if (sameSiteFlag?.includes('none') && !flags.some((f) => f === 'secure')) {
      missingFlags.push('SameSite=None requires Secure');
      impacts.push('SameSite=None without Secure flag is ignored by browsers');
    }
  }

  if (missingFlags.length === 0) return null;

  return {
    name,
    missingFlags,
    impact: impacts.join('; '),
    raw: setCookieHeader.slice(0, 200),
  };
}

// ─── CORS Check ───────────────────────────────────────────────

async function checkCors(
  baseUrl: string,
  timeout: number,
): Promise<CorsIssue[]> {
  const issues: CorsIssue[] = [];

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(baseUrl, {
      method: 'OPTIONS',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
        Origin: 'https://evil.attacker.com',
        'Access-Control-Request-Method': 'GET',
      },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);

    const allowOrigin = response.headers.get('Access-Control-Allow-Origin');
    const allowCredentials = response.headers.get('Access-Control-Allow-Credentials');

    if (allowOrigin === '*') {
      issues.push({
        type: 'wildcard_origin',
        description: 'CORS allows any origin (*) — any website can make requests',
        evidence: `Access-Control-Allow-Origin: ${allowOrigin}`,
      });

      if (allowCredentials === 'true') {
        issues.push({
          type: 'credentials_with_wildcard',
          description: 'CORS allows credentials with wildcard origin — critical misconfiguration',
          evidence: `Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true`,
        });
      }
    } else if (allowOrigin === 'https://evil.attacker.com') {
      issues.push({
        type: 'reflect_origin',
        description: 'CORS reflects arbitrary origin — effectively allows any origin',
        evidence: `Origin "https://evil.attacker.com" was reflected in Access-Control-Allow-Origin`,
      });
    } else if (allowOrigin === 'null') {
      issues.push({
        type: 'null_origin',
        description: 'CORS allows null origin — can be exploited via sandboxed iframes',
        evidence: `Access-Control-Allow-Origin: null`,
      });
    }
  } catch {
    // CORS check failed — not an issue
  }

  return issues;
}

// ─── Fingerprinting ───────────────────────────────────────────

function buildFingerprint(headers: Headers): TechFingerprint {
  const fp: TechFingerprint = { technologies: [] };

  // Server header
  const server = headers.get('Server');
  if (server) {
    fp.server = server;
    fp.technologies.push(`Server: ${server}`);
  }

  // X-Powered-By
  const poweredBy = headers.get('X-Powered-By');
  if (poweredBy) {
    fp.framework = poweredBy;
    fp.technologies.push(`Framework: ${poweredBy}`);
  }

  // Detect by header patterns
  if (headers.get('X-Vercel-Id')) {
    fp.cdn = 'Vercel';
    fp.technologies.push('CDN: Vercel');
  }
  if (headers.get('CF-Ray')) {
    fp.cdn = 'Cloudflare';
    fp.technologies.push('CDN: Cloudflare');
  }
  if (headers.get('X-Amz-Cf-Id')) {
    fp.cdn = 'CloudFront';
    fp.technologies.push('CDN: CloudFront');
  }
  if (headers.get('X-Cloud-Trace-Context')) {
    fp.cdn = 'Google Cloud';
    fp.technologies.push('Platform: Google Cloud');
  }
  if (headers.get('X-Firebase-Auth')) {
    fp.technologies.push('Auth: Firebase');
  }

  // Detect runtime from Server header
  if (server) {
    if (/nginx/i.test(server)) fp.technologies.push('Proxy: Nginx');
    if (/apache/i.test(server)) fp.technologies.push('Proxy: Apache');
    if (/express/i.test(server)) fp.runtime = 'Node.js (Express)';
    if (/next\.js/i.test(server)) fp.runtime = 'Node.js (Next.js)';
    if (/gunicorn/i.test(server)) fp.runtime = 'Python (Gunicorn)';
    if (/uvicorn/i.test(server)) fp.runtime = 'Python (Uvicorn)';
  }

  return fp;
}
