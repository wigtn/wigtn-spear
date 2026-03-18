/**
 * SPEAR-25: Probe Engine
 *
 * Performs live HTTP probing against discovered API endpoints to verify
 * authentication enforcement and discover auth bypasses.
 *
 * Probing strategy per endpoint:
 *   1. No Auth       -- Send request with no authentication headers
 *   2. Invalid Token -- Send request with invalid Bearer token
 *   3. Expired Token -- Send request with expired JWT format token
 *   4. Auth Bypass   -- 10 techniques (case manipulation, double encoding, etc.)
 *   5. CORS Check    -- OPTIONS with evil origin
 *   6. Rate Limit    -- 10 rapid requests to detect rate limiting
 *
 * Safety constraints:
 *   - Uses built-in node:fetch (no external deps)
 *   - Default timeout: 10 seconds per request
 *   - Max 5 requests/second to avoid triggering WAF
 *   - Only probes and reports -- does NOT exploit
 */

import { createHash } from 'node:crypto';
import type { SpearLogger, LiveAttackOptions } from '@wigtn/shared';
import { matchesBaseline } from './baseline-fingerprinter.js';
import type { BaselineFingerprint } from './baseline-fingerprinter.js';

// ─── Types ────────────────────────────────────────────────────

export interface ProbeResult {
  endpoint: EndpointInfo;
  /** Result of sending request with no authentication */
  noAuth: {
    status: number;
    accessible: boolean;
    responseSize: number;
    serverHeader?: string;
    durationMs: number;
  };
  /** Result of sending request with an invalid token */
  invalidAuth?: {
    status: number;
    accessible: boolean;
    durationMs: number;
  };
  /** Result of sending request with an expired token format */
  expiredAuth?: {
    status: number;
    accessible: boolean;
    durationMs: number;
  };
  /** Auth bypass attempt results */
  bypasses?: AuthBypassResult[];
  /** CORS misconfiguration check */
  cors?: CorsCheckResult;
  /** Rate limit check */
  rateLimit?: RateLimitResult;
}

export interface EndpointInfo {
  method: string;
  path: string;
  file?: string;
  line?: number;
}

export interface AuthBypassResult {
  technique: string;
  status: number;
  accessible: boolean;
  evidence: string;
  requestDetails?: string;
}

export interface CorsCheckResult {
  allowOrigin?: string;
  allowCredentials?: boolean;
  permissive: boolean;
  evidence: string;
}

export interface RateLimitResult {
  totalRequests: number;
  successfulRequests: number;
  rateLimited: boolean;
  limitHitAtRequest?: number;
  evidence: string;
}

// ─── Constants ────────────────────────────────────────────────

/** Default timeout for HTTP requests (10 seconds). */
const DEFAULT_TIMEOUT_MS = 10_000;

/** Rate limit: max 5 requests per second to avoid WAF triggers. */
const REQUEST_DELAY_MS = 200;

/** Number of rapid requests for rate limit detection. */
const RATE_LIMIT_REQUEST_COUNT = 10;

/** Invalid Bearer token for testing auth validation. */
const INVALID_TOKEN = 'invalid_token_12345';

/**
 * Fake expired JWT token (header.payload.signature format).
 * Payload decodes to { "exp": 0 } (epoch 0 = expired).
 * This is NOT a valid JWT -- it is intentionally malformed for testing.
 */
const EXPIRED_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJleHAiOjAsInN1YiI6InRlc3QifQ.' +
  'invalid_signature_for_probe';

// ─── Probe Engine ─────────────────────────────────────────────

/**
 * ProbeEngine sends HTTP requests to API endpoints to verify
 * authentication enforcement and discover auth bypasses.
 */
export class ProbeEngine {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly maxRequests: number;
  private readonly customHeaders: Record<string, string>;
  private readonly logger: SpearLogger;
  private readonly baseline: BaselineFingerprint | null;
  private requestCount = 0;

  constructor(liveAttack: LiveAttackOptions, logger: SpearLogger, baseline?: BaselineFingerprint | null) {
    // Ensure base URL has no trailing slash
    this.baseUrl = liveAttack.targetUrl.replace(/\/+$/, '');
    this.timeout = liveAttack.timeout ?? DEFAULT_TIMEOUT_MS;
    this.maxRequests = liveAttack.maxRequests ?? 500;
    this.customHeaders = liveAttack.headers ?? {};
    this.logger = logger;
    this.baseline = baseline ?? null;
  }

  /**
   * Probe a single endpoint with all test strategies.
   *
   * Performs the following checks in order:
   *   1. No Auth request
   *   2. Invalid Token request
   *   3. Expired Token request
   *   4. Auth bypass attempts (10 techniques)
   *   5. CORS permissiveness check
   *   6. Rate limit detection
   */
  async probeEndpoint(endpoint: EndpointInfo): Promise<ProbeResult | null> {
    if (this.requestCount >= this.maxRequests) {
      this.logger.warn('Max request limit reached, skipping endpoint', {
        endpoint: `${endpoint.method} ${endpoint.path}`,
        maxRequests: this.maxRequests,
      });
      return null;
    }

    const fullUrl = this.buildUrl(endpoint.path);
    const method = this.normalizeMethod(endpoint.method);

    this.logger.info('Probing endpoint', {
      method,
      path: endpoint.path,
      url: fullUrl,
    });

    // ── Step 1: No Auth ─────────────────────────────────────

    const noAuth = await this.sendRequest(fullUrl, method, {});
    if (noAuth === null) {
      this.logger.debug('No-auth request failed (network error), skipping endpoint', {
        endpoint: `${method} ${endpoint.path}`,
      });
      return null;
    }

    // Baseline FP filter: if noAuth response matches the catch-all baseline, skip
    if (matchesBaseline(this.baseline, noAuth.status, noAuth.bodyText)) {
      this.logger.debug('Response matches baseline (catch-all), filtering as FP', {
        endpoint: `${method} ${endpoint.path}`,
        status: noAuth.status,
      });
      return null;
    }

    await this.rateDelay();

    // ── Step 2: Invalid Token ───────────────────────────────

    let invalidAuth: ProbeResult['invalidAuth'];
    if (!this.isExhausted()) {
      const result = await this.sendRequest(fullUrl, method, {
        Authorization: `Bearer ${INVALID_TOKEN}`,
      });
      if (result !== null) {
        invalidAuth = {
          status: result.status,
          accessible: isAccessible(result.status),
          durationMs: result.durationMs,
        };
      }
      await this.rateDelay();
    }

    // ── Step 3: Expired Token ───────────────────────────────

    let expiredAuth: ProbeResult['expiredAuth'];
    if (!this.isExhausted()) {
      const result = await this.sendRequest(fullUrl, method, {
        Authorization: `Bearer ${EXPIRED_JWT}`,
      });
      if (result !== null) {
        expiredAuth = {
          status: result.status,
          accessible: isAccessible(result.status),
          durationMs: result.durationMs,
        };
      }
      await this.rateDelay();
    }

    // ── Step 4: Auth Bypass Attempts ────────────────────────

    let bypasses: AuthBypassResult[] | undefined;
    if (!this.isExhausted()) {
      bypasses = await this.runBypassAttempts(endpoint, method);
    }

    // ── Step 5: CORS Check ──────────────────────────────────

    let cors: CorsCheckResult | undefined;
    if (!this.isExhausted()) {
      cors = await this.checkCors(fullUrl);
      await this.rateDelay();
    }

    // ── Step 6: Rate Limit Check ────────────────────────────

    let rateLimit: RateLimitResult | undefined;
    if (!this.isExhausted()) {
      rateLimit = await this.checkRateLimit(fullUrl, method);
    }

    return {
      endpoint,
      noAuth: {
        status: noAuth.status,
        accessible: isAccessible(noAuth.status),
        responseSize: noAuth.bodySize,
        serverHeader: noAuth.serverHeader,
        durationMs: noAuth.durationMs,
      },
      invalidAuth,
      expiredAuth,
      bypasses,
      cors,
      rateLimit,
    };
  }

  // ─── Bypass Techniques ─────────────────────────────────────

  /**
   * Run all 10 auth bypass techniques against an endpoint.
   */
  private async runBypassAttempts(
    endpoint: EndpointInfo,
    method: string,
  ): Promise<AuthBypassResult[]> {
    const results: AuthBypassResult[] = [];
    const techniques = this.generateBypassAttempts(endpoint, method);

    for (const technique of techniques) {
      if (this.isExhausted()) break;

      const result = await this.sendRequest(
        technique.url,
        technique.method,
        technique.headers,
      );

      if (result !== null) {
        const accessible = isAccessible(result.status);
        results.push({
          technique: technique.name,
          status: result.status,
          accessible,
          evidence: accessible
            ? `Bypass successful: ${technique.name} returned ${result.status} (${result.bodySize} bytes)`
            : `Bypass failed: ${technique.name} returned ${result.status}`,
          requestDetails: `${technique.method} ${technique.url}`,
        });
      }

      await this.rateDelay();
    }

    return results;
  }

  /**
   * Generate the 10 auth bypass attempt configurations.
   */
  private generateBypassAttempts(
    endpoint: EndpointInfo,
    method: string,
  ): BypassAttempt[] {
    const path = endpoint.path;
    const attempts: BypassAttempt[] = [];

    // 1. Case manipulation: /Admin vs /admin
    const casePath = manipulateCase(path);
    if (casePath !== path) {
      attempts.push({
        name: 'case_manipulation',
        url: this.buildUrl(casePath),
        method,
        headers: {},
      });
    }

    // 2. Double encoding: %252e%252e%252f
    const doubleEncoded = doubleEncode(path);
    attempts.push({
      name: 'double_encoding',
      url: this.buildUrl(doubleEncoded),
      method,
      headers: {},
    });

    // 3. Path traversal: /api/../relay/calls/start
    const traversalPath = injectPathTraversal(path);
    if (traversalPath !== path) {
      attempts.push({
        name: 'path_traversal',
        url: this.buildUrl(traversalPath),
        method,
        headers: {},
      });
    }

    // 4. HTTP method override: X-HTTP-Method-Override header
    attempts.push({
      name: 'method_override',
      url: this.buildUrl(path),
      method: 'POST',
      headers: { 'X-HTTP-Method-Override': 'GET' },
    });

    // 5. HTTP verb tampering: use GET on POST-only endpoints
    const altMethod = method === 'GET' ? 'POST' : 'GET';
    attempts.push({
      name: 'verb_tampering',
      url: this.buildUrl(path),
      method: altMethod,
      headers: {},
    });

    // 6. Null byte injection: /api/endpoint%00.json
    attempts.push({
      name: 'null_byte_injection',
      url: this.buildUrl(path + '%00.json'),
      method,
      headers: {},
    });

    // 7. Trailing slash: /api/endpoint/ vs /api/endpoint
    const trailingSlashPath = path.endsWith('/')
      ? path.slice(0, -1)
      : path + '/';
    attempts.push({
      name: 'trailing_slash',
      url: this.buildUrl(trailingSlashPath),
      method,
      headers: {},
    });

    // 8. Add .json extension: /api/endpoint.json
    attempts.push({
      name: 'json_extension',
      url: this.buildUrl(path + '.json'),
      method,
      headers: {},
    });

    // 9. Origin header spoof
    attempts.push({
      name: 'origin_spoof',
      url: this.buildUrl(path),
      method,
      headers: { Origin: 'http://localhost:3000' },
    });

    // 10. Referer header spoof
    attempts.push({
      name: 'referer_spoof',
      url: this.buildUrl(path),
      method,
      headers: { Referer: 'https://trusted-domain.com' },
    });

    return attempts;
  }

  // ─── CORS Check ─────────────────────────────────────────────

  /**
   * Check CORS configuration by sending OPTIONS with a malicious origin.
   */
  private async checkCors(fullUrl: string): Promise<CorsCheckResult> {
    const result = await this.sendRequest(fullUrl, 'OPTIONS', {
      Origin: 'https://evil.com',
      'Access-Control-Request-Method': 'GET',
    });

    if (result === null) {
      return {
        permissive: false,
        evidence: 'CORS check failed: no response from server',
      };
    }

    const allowOrigin = result.headers.get('access-control-allow-origin') ?? undefined;
    const allowCredentials =
      result.headers.get('access-control-allow-credentials') === 'true';

    const permissive =
      allowOrigin === '*' ||
      allowOrigin === 'https://evil.com' ||
      (allowOrigin === 'null');

    let evidence: string;
    if (permissive && allowCredentials) {
      evidence =
        `Permissive CORS: Access-Control-Allow-Origin=${allowOrigin} ` +
        `with Access-Control-Allow-Credentials=true -- credentials can be stolen cross-origin`;
    } else if (permissive) {
      evidence = `Permissive CORS: Access-Control-Allow-Origin=${allowOrigin}`;
    } else if (allowOrigin) {
      evidence = `CORS restricted: Access-Control-Allow-Origin=${allowOrigin}`;
    } else {
      evidence = 'No CORS headers in response';
    }

    return { allowOrigin, allowCredentials, permissive, evidence };
  }

  // ─── Rate Limit Check ──────────────────────────────────────

  /**
   * Check rate limiting by sending rapid requests.
   * Sends 10 requests and checks if any return 429.
   */
  private async checkRateLimit(
    fullUrl: string,
    method: string,
  ): Promise<RateLimitResult> {
    let successfulRequests = 0;
    let limitHitAtRequest: number | undefined;
    const totalToSend = Math.min(
      RATE_LIMIT_REQUEST_COUNT,
      this.maxRequests - this.requestCount,
    );

    for (let i = 0; i < totalToSend; i++) {
      if (this.isExhausted()) break;

      const result = await this.sendRequest(fullUrl, method, {});
      if (result === null) break;

      if (result.status === 429) {
        limitHitAtRequest = i + 1;
        break;
      }

      if (isAccessible(result.status) || result.status === 401 || result.status === 403) {
        successfulRequests++;
      }

      // No delay here -- we want to test rate limiting with rapid requests
    }

    const rateLimited = limitHitAtRequest !== undefined;
    const evidence = rateLimited
      ? `Rate limited at request ${limitHitAtRequest} of ${totalToSend}`
      : `No rate limiting detected after ${successfulRequests} rapid requests`;

    return {
      totalRequests: totalToSend,
      successfulRequests,
      rateLimited,
      limitHitAtRequest,
      evidence,
    };
  }

  // ─── HTTP Request Helper ───────────────────────────────────

  /**
   * Send a single HTTP request and return parsed response info.
   *
   * Handles timeouts, network errors, and response parsing gracefully.
   * Returns null on any network-level failure.
   */
  private async sendRequest(
    url: string,
    method: string,
    extraHeaders: Record<string, string>,
  ): Promise<RequestResult | null> {
    this.requestCount++;

    const headers: Record<string, string> = {
      'User-Agent': 'WIGTN-SPEAR/0.1.0 (Security Scanner)',
      Accept: '*/*',
      ...this.customHeaders,
      ...extraHeaders,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const startTime = performance.now();

    try {
      const response = await fetch(url, {
        method,
        headers,
        signal: controller.signal,
        redirect: 'manual', // Do not follow redirects -- we want to see the raw response
      });

      const durationMs = Math.round(performance.now() - startTime);

      // Read body as text (limit to 64KB to avoid memory issues)
      let bodyText = '';
      try {
        bodyText = await response.text();
        if (bodyText.length > 65_536) {
          bodyText = bodyText.slice(0, 65_536);
        }
      } catch {
        // Body read failed -- that's OK
      }

      return {
        status: response.status,
        bodySize: bodyText.length,
        bodyText,
        bodyHash: createHash('sha256').update(bodyText, 'utf8').digest('hex'),
        serverHeader: response.headers.get('server') ?? undefined,
        headers: response.headers,
        durationMs,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);

      // Distinguish between timeout and other errors
      if (message.includes('abort') || message.includes('timeout')) {
        this.logger.debug('Request timed out', { url, method, timeout: this.timeout });
      } else {
        this.logger.debug('Request failed', { url, method, error: message });
      }

      return null;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ─── Helpers ────────────────────────────────────────────────

  /**
   * Build full URL from endpoint path.
   */
  private buildUrl(path: string): string {
    // Ensure path starts with /
    const normalizedPath = path.startsWith('/') ? path : '/' + path;
    const fullUrl = this.baseUrl + normalizedPath;

    // Validate URL structure and ensure origin matches base
    try {
      const parsed = new URL(fullUrl);
      const base = new URL(this.baseUrl);
      if (parsed.origin !== base.origin) {
        this.logger.warn('buildUrl: origin mismatch, using base origin', {
          path,
          parsedOrigin: parsed.origin,
          baseOrigin: base.origin,
        });
        return base.origin + parsed.pathname + parsed.search;
      }
    } catch {
      this.logger.warn('buildUrl: invalid URL constructed', { path, fullUrl });
      // Fall through with the raw concatenation
    }

    return fullUrl;
  }

  /**
   * Normalize HTTP method to uppercase. Convert WS to GET.
   */
  private normalizeMethod(method: string): string {
    const upper = method.toUpperCase();
    if (upper === 'WS' || upper === 'WEBSOCKET') return 'GET';
    if (upper === 'ALL') return 'GET';
    return upper;
  }

  /**
   * Check if max request limit is exhausted.
   */
  private isExhausted(): boolean {
    return this.requestCount >= this.maxRequests;
  }

  /**
   * Delay between requests to respect rate limiting (5 req/sec).
   */
  private async rateDelay(): Promise<void> {
    await sleep(REQUEST_DELAY_MS);
  }
}

// ─── Internal Types ───────────────────────────────────────────

interface RequestResult {
  status: number;
  bodySize: number;
  bodyText: string;
  bodyHash: string;
  serverHeader?: string;
  headers: Headers;
  durationMs: number;
}

interface BypassAttempt {
  name: string;
  url: string;
  method: string;
  headers: Record<string, string>;
}

// ─── Utility Functions ────────────────────────────────────────

/**
 * Check if an HTTP status code indicates the endpoint is accessible
 * (i.e., not protected by authentication).
 */
function isAccessible(status: number): boolean {
  return status >= 200 && status <= 299;
}

/**
 * Manipulate case of path segments.
 * e.g., /api/admin/users -> /api/Admin/users
 */
function manipulateCase(path: string): string {
  const segments = path.split('/');
  if (segments.length < 3) return path;

  // Capitalize the second-to-last meaningful segment
  for (let i = segments.length - 1; i >= 0; i--) {
    const segment = segments[i]!;
    if (segment.length > 0) {
      segments[i] = segment.charAt(0).toUpperCase() + segment.slice(1);
      break;
    }
  }

  return segments.join('/');
}

/**
 * Double-encode special path characters.
 * e.g., / -> %252f (% encoded as %25, then f)
 */
function doubleEncode(path: string): string {
  // Replace the first / after the leading / with double-encoded version
  const parts = path.split('/').filter(Boolean);
  if (parts.length < 2) return path;

  // Double-encode the path separator between first two segments
  return '/' + parts[0] + '%252f' + parts.slice(1).join('/');
}

/**
 * Inject path traversal sequence.
 * e.g., /api/admin/users -> /api/../api/admin/users
 */
function injectPathTraversal(path: string): string {
  const segments = path.split('/').filter(Boolean);
  if (segments.length < 2) return path;

  // Insert /../<first_segment> after the first segment
  const first = segments[0]!;
  return '/' + first + '/../' + segments.join('/');
}

/**
 * Sleep for the specified number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
