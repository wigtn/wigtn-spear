/**
 * SPEAR-25: Error Provocator
 *
 * Provokes error responses from the target server using 8 different techniques
 * designed to trigger verbose error handlers. Unlike code review which only
 * reads error handling code, SPEAR actually triggers the errors and inspects
 * the responses for leaked information.
 *
 * Detected leaks:
 *   - Stack traces (file paths, line numbers, frameworks)
 *   - Database connection strings
 *   - Internal IP addresses
 *   - Environment variable values
 *   - Server software versions
 *
 * @module error-provocator
 */

import type { SpearLogger } from '@wigtn/shared';
import { matchesBaseline } from './baseline-fingerprinter.js';
import type { BaselineFingerprint } from './baseline-fingerprinter.js';

// ─── Types ────────────────────────────────────────────────────

export interface ErrorProvocationResult {
  /** Provocation technique that was used */
  technique: string;
  /** URL that was probed */
  url: string;
  /** HTTP status code */
  status: number;
  /** Leaked information found in the response */
  leaks: LeakedInfo[];
}

export interface LeakedInfo {
  /** Type of leaked information */
  type: 'stack_trace' | 'file_path' | 'db_connection' | 'internal_ip' | 'env_variable' | 'server_version';
  /** The leaked value (truncated for safety) */
  value: string;
  /** Evidence snippet from the response */
  evidence: string;
}

export interface ErrorProvocationConfig {
  /** Base URL to probe */
  baseUrl: string;
  /** Specific API paths to target (uses common paths if not provided) */
  targetPaths?: string[];
  /** Baseline fingerprint for FP filtering */
  baseline?: BaselineFingerprint | null;
  /** Request timeout in ms */
  timeout?: number;
  /** Maximum requests to send (default: 15) */
  maxRequests?: number;
  /** Logger instance */
  logger?: SpearLogger;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_REQUESTS = 15;
const REQUEST_DELAY_MS = 200;

/** Common API paths to target for error provocation */
const DEFAULT_TARGET_PATHS = [
  '/api',
  '/api/v1',
  '/api/users',
  '/api/auth/login',
  '/graphql',
];

// ─── Provocation Techniques ───────────────────────────────────

interface Provocation {
  name: string;
  buildRequest: (baseUrl: string, path: string) => { url: string; method: string; headers: Record<string, string>; body?: string };
}

const PROVOCATIONS: readonly Provocation[] = [
  {
    name: 'invalid_json',
    buildRequest: (baseUrl, path) => ({
      url: `${baseUrl}${path}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"broken',
    }),
  },
  {
    name: 'sql_injection_probe',
    buildRequest: (baseUrl, path) => ({
      url: `${baseUrl}${path}?id=${encodeURIComponent("' OR 1=1 --")}`,
      method: 'GET',
      headers: {},
    }),
  },
  {
    name: 'xss_probe',
    buildRequest: (baseUrl, path) => ({
      url: `${baseUrl}${path}?q=${encodeURIComponent('<script>alert(1)</script>')}`,
      method: 'GET',
      headers: {},
    }),
  },
  {
    name: 'type_confusion',
    buildRequest: (baseUrl, path) => ({
      url: `${baseUrl}${path}?id=not_a_number&page=[]&limit={}`,
      method: 'GET',
      headers: {},
    }),
  },
  {
    name: 'oversized_header',
    buildRequest: (baseUrl, path) => ({
      url: `${baseUrl}${path}`,
      method: 'GET',
      headers: { 'X-Custom-Header': 'A'.repeat(8192) },
    }),
  },
  {
    name: 'invalid_content_type',
    buildRequest: (baseUrl, path) => ({
      url: `${baseUrl}${path}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/xml' },
      body: '<?xml version="1.0"?><root><test>1</test></root>',
    }),
  },
  {
    name: 'null_byte_path',
    buildRequest: (baseUrl, _path) => ({
      url: `${baseUrl}/api/%00/test`,
      method: 'GET',
      headers: {},
    }),
  },
  {
    name: 'empty_body_post',
    buildRequest: (baseUrl, path) => ({
      url: `${baseUrl}${path}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '',
    }),
  },
];

// ─── Leak Detection Patterns ──────────────────────────────────

interface LeakPattern {
  type: LeakedInfo['type'];
  regex: RegExp;
  extract: (match: RegExpMatchArray) => string;
}

const LEAK_PATTERNS: readonly LeakPattern[] = [
  // Stack traces
  {
    type: 'stack_trace',
    regex: /at\s+(?:[\w$.]+\s+\()?\/?(?:[\w./\\-]+\.(?:js|ts|jsx|tsx|py|rb|java|go|rs|php)):(\d+)(?::\d+)?\)?/,
    extract: (m) => m[0],
  },
  {
    type: 'stack_trace',
    regex: /(?:Error|Exception|Traceback)[:\s]+[\s\S]{0,200}(?:at\s|File\s|in\s)/,
    extract: (m) => m[0].slice(0, 200),
  },
  // File paths
  {
    type: 'file_path',
    regex: /(?:\/(?:home|var|usr|app|srv|opt|etc)\/[\w./-]{5,})|(?:[A-Z]:\\[\w.\\-]{5,})/,
    extract: (m) => m[0],
  },
  {
    type: 'file_path',
    regex: /(?:\/app\/|\/src\/|\/dist\/|\/build\/)[\w./-]+\.(?:js|ts|py|rb|go|java|php)/,
    extract: (m) => m[0],
  },
  // Database connection strings
  {
    type: 'db_connection',
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s"'<>]{5,}/,
    extract: (m) => maskDbConnection(m[0]),
  },
  // Internal IPs
  {
    type: 'internal_ip',
    regex: /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?/,
    extract: (m) => m[0],
  },
  // Environment variables leaked in error messages
  {
    type: 'env_variable',
    regex: /(?:DATABASE_URL|DB_PASSWORD|SECRET_KEY|JWT_SECRET|API_SECRET|PRIVATE_KEY|AWS_SECRET)\s*[:=]\s*["']?[^\s"']{5,}/,
    extract: (m) => m[0].slice(0, 50) + '***',
  },
  // Server version info in error pages
  {
    type: 'server_version',
    regex: /(?:Express|Django|Flask|Rails|Spring|Laravel|Next\.js|Nuxt)\s*(?:v?\d+\.\d+(?:\.\d+)?)/i,
    extract: (m) => m[0],
  },
];

// ─── Core Function ────────────────────────────────────────────

/**
 * Provoke error responses and detect information leakage.
 *
 * Sends up to `maxRequests` provocation requests using various techniques
 * designed to trigger verbose error responses. Each response is scanned
 * for leaked information (stack traces, DB strings, internal IPs, etc.).
 */
export async function provokeErrors(
  config: ErrorProvocationConfig,
): Promise<ErrorProvocationResult[]> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const maxRequests = config.maxRequests ?? DEFAULT_MAX_REQUESTS;
  const logger = config.logger;
  const targetPaths = config.targetPaths ?? DEFAULT_TARGET_PATHS;

  logger?.info('error-provocator: starting error provocation', {
    baseUrl,
    techniques: PROVOCATIONS.length,
    targetPaths: targetPaths.length,
  });

  const results: ErrorProvocationResult[] = [];
  let requestCount = 0;

  for (const provocation of PROVOCATIONS) {
    if (requestCount >= maxRequests) break;

    // Use the first target path for each technique
    const path = targetPaths[requestCount % targetPaths.length] ?? '/api';
    const req = provocation.buildRequest(baseUrl, path);

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(req.url, {
        method: req.method,
        headers: {
          'User-Agent': 'WIGTN-SPEAR/0.1.0 (Security Scanner)',
          Accept: '*/*',
          ...req.headers,
        },
        body: req.body ?? undefined,
        signal: controller.signal,
        redirect: 'manual',
      });
      clearTimeout(timer);

      const body = await response.text();
      requestCount++;

      // Filter baseline matches (FP elimination)
      if (matchesBaseline(config.baseline, response.status, body)) {
        continue;
      }

      // Scan for leaks
      const leaks = detectLeaks(body);

      if (leaks.length > 0) {
        results.push({
          technique: provocation.name,
          url: req.url,
          status: response.status,
          leaks,
        });
      }
    } catch {
      requestCount++;
      // Network errors are expected for some techniques
    }

    await sleep(REQUEST_DELAY_MS);
  }

  logger?.info('error-provocator: provocation complete', {
    requests: requestCount,
    resultsWithLeaks: results.length,
    totalLeaks: results.reduce((sum, r) => sum + r.leaks.length, 0),
  });

  return results;
}

// ─── Leak Detection ───────────────────────────────────────────

function detectLeaks(body: string): LeakedInfo[] {
  const leaks: LeakedInfo[] = [];
  const seen = new Set<string>();

  // Only scan first 100KB
  const content = body.slice(0, 102_400);

  for (const pattern of LEAK_PATTERNS) {
    // Use global regex to find ALL matches, not just the first
    const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
    for (const match of content.matchAll(globalRegex)) {
      const value = pattern.extract(match);
      const key = `${pattern.type}:${value.slice(0, 50)}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Extract evidence (surrounding context)
      const idx = match.index!;
      const evidenceStart = Math.max(0, idx - 30);
      const evidenceEnd = Math.min(content.length, idx + match[0].length + 30);
      const evidence = content.slice(evidenceStart, evidenceEnd).replace(/\n/g, ' ').slice(0, 200);

      leaks.push({
        type: pattern.type,
        value: value.slice(0, 100),
        evidence,
      });
    }
  }

  return leaks;
}

// ─── Helpers ──────────────────────────────────────────────────

function maskDbConnection(connStr: string): string {
  try {
    const url = new URL(connStr);
    if (url.password) url.password = '***';
    if (url.username) url.username = '***';
    if (url.hostname) {
      // Mask hostname partially: keep first 3 chars + ***
      url.hostname = url.hostname.length > 3
        ? url.hostname.slice(0, 3) + '***'
        : '***';
    }
    return url.toString().slice(0, 80);
  } catch {
    // Fallback: regex-based masking for non-standard connection strings
    return connStr
      .replace(/:([^@/]+)@/, ':***@')
      .replace(/@([^:/]+)/, '@***')
      .slice(0, 80);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
