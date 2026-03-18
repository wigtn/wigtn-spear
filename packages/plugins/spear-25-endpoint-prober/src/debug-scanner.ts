/**
 * SPEAR-25: Debug & Logging Endpoint Scanner
 *
 * Covers OWASP A09 - Security Logging and Monitoring Failures
 *
 * Scans for exposed debug, logging, monitoring, and profiling endpoints
 * that should never be accessible in production:
 *
 *   - Debug endpoints: /debug, /_debug, /trace
 *   - Monitoring: /actuator (Spring Boot), /metrics, /health (detailed)
 *   - Logging: /logs, /console, /admin/logs
 *   - Profiling: /debug/pprof (Go), /_profiler (Symfony)
 *   - Error leakage: stack traces in error responses
 *   - Introspection: GraphQL introspection, API schema exposure
 *   - Environment: .env files, config dumps
 *   - Source maps: .js.map files that expose source code
 *
 * These are common in development but catastrophic in production —
 * they leak internal architecture, secrets, and attack surface.
 */

import type { SpearLogger } from '@wigtn/shared';
import { matchesBaseline } from './baseline-fingerprinter.js';
import type { BaselineFingerprint } from './baseline-fingerprinter.js';

// ─── Types ────────────────────────────────────────────────────

export interface DebugScanResult {
  /** All discovered debug/logging endpoints */
  endpoints: DiscoveredDebugEndpoint[];
  /** Whether error responses leak stack traces */
  stackTraceLeaked: boolean;
  /** Stack trace evidence (if found) */
  stackTraceEvidence?: string;
  /** Total endpoints probed */
  totalProbed: number;
}

export interface DiscoveredDebugEndpoint {
  url: string;
  status: number;
  category: DebugCategory;
  service: string;
  exposure: string;
  latencyMs: number;
  evidence: string;
}

export type DebugCategory =
  | 'debug'
  | 'monitoring'
  | 'logging'
  | 'profiling'
  | 'environment'
  | 'sourcemap'
  | 'introspection'
  | 'admin';

export interface DebugScanConfig {
  baseUrl: string;
  timeout?: number;
  logger?: SpearLogger;
  /** Baseline fingerprint for FP elimination (catch-all filter) */
  baseline?: BaselineFingerprint | null;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 5_000;
const PROBE_DELAY_MS = 80;
const MAX_EVIDENCE_LENGTH = 500;

// ─── Endpoint Definitions ─────────────────────────────────────

interface DebugProbeTarget {
  path: string;
  category: DebugCategory;
  service: string;
  exposure: string;
  confirmPattern?: string;
}

const DEBUG_ENDPOINTS: readonly DebugProbeTarget[] = [
  // ── Debug ───────────────────────────────────────────────
  { path: '/debug', category: 'debug', service: 'generic', exposure: 'Debug endpoint exposed' },
  { path: '/_debug', category: 'debug', service: 'django', exposure: 'Django debug endpoint' },
  { path: '/debug/vars', category: 'debug', service: 'go', exposure: 'Go expvar debug variables exposed' },
  { path: '/debug/requests', category: 'debug', service: 'go', exposure: 'Go debug request tracing exposed' },
  { path: '/__debug__', category: 'debug', service: 'flask', exposure: 'Flask debug mode active' },
  { path: '/trace', category: 'debug', service: 'generic', exposure: 'HTTP TRACE/debug tracing active' },
  { path: '/_error', category: 'debug', service: 'nextjs', exposure: 'Next.js error debug page' },

  // ── Monitoring (Spring Boot Actuator) ───────────────────
  { path: '/actuator', category: 'monitoring', service: 'spring-boot', exposure: 'Spring Boot Actuator — full server internals', confirmPattern: '_links' },
  { path: '/actuator/env', category: 'monitoring', service: 'spring-boot', exposure: 'Spring Boot env — environment variables and secrets' },
  { path: '/actuator/configprops', category: 'monitoring', service: 'spring-boot', exposure: 'Spring Boot config — all configuration properties' },
  { path: '/actuator/beans', category: 'monitoring', service: 'spring-boot', exposure: 'Spring Boot beans — all registered Spring beans' },
  { path: '/actuator/mappings', category: 'monitoring', service: 'spring-boot', exposure: 'Spring Boot mappings — all URL routes and handlers' },
  { path: '/actuator/heapdump', category: 'monitoring', service: 'spring-boot', exposure: 'Spring Boot heapdump — JVM memory dump with secrets' },
  { path: '/actuator/threaddump', category: 'monitoring', service: 'spring-boot', exposure: 'Spring Boot threaddump — thread state exposed' },

  // ── Monitoring (Generic) ────────────────────────────────
  { path: '/metrics', category: 'monitoring', service: 'prometheus', exposure: 'Prometheus metrics — internal performance data' },
  { path: '/metrics/prometheus', category: 'monitoring', service: 'prometheus', exposure: 'Prometheus metrics endpoint' },
  { path: '/_status', category: 'monitoring', service: 'generic', exposure: 'Status endpoint with detailed server info' },
  { path: '/server-status', category: 'monitoring', service: 'apache', exposure: 'Apache server-status — request details and uptime' },
  { path: '/nginx_status', category: 'monitoring', service: 'nginx', exposure: 'Nginx stub status — connection metrics' },
  { path: '/server-info', category: 'monitoring', service: 'apache', exposure: 'Apache server-info — full module configuration' },

  // ── Logging ─────────────────────────────────────────────
  { path: '/logs', category: 'logging', service: 'generic', exposure: 'Application logs exposed' },
  { path: '/log', category: 'logging', service: 'generic', exposure: 'Log endpoint exposed' },
  { path: '/console', category: 'logging', service: 'h2-console', exposure: 'H2 database console — SQL execution possible' },
  { path: '/admin/logs', category: 'logging', service: 'generic', exposure: 'Admin log viewer — application logs exposed' },
  { path: '/elmah.axd', category: 'logging', service: 'aspnet', exposure: 'ELMAH error log — .NET error details and stack traces' },

  // ── Profiling ───────────────────────────────────────────
  { path: '/debug/pprof/', category: 'profiling', service: 'go', exposure: 'Go pprof profiling — CPU/memory profiles exposed', confirmPattern: 'profile' },
  { path: '/debug/pprof/heap', category: 'profiling', service: 'go', exposure: 'Go heap profile — memory allocation details' },
  { path: '/debug/pprof/goroutine', category: 'profiling', service: 'go', exposure: 'Go goroutine profile — concurrency state exposed' },
  { path: '/_profiler', category: 'profiling', service: 'symfony', exposure: 'Symfony profiler — request/response debug info' },
  { path: '/__clockwork', category: 'profiling', service: 'laravel', exposure: 'Laravel Clockwork — request profiling data' },

  // ── Environment / Config ────────────────────────────────
  { path: '/.env', category: 'environment', service: 'generic', exposure: '.env file — secrets, API keys, database credentials', confirmPattern: '=' },
  { path: '/.env.local', category: 'environment', service: 'generic', exposure: '.env.local — local environment secrets' },
  { path: '/.env.production', category: 'environment', service: 'generic', exposure: '.env.production — production secrets' },
  { path: '/config', category: 'environment', service: 'generic', exposure: 'Configuration endpoint — server config exposed' },
  { path: '/config.json', category: 'environment', service: 'generic', exposure: 'Config JSON — application configuration' },
  { path: '/info', category: 'environment', service: 'spring-boot', exposure: 'Spring Boot info — build and git details' },
  { path: '/phpinfo.php', category: 'environment', service: 'php', exposure: 'PHP info — full PHP configuration and extensions' },
  { path: '/wp-config.php.bak', category: 'environment', service: 'wordpress', exposure: 'WordPress config backup — database credentials' },

  // ── Source Maps ─────────────────────────────────────────
  { path: '/main.js.map', category: 'sourcemap', service: 'generic', exposure: 'JavaScript source map — original source code exposed' },
  { path: '/static/js/main.js.map', category: 'sourcemap', service: 'react', exposure: 'React source map — full frontend source code' },
  { path: '/_next/static/chunks/main.js.map', category: 'sourcemap', service: 'nextjs', exposure: 'Next.js source map — frontend source code' },
  { path: '/assets/index.js.map', category: 'sourcemap', service: 'vite', exposure: 'Vite source map — frontend source code' },

  // ── Introspection ───────────────────────────────────────
  { path: '/graphql', category: 'introspection', service: 'graphql', exposure: 'GraphQL endpoint — may allow introspection query' },

  // ── Admin ───────────────────────────────────────────────
  { path: '/admin', category: 'admin', service: 'generic', exposure: 'Admin panel accessible' },
  { path: '/admin/', category: 'admin', service: 'generic', exposure: 'Admin panel directory listing' },
  { path: '/adminer', category: 'admin', service: 'adminer', exposure: 'Adminer database management — direct DB access' },
  { path: '/phpmyadmin', category: 'admin', service: 'phpmyadmin', exposure: 'phpMyAdmin — MySQL database management' },
  { path: '/_admin', category: 'admin', service: 'generic', exposure: 'Hidden admin endpoint' },
  { path: '/dashboard', category: 'admin', service: 'generic', exposure: 'Dashboard endpoint accessible without auth' },
];

// ─── Scanner ──────────────────────────────────────────────────

/**
 * Scan for exposed debug, logging, monitoring, and profiling endpoints.
 */
export async function scanDebugEndpoints(
  config: DebugScanConfig,
): Promise<DebugScanResult> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const logger = config.logger;

  logger?.info('debug-scanner: starting scan', { baseUrl });

  const endpoints: DiscoveredDebugEndpoint[] = [];
  let totalProbed = 0;

  const baseline = config.baseline;

  for (const target of DEBUG_ENDPOINTS) {
    const url = baseUrl + target.path;
    const result = await probeDebugEndpoint(url, target, timeout, baseline);
    totalProbed++;

    if (result) {
      endpoints.push(result);
      logger?.info('debug-scanner: endpoint found', {
        category: result.category,
        service: result.service,
        url: result.url,
        status: result.status,
      });
    }

    await sleep(PROBE_DELAY_MS);
  }

  // Check for stack trace leakage in error responses
  const stackTraceCheck = await checkStackTraceLeakage(baseUrl, timeout);

  logger?.info('debug-scanner: scan complete', {
    totalProbed,
    found: endpoints.length,
    stackTraceLeaked: stackTraceCheck.leaked,
  });

  return {
    endpoints,
    stackTraceLeaked: stackTraceCheck.leaked,
    stackTraceEvidence: stackTraceCheck.evidence,
    totalProbed,
  };
}

// ─── Probes ───────────────────────────────────────────────────

async function probeDebugEndpoint(
  url: string,
  target: DebugProbeTarget,
  timeout: number,
  baseline?: BaselineFingerprint | null,
): Promise<DiscoveredDebugEndpoint | null> {
  const start = performance.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'WIGTN-SPEAR/0.1.0 (Security Scanner)',
        Accept: 'text/html, application/json, */*',
      },
      signal: controller.signal,
      redirect: 'manual',
    });

    clearTimeout(timer);
    const latencyMs = Math.round(performance.now() - start);

    let bodyText = '';
    try {
      bodyText = await response.text();
      if (bodyText.length > 10_000) bodyText = bodyText.slice(0, 10_000);
    } catch { /* ignore */ }

    // Skip 404s and redirects to login
    if (response.status === 404) return null;
    if (response.status >= 300 && response.status < 400) return null;

    // Baseline FP filter: if response matches the catch-all baseline, skip
    if (matchesBaseline(baseline, response.status, bodyText)) return null;

    // Confirm pattern if specified
    if (target.confirmPattern && !bodyText.includes(target.confirmPattern)) {
      if (response.status !== 200) return null;
    }

    // For .env files, verify it looks like an env file (contains KEY=VALUE)
    if (target.path.includes('.env') && !/^[A-Z_]+=.+/m.test(bodyText)) {
      return null;
    }

    // GraphQL introspection check
    if (target.service === 'graphql' && response.status === 200) {
      const introspectionAllowed = await checkGraphqlIntrospection(url, timeout);
      if (!introspectionAllowed) return null;
    }

    return {
      url,
      status: response.status,
      category: target.category,
      service: target.service,
      exposure: target.exposure,
      latencyMs,
      evidence: bodyText.slice(0, MAX_EVIDENCE_LENGTH),
    };
  } catch {
    return null;
  }
}

/**
 * Check if GraphQL endpoint allows introspection.
 */
async function checkGraphqlIntrospection(
  url: string,
  timeout: number,
): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'WIGTN-SPEAR/0.1.0',
      },
      body: JSON.stringify({
        query: '{ __schema { types { name } } }',
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);
    const body = await response.text();

    return body.includes('__schema') || body.includes('types');
  } catch {
    return false;
  }
}

/**
 * Check if error responses leak stack traces.
 * Sends a request designed to trigger an error and examines the response.
 */
async function checkStackTraceLeakage(
  baseUrl: string,
  timeout: number,
): Promise<{ leaked: boolean; evidence?: string }> {
  // Request paths designed to trigger errors
  const errorPaths = [
    '/api/%00',                    // Null byte
    '/api/undefined/undefined',    // Missing resource
    '/api/' + 'A'.repeat(500),     // Long path
    '/' + '../'.repeat(20),        // Path traversal
  ];

  for (const path of errorPaths) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(baseUrl + path, {
        method: 'GET',
        headers: { 'User-Agent': 'WIGTN-SPEAR/0.1.0' },
        signal: controller.signal,
        redirect: 'manual',
      });

      clearTimeout(timer);

      let body = '';
      try {
        body = await response.text();
        if (body.length > 10_000) body = body.slice(0, 10_000);
      } catch { continue; }

      // Check for stack trace patterns
      const stackTracePatterns = [
        /at\s+\S+\s+\(.*:\d+:\d+\)/,         // Node.js: at Function (file:line:col)
        /Traceback \(most recent call last\)/,  // Python
        /at\s+[\w.$]+\([\w.]+\.java:\d+\)/,    // Java
        /\.go:\d+\s/,                            // Go
        /Stack trace:/i,                          // Generic
        /Exception in thread/,                    // Java thread
        /File ".*", line \d+/,                    // Python file reference
        /vendor\/.*\.php:\d+/,                   // PHP
      ];

      for (const pattern of stackTracePatterns) {
        if (pattern.test(body)) {
          return {
            leaked: true,
            evidence: body.slice(0, MAX_EVIDENCE_LENGTH),
          };
        }
      }

      await sleep(PROBE_DELAY_MS);
    } catch {
      continue;
    }
  }

  return { leaked: false };
}

// ─── Helpers ──────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
