/**
 * SPEAR-25: Cloud Service Discovery Module
 *
 * Given a known Cloud Run / Cloud Functions URL, enumerates sibling services
 * by brute-forcing service name patterns while reusing the project hash.
 *
 * Cloud Run URL anatomy:
 *   {service}-{project_hash}-{region}.a.run.app
 *   Example: wigvo-web-gzjzn35jyq-du.a.run.app
 *     → service = "wigvo-web"
 *     → hash    = "gzjzn35jyq"
 *     → region  = "du"
 *
 * Discovery strategy:
 *   1. Parse the known URL to extract hash and region
 *   2. Generate candidate service names from:
 *      a) Common service name patterns (api, relay, admin, backend, etc.)
 *      b) Prefix/suffix permutations of the known service name
 *   3. Probe each candidate with a HEAD request
 *   4. Return all responding services with metadata
 *
 * This automates what was previously done manually with curl.
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface CloudServiceResult {
  /** Full URL of the discovered service */
  url: string;
  /** Service name component */
  serviceName: string;
  /** HTTP status code from probe */
  status: number;
  /** Response server header (e.g., "Google Frontend") */
  serverHeader?: string;
  /** Response latency in ms */
  latencyMs: number;
  /** Whether the service appears to be a real running service (not 404) */
  alive: boolean;
}

export interface CloudDiscoveryConfig {
  /** Known URL to derive project hash from */
  knownUrl: string;
  /** Maximum number of probes to send */
  maxProbes?: number;
  /** Timeout per probe in ms (default: 5000) */
  timeout?: number;
  /** Logger instance */
  logger?: SpearLogger;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_PROBES = 100;
const PROBE_DELAY_MS = 100;

/**
 * Common service name patterns for Cloud Run / Cloud Functions.
 * These are checked as-is and also combined with the base project name.
 */
const COMMON_SERVICE_SUFFIXES: readonly string[] = [
  'api',
  'relay',
  'backend',
  'server',
  'admin',
  'auth',
  'gateway',
  'proxy',
  'worker',
  'cron',
  'scheduler',
  'webhook',
  'ws',
  'websocket',
  'realtime',
  'stream',
  'events',
  'notifications',
  'push',
  'media',
  'upload',
  'cdn',
  'assets',
  'static',
  'docs',
  'staging',
  'dev',
  'test',
  'preview',
  'canary',
  'internal',
  'metrics',
  'monitor',
  'health',
  'status',
  'graphql',
  'grpc',
  'rpc',
];

/**
 * Cloud Run URL pattern.
 * Matches: {service}-{hash}-{region}.a.run.app
 */
const CLOUD_RUN_PATTERN =
  /^https?:\/\/(.+)-([a-z0-9]{10,})-([a-z]{2})\.a\.run\.app/;

// ─── URL Parser ───────────────────────────────────────────────

interface ParsedCloudRunUrl {
  serviceName: string;
  projectHash: string;
  region: string;
  protocol: string;
}

/**
 * Parse a Cloud Run URL into its components.
 * Returns null if the URL doesn't match the Cloud Run pattern.
 */
export function parseCloudRunUrl(url: string): ParsedCloudRunUrl | null {
  const match = url.match(CLOUD_RUN_PATTERN);
  if (!match) return null;

  return {
    serviceName: match[1]!,
    projectHash: match[2]!,
    region: match[3]!,
    protocol: url.startsWith('https') ? 'https' : 'http',
  };
}

// ─── Candidate Generator ──────────────────────────────────────

/**
 * Generate candidate service names based on the known service name.
 *
 * Strategy:
 *   1. Split known name into parts (e.g., "wigvo-web" → ["wigvo", "web"])
 *   2. Use the base prefix (e.g., "wigvo") to generate permutations
 *   3. Add common standalone service names
 */
function generateCandidates(knownService: string): string[] {
  const candidates = new Set<string>();
  const parts = knownService.split('-');
  const basePrefix = parts[0]!; // e.g., "wigvo"

  // Prefix + common suffix: wigvo-relay, wigvo-api, wigvo-backend, ...
  for (const suffix of COMMON_SERVICE_SUFFIXES) {
    candidates.add(`${basePrefix}-${suffix}`);
  }

  // If original has 2+ parts, try replacing last part
  if (parts.length >= 2) {
    const prefix = parts.slice(0, -1).join('-'); // e.g., "wigvo"
    for (const suffix of COMMON_SERVICE_SUFFIXES) {
      candidates.add(`${prefix}-${suffix}`);
    }
  }

  // Standalone common names
  for (const name of COMMON_SERVICE_SUFFIXES) {
    candidates.add(name);
  }

  // Remove the known service name itself
  candidates.delete(knownService);

  return Array.from(candidates);
}

/**
 * Build a Cloud Run URL from components.
 */
function buildCloudRunUrl(
  protocol: string,
  serviceName: string,
  projectHash: string,
  region: string,
): string {
  return `${protocol}://${serviceName}-${projectHash}-${region}.a.run.app`;
}

// ─── Discovery Engine ─────────────────────────────────────────

/**
 * Discover sibling Cloud Run services by probing candidate URLs.
 *
 * Given a known Cloud Run URL, extracts the project hash and region,
 * generates candidate service names, and probes each one.
 *
 * Returns only alive services (status != 404 and not connection refused).
 */
export async function discoverCloudServices(
  config: CloudDiscoveryConfig,
): Promise<CloudServiceResult[]> {
  const parsed = parseCloudRunUrl(config.knownUrl);
  if (!parsed) {
    config.logger?.warn('cloud-discovery: URL does not match Cloud Run pattern', {
      url: config.knownUrl,
    });
    return [];
  }

  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const maxProbes = config.maxProbes ?? DEFAULT_MAX_PROBES;

  const candidates = generateCandidates(parsed.serviceName);
  const probeCandidates = candidates.slice(0, maxProbes);

  config.logger?.info('cloud-discovery: starting service enumeration', {
    knownService: parsed.serviceName,
    projectHash: parsed.projectHash,
    region: parsed.region,
    candidates: probeCandidates.length,
  });

  const results: CloudServiceResult[] = [];
  let probed = 0;

  for (const candidate of probeCandidates) {
    const url = buildCloudRunUrl(
      parsed.protocol,
      candidate,
      parsed.projectHash,
      parsed.region,
    );

    const result = await probeService(url, candidate, timeout);
    probed++;

    if (result.alive) {
      results.push(result);
      config.logger?.info('cloud-discovery: service found!', {
        serviceName: candidate,
        url,
        status: result.status,
        latencyMs: result.latencyMs,
      });
    }

    // Rate limiting
    if (probed < probeCandidates.length) {
      await sleep(PROBE_DELAY_MS);
    }
  }

  config.logger?.info('cloud-discovery: enumeration complete', {
    probed,
    found: results.length,
  });

  return results;
}

// ─── Service Probe ────────────────────────────────────────────

/**
 * Probe a single service URL to check if it's alive.
 *
 * A service is considered "alive" if:
 *   - It responds with any status other than connection refused
 *   - It doesn't return a generic cloud provider 404 page
 *
 * Uses HEAD first (cheaper), falls back to GET if needed.
 */
async function probeService(
  url: string,
  serviceName: string,
  timeout: number,
): Promise<CloudServiceResult> {
  const start = performance.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'HEAD',
      headers: {
        'User-Agent': 'WIGTN-SPEAR/0.1.0 (Security Scanner)',
      },
      signal: controller.signal,
      redirect: 'manual',
    });

    clearTimeout(timer);
    const latencyMs = Math.round(performance.now() - start);

    // Cloud Run returns 404 for non-existent services.
    // A real service can return anything EXCEPT the default 404.
    const alive = response.status !== 404;

    return {
      url,
      serviceName,
      status: response.status,
      serverHeader: response.headers.get('server') ?? undefined,
      latencyMs,
      alive,
    };
  } catch {
    return {
      url,
      serviceName,
      status: 0,
      latencyMs: Math.round(performance.now() - start),
      alive: false,
    };
  }
}

// ─── Utilities ────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
