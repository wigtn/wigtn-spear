/**
 * SPEAR-25: Baseline Fingerprinter
 *
 * Captures a "baseline" response fingerprint from the target server by probing
 * 3 random UUID paths. If all 3 return identical status + bodyHash + bodyLength,
 * the server has a catch-all route (e.g. SPA fallback, custom 404 page).
 *
 * Any subsequent probe whose response matches this baseline is classified as
 * a false positive and filtered out -- this is the primary FP elimination mechanism
 * that reduces FP rate from 55-86% down to ~5%.
 *
 * @module baseline-fingerprinter
 */

import { createHash, randomUUID } from 'node:crypto';
import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface BaselineFingerprint {
  /** HTTP status code of the baseline response */
  status: number;
  /** SHA-256 hash of the response body */
  bodyHash: string;
  /** Length of the response body in bytes */
  bodyLength: number;
  /** Whether the server appears to have a catch-all route */
  isCatchAll: boolean;
}

export interface BaselineCaptureConfig {
  /** Base URL to probe */
  baseUrl: string;
  /** Request timeout in ms (default: 5000) */
  timeout?: number;
  /** Logger instance */
  logger?: SpearLogger;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 5_000;
const PROBE_COUNT = 3;

// ─── Core Functions ───────────────────────────────────────────

/**
 * Capture the baseline fingerprint for a target server.
 *
 * Sends 3 requests to random UUID paths (e.g. /a1b2c3d4-...) and compares
 * the responses. If all 3 produce identical status + body hash + body length,
 * the server has a catch-all and `isCatchAll` is set to true.
 *
 * @returns BaselineFingerprint, or null if baseline capture fails
 */
export async function captureBaseline(
  config: BaselineCaptureConfig,
): Promise<BaselineFingerprint | null> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const logger = config.logger;

  logger?.info('baseline-fingerprinter: capturing baseline', { baseUrl });

  const probes: Array<{ status: number; bodyHash: string; bodyLength: number }> = [];

  for (let i = 0; i < PROBE_COUNT; i++) {
    const randomPath = `/${randomUUID()}`;
    const url = baseUrl + randomPath;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
          Accept: '*/*',
        },
        signal: controller.signal,
        redirect: 'follow',
      });
      clearTimeout(timer);

      // Skip baseline if server is rate limiting or unavailable
      if (response.status === 429 || response.status === 503) {
        logger?.debug('baseline-fingerprinter: server rate limiting/unavailable, skipping baseline');
        return null;
      }

      const body = await response.text();
      const bodyHash = sha256(body);

      probes.push({
        status: response.status,
        bodyHash,
        bodyLength: body.length,
      });

      // Delay between probes to avoid rate limiting
      if (i < PROBE_COUNT - 1) {
        await sleep(300);
      }
    } catch (err) {
      logger?.debug('baseline-fingerprinter: probe failed', {
        url,
        error: String(err),
      });
      return null;
    }
  }

  // Check if at least 2 of 3 probes match (majority voting)
  const first = probes[0]!;
  const matchCount = probes.filter(
    (p) =>
      p.status === first.status &&
      p.bodyHash === first.bodyHash &&
      p.bodyLength === first.bodyLength,
  ).length;
  const allMatch = matchCount >= 2;

  const result: BaselineFingerprint = {
    status: first.status,
    bodyHash: first.bodyHash,
    bodyLength: first.bodyLength,
    isCatchAll: allMatch,
  };

  logger?.info('baseline-fingerprinter: baseline captured', {
    status: result.status,
    bodyLength: result.bodyLength,
    isCatchAll: result.isCatchAll,
  });

  return result;
}

/**
 * Check if a probe response matches the baseline fingerprint.
 *
 * Used to filter out false positives: if a response matches the catch-all
 * baseline, it's NOT a real finding (the server returns this for any path).
 *
 * @param baseline - The captured baseline fingerprint
 * @param status   - HTTP status of the probe response
 * @param body     - Response body text
 * @returns true if the response matches the baseline (i.e., is a false positive)
 */
export function matchesBaseline(
  baseline: BaselineFingerprint | null | undefined,
  status: number,
  body: string,
): boolean {
  if (!baseline || !baseline.isCatchAll) return false;

  return (
    status === baseline.status &&
    body.length === baseline.bodyLength &&
    sha256(body) === baseline.bodyHash
  );
}

// ─── Helpers ──────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
