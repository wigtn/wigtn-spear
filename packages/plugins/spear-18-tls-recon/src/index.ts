/**
 * SPEAR-18: TLS Recon Plugin
 *
 * Performs TLS/certificate reconnaissance against discovered endpoints.
 *
 * Operation modes:
 *   SAFE mode:       Scans source code for HTTPS/WSS endpoints (no network)
 *   AGGRESSIVE mode: Connects to discovered endpoints and analyzes TLS configuration
 *
 * Extracts:
 *   - Certificate subject/issuer, expiration, serial, fingerprint
 *   - TLS protocol version (warns if < TLS 1.2)
 *   - Cipher suite (warns if weak)
 *   - Certificate chain depth
 *   - Subject Alternative Names (SAN)
 *   - HSTS header presence
 *   - Certificate Transparency SCTs
 *
 * MITRE ATT&CK Techniques:
 *   - T1590.001  Gather Victim Network Information: Domain Properties
 *   - T1590.003  Gather Victim Network Information: Network Trust Dependencies
 *   - T1596.003  Search Open Technical Databases: Digital Certificates
 *   - T1595.002  Active Scanning: Vulnerability Scanning
 */

import { resolve } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
} from '@wigtn/shared';

import { extractEndpoints, getUniqueOrigins } from './url-extractor.js';
import { analyzeTls, generateTlsFindings } from './tls-analyzer.js';

// ─── Plugin Implementation ─────────────────────────────────────

/**
 * TlsReconPlugin -- SPEAR-18 Reconnaissance Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Discovers HTTPS endpoints in source code and analyzes their TLS configuration.
 */
export class TlsReconPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'tls-recon',
    name: 'TLS Certificate Reconnaissance',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Discovers HTTPS endpoints in source code and analyzes TLS configuration ' +
      'including certificate validity, protocol version, cipher suites, HSTS, ' +
      'and Certificate Transparency.',
    severity: 'medium',
    tags: [
      'tls', 'ssl', 'certificate', 'recon', 'https',
      'hsts', 'cipher', 'expiry', 'transparency',
    ],
    references: [
      'CWE-295', 'CWE-319', 'CWE-327',
      'OWASP-A02', 'OWASP-A07',
    ],
    safeMode: true,
    requiresNetwork: false,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read', 'net:outbound'],
    trustLevel: 'builtin',
  };

  /**
   * Setup: Log initialization.
   */
  async setup(context: PluginContext): Promise<void> {
    context.logger.info('TLS Recon plugin initialized', {
      mode: context.mode,
    });
  }

  /**
   * Scan: Extract URLs in safe mode, analyze TLS in aggressive mode.
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);
    const exclude = target.exclude ?? [];

    // ── Phase 1: Safe Mode -- Extract endpoints from source code ──

    context.logger.info('Extracting HTTPS endpoints from source code', { rootDir });

    const endpoints = await extractEndpoints(rootDir, exclude);
    const origins = getUniqueOrigins(endpoints);

    context.logger.info('Endpoint extraction complete', {
      totalEndpoints: endpoints.length,
      uniqueOrigins: origins.length,
    });

    // Yield discovery findings for each endpoint
    for (const ep of endpoints) {
      yield {
        ruleId: 'spear-18/endpoint-discovered',
        severity: 'info',
        message: `HTTPS endpoint: ${ep.url}`,
        file: ep.file,
        line: ep.line,
        metadata: {
          pluginId: this.metadata.id,
          endpoint: ep.url,
          source: ep.source,
        },
      };
    }

    // ── Phase 2: Aggressive Mode -- TLS Analysis ─────────────────

    if (context.mode !== 'aggressive') {
      context.logger.info('Safe mode: skipping TLS connection analysis');
      return;
    }

    if (origins.length === 0) {
      context.logger.info('No endpoints discovered, skipping TLS analysis');
      return;
    }

    context.logger.info('Aggressive mode: analyzing TLS on discovered endpoints', {
      endpointCount: origins.length,
    });

    let analyzed = 0;
    let failed = 0;

    for (const origin of origins) {
      context.logger.debug('Analyzing TLS', { endpoint: origin });

      try {
        const result = await analyzeTls(origin);
        const findings = generateTlsFindings(result);

        for (const finding of findings) {
          yield finding;
        }

        if (result.connected) {
          analyzed++;
        } else {
          failed++;
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        context.logger.warn('TLS analysis failed for endpoint', {
          endpoint: origin,
          error: message,
        });

        yield {
          ruleId: 'spear-18/tls-analysis-error',
          severity: 'info',
          message: `TLS analysis error for ${origin}: ${message}`,
          metadata: {
            pluginId: this.metadata.id,
            endpoint: origin,
            error: message,
          },
        };

        failed++;
      }
    }

    context.logger.info('TLS analysis complete', {
      analyzed,
      failed,
      total: origins.length,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // No state to clean up.
  }
}

// ─── Default Export ────────────────────────────────────────────

export default new TlsReconPlugin();
