/**
 * SPEAR-25: Endpoint Auth Prober Plugin
 *
 * Probes API endpoints to verify authentication enforcement and discover
 * auth bypasses. This plugin operates in two modes:
 *
 * Safe mode (no liveAttack):
 *   - Discovers endpoints from source code via static analysis
 *   - Yields findings for endpoints that appear to have NO auth decorators/middleware
 *   - Useful even without live probing as a static analysis check
 *
 * Aggressive mode WITH liveAttack:
 *   - Discovers endpoints from source code (if target.path exists)
 *   - Or uses liveAttack.endpoints if provided
 *   - Probes each endpoint live with HTTP requests
 *   - Yields findings with ACTUAL PROOF of authentication failures
 *
 * This is the plugin that would have PROVEN the WIGVO /relay/calls/start
 * vulnerability -- instead of just pattern-matching "no auth decorator found",
 * it actually sends a request and checks if it goes through.
 *
 * Probing techniques:
 *   1. No Auth          -- Request with no credentials
 *   2. Invalid Token    -- Request with invalid Bearer token
 *   3. Expired Token    -- Request with expired JWT format
 *   4. Auth Bypasses    -- 10 techniques (case, encoding, traversal, etc.)
 *   5. CORS Check       -- OPTIONS with evil origin
 *   6. Rate Limit       -- 10 rapid requests
 *
 * MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
 * CWE: CWE-306 (Missing Authentication for Critical Function)
 * OWASP: API2 (Broken Authentication)
 */

import { resolve } from 'node:path';
import type {
  SpearPlugin,
  Finding,
  ScanTarget,
  PluginContext,
  PluginMetadata,
  LiveEndpoint,
  Severity,
} from '@wigtn/shared';

import { discoverEndpoints } from './endpoint-discovery.js';
import type { DiscoveredEndpoint } from './endpoint-discovery.js';
import { ProbeEngine } from './probe-engine.js';
import type { ProbeResult, EndpointInfo, AuthBypassResult } from './probe-engine.js';
import { discoverCloudServices, parseCloudRunUrl } from './cloud-service-discovery.js';
import type { CloudServiceResult } from './cloud-service-discovery.js';
import { scanOpenApi } from './openapi-scanner.js';
import type { OpenApiScanResult, DangerousParam } from './openapi-scanner.js';

// ─── Plugin Implementation ────────────────────────────────────

/**
 * EndpointProberPlugin -- SPEAR-25 Attack Module
 *
 * Implements the SpearPlugin interface from @wigtn/shared.
 * Probes API endpoints to verify authentication enforcement
 * and discover auth bypasses through live HTTP requests.
 */
export class EndpointProberPlugin implements SpearPlugin {
  metadata: PluginMetadata = {
    id: 'endpoint-prober',
    name: 'Endpoint Auth Prober',
    version: '0.1.0',
    author: 'WIGTN Team',
    description:
      'Probes API endpoints to verify authentication enforcement and discover auth bypasses',
    severity: 'critical',
    tags: ['auth', 'endpoint', 'live-attack', 'api-security'],
    references: ['OWASP-API2', 'CWE-306'],
    safeMode: false,
    requiresNetwork: true,
    supportedPlatforms: ['darwin', 'linux', 'win32'],
    permissions: ['fs:read', 'net:outbound'],
    trustLevel: 'builtin',
  };

  /**
   * Setup: Log initialization.
   */
  async setup(context: PluginContext): Promise<void> {
    context.logger.info('Endpoint Auth Prober initialized', {
      mode: context.mode,
      hasLiveAttack: !!context.liveAttack,
      targetUrl: context.liveAttack?.targetUrl ?? 'none',
    });
  }

  /**
   * Scan: Discover endpoints and probe them for authentication issues.
   *
   * In safe mode:
   *   - Discover endpoints from source code
   *   - Yield findings for endpoints with no detected auth (static analysis)
   *
   * In aggressive mode with liveAttack:
   *   - Discover endpoints from source (or use provided endpoints)
   *   - Probe each endpoint with live HTTP requests
   *   - Yield findings with actual proof of auth failures
   */
  async *scan(target: ScanTarget, context: PluginContext): AsyncGenerator<Finding> {
    const rootDir = resolve(target.path);

    // ── Phase 1: Endpoint Discovery ───────────────────────────

    context.logger.info('Starting endpoint discovery', { rootDir });

    const discoveredEndpoints = await discoverEndpoints(rootDir, target.exclude);

    context.logger.info('Endpoint discovery complete', {
      discovered: discoveredEndpoints.length,
    });

    // ── Phase 2: Static Analysis Findings (Safe Mode) ─────────

    // Always emit static analysis findings for endpoints with no auth
    let staticFindingsCount = 0;

    for (const endpoint of discoveredEndpoints) {
      if (!endpoint.hasAuth) {
        staticFindingsCount++;
        yield createStaticNoAuthFinding(endpoint);
      }
    }

    if (staticFindingsCount > 0) {
      context.logger.info('Static analysis findings emitted', {
        noAuthEndpoints: staticFindingsCount,
        totalEndpoints: discoveredEndpoints.length,
      });
    }

    // ── Phase 3: Live Probing (Aggressive Mode) ───────────────

    if (context.mode !== 'aggressive' || !context.liveAttack) {
      context.logger.info('Live probing skipped (requires aggressive mode + liveAttack config)', {
        mode: context.mode,
        hasLiveAttack: !!context.liveAttack,
      });
      return;
    }

    context.logger.info('Starting live endpoint probing', {
      targetUrl: context.liveAttack.targetUrl,
    });

    // Track endpoints to avoid duplicates between source/config/openapi
    const endpointsToProbeKeys = new Set<string>();
    const additionalEndpoints: EndpointInfo[] = [];

    // ── Phase 3a: Cloud Service Discovery ─────────────────────

    const parsedCloudUrl = parseCloudRunUrl(context.liveAttack.targetUrl);
    if (parsedCloudUrl) {
      context.logger.info('Cloud Run URL detected, starting service enumeration', {
        service: parsedCloudUrl.serviceName,
        hash: parsedCloudUrl.projectHash,
        region: parsedCloudUrl.region,
      });

      const cloudServices = await discoverCloudServices({
        knownUrl: context.liveAttack.targetUrl,
        maxProbes: 80,
        timeout: context.liveAttack.timeout ?? 5000,
        logger: context.logger,
      });

      for (const svc of cloudServices) {
        yield {
          ruleId: 'spear-25/cloud-service-discovered',
          severity: 'high',
          message:
            `Cloud Run sibling service discovered: ${svc.serviceName} at ${svc.url} ` +
            `(status ${svc.status}, ${svc.latencyMs}ms)`,
          cvss: 7.5,
          mitreTechniques: ['T1595'],
          remediation:
            'Review service naming conventions. Consider using non-guessable service names ' +
            'or restricting access via IAM/ingress policies.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'cloud_service_discovery',
            service: svc.serviceName,
            url: svc.url,
            status: svc.status,
            serverHeader: svc.serverHeader,
            latencyMs: svc.latencyMs,
            analysisType: 'live',
          },
        };
      }
    }

    // ── Phase 3b: OpenAPI/Swagger Scanner ──────────────────────

    context.logger.info('Scanning for exposed API documentation');

    const openApiResult = await scanOpenApi({
      baseUrl: context.liveAttack.targetUrl,
      timeout: context.liveAttack.timeout ?? 8000,
      logger: context.logger,
    });

    if (openApiResult.found) {
      // Finding: API docs exposed
      for (const docUrl of openApiResult.exposedUrls) {
        yield {
          ruleId: 'spear-25/openapi-exposed',
          severity: 'high',
          message:
            `API documentation publicly exposed: ${docUrl.url} ` +
            `(status ${docUrl.status}, ${docUrl.isSpec ? 'parseable spec' : 'docs UI'})`,
          cvss: 7.5,
          mitreTechniques: ['T1592'],
          remediation:
            'Restrict API documentation endpoints to internal networks or authenticated users. ' +
            'Disable Swagger UI and OpenAPI spec endpoints in production.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'openapi_exposed',
            url: docUrl.url,
            status: docUrl.status,
            contentType: docUrl.contentType,
            isSpec: docUrl.isSpec,
            analysisType: 'live',
          },
        };
      }

      // Finding: Unauthenticated endpoints found in spec
      for (const ep of openApiResult.unauthenticatedEndpoints) {
        yield {
          ruleId: 'spear-25/openapi-no-auth',
          severity: 'high',
          message:
            `OpenAPI spec defines unauthenticated endpoint: ` +
            `${ep.method} ${ep.path}${ep.summary ? ` (${ep.summary})` : ''}`,
          cvss: 8.1,
          mitreTechniques: ['T1190'],
          remediation:
            'Add security definitions to all API endpoints in the OpenAPI spec. ' +
            'Verify that authentication is enforced at runtime.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'openapi_no_auth',
            endpoint: { method: ep.method, path: ep.path },
            operationId: ep.operationId,
            analysisType: 'live',
          },
        };
      }

      // Finding: Dangerous parameters
      for (const param of openApiResult.dangerousParams) {
        const severity: Severity = param.reason.includes('prompt') ? 'critical' : 'high';
        yield {
          ruleId: 'spear-25/dangerous-param',
          severity,
          message:
            `Dangerous parameter in API spec: ${param.paramName} ` +
            `in ${param.method} ${param.endpoint} (${param.location}) — ${param.reason}`,
          cvss: severity === 'critical' ? 9.1 : 7.5,
          mitreTechniques: ['T1190'],
          remediation:
            `Review the "${param.paramName}" parameter for security implications. ` +
            'Consider removing it from the public API or adding strict validation.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'dangerous_param',
            endpoint: { method: param.method, path: param.endpoint },
            paramName: param.paramName,
            location: param.location,
            reason: param.reason,
            analysisType: 'live',
          },
        };
      }

      // Add unauthenticated endpoints from OpenAPI to the probe list
      for (const ep of openApiResult.unauthenticatedEndpoints) {
        const key = `${ep.method}:${ep.path}`;
        if (!endpointsToProbeKeys.has(key)) {
          endpointsToProbeKeys.add(key);
          additionalEndpoints.push({
            method: ep.method,
            path: ep.path,
          });
        }
      }
    }

    const probeEngine = new ProbeEngine(context.liveAttack, context.logger);

    // Build the list of endpoints to probe
    const endpointsToProbe = buildProbeList(
      discoveredEndpoints,
      context.liveAttack.endpoints,
    );

    // Track keys of already-known endpoints
    for (const ep of endpointsToProbe) {
      endpointsToProbeKeys.add(`${ep.method}:${ep.path}`);
    }

    context.logger.info('Endpoints to probe', {
      total: endpointsToProbe.length,
      fromSource: discoveredEndpoints.length,
      fromConfig: context.liveAttack.endpoints?.length ?? 0,
    });

    let probedCount = 0;
    let liveFindingsCount = 0;

    // Merge additional endpoints discovered from OpenAPI
    const allEndpoints = [...endpointsToProbe, ...additionalEndpoints];

    for (const endpoint of allEndpoints) {
      const result = await probeEngine.probeEndpoint(endpoint);
      if (result === null) continue;

      probedCount++;

      // Yield findings based on probe results
      for (const finding of analyzeProbeResult(result, context)) {
        liveFindingsCount++;
        yield finding;
      }
    }

    context.logger.info('Live probing complete', {
      endpointsProbed: probedCount,
      liveFindings: liveFindingsCount,
    });
  }

  /**
   * Teardown: No resources to release.
   */
  async teardown(_context: PluginContext): Promise<void> {
    // Stateless -- no cleanup needed.
  }
}

// ─── Finding Generators ───────────────────────────────────────

/**
 * Create a finding for an endpoint with no auth detected via static analysis.
 */
function createStaticNoAuthFinding(endpoint: DiscoveredEndpoint): Finding {
  return {
    ruleId: 'spear-25/static-no-auth',
    severity: 'high',
    message:
      `Potentially unauthenticated endpoint: ${endpoint.method} ${endpoint.path} ` +
      `-- no auth middleware/decorator detected in ${endpoint.framework} source`,
    file: endpoint.file,
    line: endpoint.line,
    cvss: 7.5,
    mitreTechniques: ['T1190'],
    remediation:
      'Add authentication middleware to this endpoint. ' +
      'Verify that all API endpoints require proper authentication before processing requests.',
    metadata: {
      pluginId: 'endpoint-prober',
      category: 'static_no_auth',
      endpoint: { method: endpoint.method, path: endpoint.path },
      framework: endpoint.framework,
      authType: endpoint.authType ?? 'none',
      analysisType: 'static',
    },
  };
}

/**
 * Analyze a probe result and yield findings for any issues detected.
 */
function* analyzeProbeResult(
  result: ProbeResult,
  context: PluginContext,
): Generator<Finding> {
  const { endpoint } = result;
  const method = endpoint.method;
  const path = endpoint.path;
  const targetUrl = context.liveAttack?.targetUrl ?? '';

  // ── Check 1: Unauthenticated access ──────────────────────

  if (result.noAuth.accessible) {
    // Endpoint returned 200 without credentials -- CRITICAL
    const invalidAlsoAccessible = result.invalidAuth?.accessible === true;
    const authNotChecked = invalidAlsoAccessible
      ? ' -- auth is NOT checked at all (invalid token also accepted)'
      : '';

    yield {
      ruleId: 'spear-25/no-auth',
      severity: 'critical',
      message:
        `Unauthenticated endpoint: ${method} ${path} returned ${result.noAuth.status} ` +
        `without credentials${authNotChecked}`,
      file: endpoint.file,
      line: endpoint.line,
      cvss: 9.1,
      mitreTechniques: ['T1190'],
      remediation:
        'Add authentication middleware to this endpoint. ' +
        'Ensure all requests are validated for proper credentials before processing.',
      metadata: {
        pluginId: 'endpoint-prober',
        category: 'missing_auth',
        endpoint: { method, path },
        probe: {
          noAuthStatus: result.noAuth.status,
          invalidAuthStatus: result.invalidAuth?.status,
          expiredAuthStatus: result.expiredAuth?.status,
          responseSize: result.noAuth.responseSize,
          serverHeader: result.noAuth.serverHeader,
        },
        evidence:
          `Endpoint returned ${result.noAuth.status} OK with response body ` +
          `(${result.noAuth.responseSize} bytes) without any authentication`,
        durationMs: result.noAuth.durationMs,
        targetUrl,
        analysisType: 'live',
      },
    };
  }

  // ── Check 2: Invalid token accepted ──────────────────────

  if (
    result.invalidAuth?.accessible &&
    !result.noAuth.accessible
  ) {
    // Auth is present but not validated -- token value is not checked
    yield {
      ruleId: 'spear-25/invalid-token-accepted',
      severity: 'critical',
      message:
        `Invalid token accepted: ${method} ${path} returned ${result.invalidAuth.status} ` +
        `with invalid Bearer token (auth present but not validated)`,
      file: endpoint.file,
      line: endpoint.line,
      cvss: 9.1,
      mitreTechniques: ['T1190'],
      remediation:
        'Ensure the authentication middleware validates token signatures and claims. ' +
        'Invalid or malformed tokens must be rejected with 401.',
      metadata: {
        pluginId: 'endpoint-prober',
        category: 'weak_auth_validation',
        endpoint: { method, path },
        probe: {
          noAuthStatus: result.noAuth.status,
          invalidAuthStatus: result.invalidAuth.status,
        },
        evidence:
          `Endpoint returned ${result.noAuth.status} without auth but ` +
          `${result.invalidAuth.status} with invalid token -- auth header is checked ` +
          `for presence but token value is not validated`,
        targetUrl,
        analysisType: 'live',
      },
    };
  }

  // ── Check 3: Expired token accepted ──────────────────────

  if (
    result.expiredAuth?.accessible &&
    !result.noAuth.accessible
  ) {
    yield {
      ruleId: 'spear-25/expired-token-accepted',
      severity: 'high',
      message:
        `Expired token accepted: ${method} ${path} returned ${result.expiredAuth.status} ` +
        `with expired JWT token`,
      file: endpoint.file,
      line: endpoint.line,
      cvss: 7.5,
      mitreTechniques: ['T1190'],
      remediation:
        'Ensure JWT expiration (exp) claim is validated. ' +
        'Reject tokens with expired timestamps.',
      metadata: {
        pluginId: 'endpoint-prober',
        category: 'expired_token_accepted',
        endpoint: { method, path },
        probe: {
          noAuthStatus: result.noAuth.status,
          expiredAuthStatus: result.expiredAuth.status,
        },
        evidence:
          `Endpoint accepted an expired JWT token (exp=0) and returned ${result.expiredAuth.status}`,
        targetUrl,
        analysisType: 'live',
      },
    };
  }

  // ── Check 4: Auth bypass successes ───────────────────────

  if (result.bypasses) {
    for (const bypass of result.bypasses) {
      if (bypass.accessible) {
        yield createBypassFinding(endpoint, bypass, targetUrl);
      }
    }
  }

  // ── Check 5: CORS misconfiguration ──────────────────────

  if (result.cors?.permissive) {
    yield {
      ruleId: 'spear-25/permissive-cors',
      severity: 'medium',
      message:
        `Permissive CORS on ${method} ${path}: ${result.cors.evidence}`,
      file: endpoint.file,
      line: endpoint.line,
      cvss: 5.3,
      mitreTechniques: ['T1189'],
      remediation:
        'Restrict Access-Control-Allow-Origin to specific trusted domains. ' +
        'Never use wildcard (*) with Access-Control-Allow-Credentials: true.',
      metadata: {
        pluginId: 'endpoint-prober',
        category: 'permissive_cors',
        endpoint: { method, path },
        cors: {
          allowOrigin: result.cors.allowOrigin,
          allowCredentials: result.cors.allowCredentials,
        },
        evidence: result.cors.evidence,
        targetUrl,
        analysisType: 'live',
      },
    };
  }

  // ── Check 6: No rate limiting ───────────────────────────

  if (result.rateLimit && !result.rateLimit.rateLimited) {
    yield {
      ruleId: 'spear-25/no-rate-limit',
      severity: 'medium',
      message:
        `No rate limiting on ${method} ${path}: ` +
        `${result.rateLimit.successfulRequests} requests succeeded without throttling`,
      file: endpoint.file,
      line: endpoint.line,
      cvss: 4.3,
      mitreTechniques: ['T1498'],
      remediation:
        'Implement rate limiting on this endpoint to prevent brute-force attacks and abuse. ' +
        'Consider using a reverse proxy or API gateway for rate limiting.',
      metadata: {
        pluginId: 'endpoint-prober',
        category: 'no_rate_limit',
        endpoint: { method, path },
        rateLimit: {
          totalRequests: result.rateLimit.totalRequests,
          successfulRequests: result.rateLimit.successfulRequests,
        },
        evidence: result.rateLimit.evidence,
        targetUrl,
        analysisType: 'live',
      },
    };
  }

  // ── Check 7: Rate limit detected (informational) ────────

  if (result.rateLimit?.rateLimited) {
    yield {
      ruleId: 'spear-25/rate-limit-detected',
      severity: 'info',
      message:
        `Rate limiting detected on ${method} ${path}: ${result.rateLimit.evidence}`,
      file: endpoint.file,
      line: endpoint.line,
      metadata: {
        pluginId: 'endpoint-prober',
        category: 'rate_limit_detected',
        endpoint: { method, path },
        rateLimit: {
          limitHitAtRequest: result.rateLimit.limitHitAtRequest,
        },
        evidence: result.rateLimit.evidence,
        targetUrl,
        analysisType: 'live',
      },
    };
  }
}

/**
 * Create a finding for a successful auth bypass attempt.
 */
function createBypassFinding(
  endpoint: EndpointInfo,
  bypass: AuthBypassResult,
  targetUrl: string,
): Finding {
  const severityMap: Record<string, Severity> = {
    path_traversal: 'high',
    double_encoding: 'high',
    case_manipulation: 'high',
    method_override: 'high',
    verb_tampering: 'medium',
    null_byte_injection: 'high',
    trailing_slash: 'medium',
    json_extension: 'medium',
    origin_spoof: 'medium',
    referer_spoof: 'low',
  };

  const cvssMap: Record<string, number> = {
    path_traversal: 8.1,
    double_encoding: 8.1,
    case_manipulation: 7.5,
    method_override: 7.5,
    verb_tampering: 5.3,
    null_byte_injection: 8.1,
    trailing_slash: 5.3,
    json_extension: 5.3,
    origin_spoof: 5.3,
    referer_spoof: 3.7,
  };

  return {
    ruleId: 'spear-25/auth-bypass',
    severity: severityMap[bypass.technique] ?? 'high',
    message:
      `Auth bypass via ${bypass.technique}: ${endpoint.method} ${endpoint.path} ` +
      `returned ${bypass.status}`,
    file: endpoint.file,
    line: endpoint.line,
    cvss: cvssMap[bypass.technique] ?? 7.5,
    mitreTechniques: ['T1190'],
    remediation:
      `Fix auth bypass via ${bypass.technique}. ` +
      'Ensure authentication checks are applied consistently regardless of URL encoding, ' +
      'case variations, or HTTP method overrides.',
    metadata: {
      pluginId: 'endpoint-prober',
      category: 'auth_bypass',
      technique: bypass.technique,
      endpoint: { method: endpoint.method, path: endpoint.path },
      originalPath: endpoint.path,
      bypassDetails: bypass.requestDetails,
      status: bypass.status,
      evidence: bypass.evidence,
      targetUrl,
      analysisType: 'live',
    },
  };
}

// ─── Helpers ──────────────────────────────────────────────────

/**
 * Build a unified list of endpoints to probe from discovered and configured endpoints.
 *
 * Merges endpoints discovered from source code with explicitly configured
 * endpoints, deduplicating by method+path.
 */
function buildProbeList(
  discovered: DiscoveredEndpoint[],
  configured?: LiveEndpoint[],
): EndpointInfo[] {
  const seen = new Set<string>();
  const result: EndpointInfo[] = [];

  // Add discovered endpoints
  for (const ep of discovered) {
    const key = `${ep.method}:${ep.path}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push({
        method: ep.method,
        path: ep.path,
        file: ep.file,
        line: ep.line,
      });
    }
  }

  // Add configured endpoints (from liveAttack.endpoints)
  if (configured) {
    for (const ep of configured) {
      const key = `${ep.method}:${ep.path}`;
      if (!seen.has(key)) {
        seen.add(key);
        result.push({
          method: ep.method,
          path: ep.path,
        });
      }
    }
  }

  return result;
}

// ─── Default Export ───────────────────────────────────────────

export default new EndpointProberPlugin();
