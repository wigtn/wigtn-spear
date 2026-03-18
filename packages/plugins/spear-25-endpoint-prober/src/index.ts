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
import { createHash } from 'node:crypto';
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
import { scanAiInfra } from './ai-infra-scanner.js';
import type { AiInfraResult, DiscoveredAiEndpoint } from './ai-infra-scanner.js';
import { scanDebugEndpoints } from './debug-scanner.js';
import type { DebugScanResult, DiscoveredDebugEndpoint } from './debug-scanner.js';
import { analyzeJsBundles } from './js-bundle-analyzer.js';
import type { JsBundleResult, DiscoveredSecret, DiscoveredSourceMap, DiscoveredEnvLeak } from './js-bundle-analyzer.js';
import { analyzeHttpHeaders } from './http-header-analyzer.js';
import type { HeaderAnalysisResult, MissingHeader, InsecureCookie } from './http-header-analyzer.js';
import { captureBaseline } from './baseline-fingerprinter.js';
import type { BaselineFingerprint } from './baseline-fingerprinter.js';
import { provokeErrors } from './error-provocator.js';
import type { ErrorProvocationResult } from './error-provocator.js';
import { bruteforcePaths, getWordlistSize } from './path-bruteforce.js';
import type { BruteforceResult } from './path-bruteforce.js';
import { scanGitExposure } from './git-exposure-scanner.js';
import type { GitExposureResult } from './git-exposure-scanner.js';
import { analyzeDiscoveredPaths } from './admin-panel-scanner.js';
import type { AdminScanResult } from './admin-panel-scanner.js';

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

    // Skip static analysis in live attack mode -- it scans local code, not the target
    if (!context.liveAttack) {
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
    } else {
      context.logger.info('Static analysis skipped in live attack mode');
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

    // ── Baseline Fingerprint Capture (FP Elimination) ────────
    const baseline = await captureBaseline({
      baseUrl: context.liveAttack.targetUrl,
      timeout: context.liveAttack.timeout ?? 5000,
      logger: context.logger,
    });

    if (baseline?.isCatchAll) {
      context.logger.info('Catch-all route detected, baseline FP filter active', {
        status: baseline.status,
        bodyLength: baseline.bodyLength,
      });
    }

    // ── Finding Dedup Set ────────────────────────────────────
    const emittedFingerprints = new Set<string>();

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
      baseline,
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

    // ── Phase 3c: AI Infrastructure Scanner (LLM04 + LLM08) ──

    context.logger.info('Scanning for exposed AI/ML infrastructure');

    const aiInfraResult = await scanAiInfra({
      baseUrl: context.liveAttack.targetUrl,
      timeout: context.liveAttack.timeout ?? 5000,
      logger: context.logger,
      baseline,
    });

    // ML model management endpoints (LLM04)
    for (const ep of aiInfraResult.mlEndpoints) {
      yield {
        ruleId: 'spear-25/ml-endpoint-exposed',
        severity: ep.writeable ? 'critical' : 'high',
        message:
          `ML infrastructure exposed: ${ep.service} at ${ep.url} — ${ep.exposure}`,
        cvss: ep.writeable ? 9.1 : 7.5,
        mitreTechniques: ['T1195'],
        remediation:
          `Restrict access to ${ep.service} management endpoints. ` +
          'Add authentication and limit network access to internal services only.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'ml_endpoint_exposed',
          owaspLlm: 'LLM04',
          service: ep.service,
          url: ep.url,
          unauthenticated: ep.unauthenticated,
          writeable: ep.writeable,
          evidence: ep.evidence.slice(0, 300),
          analysisType: 'live',
        },
      };
    }

    // Vector DB endpoints (LLM08)
    for (const ep of aiInfraResult.vectorDbEndpoints) {
      yield {
        ruleId: 'spear-25/vector-db-exposed',
        severity: ep.writeable ? 'critical' : 'high',
        message:
          `Vector database exposed: ${ep.service} at ${ep.url} — ${ep.exposure}`,
        cvss: ep.writeable ? 9.1 : 7.5,
        mitreTechniques: ['T1195'],
        remediation:
          `Restrict access to ${ep.service} vector database. ` +
          'Add authentication, enable TLS, and limit to internal network only. ' +
          'Exposed vector DBs allow RAG poisoning attacks.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'vector_db_exposed',
          owaspLlm: 'LLM08',
          service: ep.service,
          url: ep.url,
          unauthenticated: ep.unauthenticated,
          writeable: ep.writeable,
          evidence: ep.evidence.slice(0, 300),
          analysisType: 'live',
        },
      };
    }

    // ── Phase 3d: Debug & Logging Scanner (A09) ────────────────

    context.logger.info('Scanning for exposed debug/logging endpoints');

    const debugResult = await scanDebugEndpoints({
      baseUrl: context.liveAttack.targetUrl,
      timeout: context.liveAttack.timeout ?? 5000,
      logger: context.logger,
      baseline,
    });

    for (const ep of debugResult.endpoints) {
      const severityMap: Record<string, Severity> = {
        environment: 'critical',
        profiling: 'high',
        debug: 'high',
        monitoring: 'medium',
        logging: 'high',
        sourcemap: 'medium',
        introspection: 'medium',
        admin: 'high',
      };

      yield {
        ruleId: `spear-25/debug-${ep.category}-exposed`,
        severity: severityMap[ep.category] ?? 'medium',
        message: `Debug/logging endpoint exposed: ${ep.service} at ${ep.url} — ${ep.exposure}`,
        cvss: ep.category === 'environment' ? 9.1 : 6.5,
        mitreTechniques: ['T1592'],
        remediation:
          `Remove or restrict access to ${ep.url} in production. ` +
          'Debug and monitoring endpoints should never be publicly accessible.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: `debug_${ep.category}`,
          owaspWeb: 'A09',
          service: ep.service,
          url: ep.url,
          evidence: ep.evidence.slice(0, 300),
          analysisType: 'live',
        },
      };
    }

    // Stack trace leakage finding
    if (debugResult.stackTraceLeaked) {
      yield {
        ruleId: 'spear-25/stack-trace-leaked',
        severity: 'medium',
        message:
          'Error responses leak stack traces — internal code paths and dependencies exposed',
        cvss: 5.3,
        mitreTechniques: ['T1592'],
        remediation:
          'Configure error handling to return generic error messages in production. ' +
          'Never expose stack traces, file paths, or internal details to users.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'stack_trace_leakage',
          owaspWeb: 'A09',
          evidence: debugResult.stackTraceEvidence?.slice(0, 300),
          analysisType: 'live',
        },
      };
    }

    // ── Phase 3e: JS Bundle Analyzer ────────────────────────────

    context.logger.info('Analyzing JavaScript bundles');

    const jsBundleResult = await analyzeJsBundles({
      baseUrl: context.liveAttack.targetUrl,
      timeout: context.liveAttack.timeout ?? 10000,
      logger: context.logger,
      secretVerifier: context.secretVerifier,
      enableDeepRecovery: true,
    });

    // Secrets found in JS bundles
    for (const secret of jsBundleResult.secrets) {
      const isVerifiedActive = secret.verification?.verified && secret.verification?.active;
      const message = isVerifiedActive
        ? `VERIFIED LIVE SECRET: ${secret.pattern} ${secret.masked} is ACTIVE` +
          (secret.verification?.permissions ? ` (${secret.verification.permissions.join(', ')})` : ' (no domain restriction)') +
          ` — found in ${secret.scriptUrl}`
        : `Hardcoded secret in JavaScript bundle: ${secret.pattern} — ${secret.masked} ` +
          `found in ${secret.scriptUrl}`;

      const finding: Finding = {
        ruleId: 'spear-25/js-secret-exposed',
        severity: isVerifiedActive ? 'critical' : 'high',
        message,
        cvss: isVerifiedActive ? 9.8 : 9.1,
        mitreTechniques: ['T1552'],
        confidence: isVerifiedActive ? 'confirmed' : 'high',
        remediation:
          'Never embed API keys or secrets in frontend JavaScript. ' +
          'Use server-side proxying or environment-specific configuration. ' +
          'Rotate this credential immediately.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'js_secret_exposed',
          secretType: secret.type,
          masked: secret.masked,
          scriptUrl: secret.scriptUrl,
          context: secret.context,
          verification: secret.verification,
          analysisType: 'live',
        },
      };

      if (yieldDeduped(finding, emittedFingerprints)) {
        yield finding;
      }
    }

    // Accessible source maps
    for (const sourceMap of jsBundleResult.sourceMaps) {
      if (!sourceMap.accessible) continue;

      yield {
        ruleId: 'spear-25/sourcemap-exposed',
        severity: 'high',
        message:
          `Source map publicly accessible: ${sourceMap.url} ` +
          `(${sourceMap.sourceCount ?? '?'} source files, ${sourceMap.size ?? 0} bytes)`,
        cvss: 7.5,
        mitreTechniques: ['T1592'],
        remediation:
          'Remove source maps from production deployment. ' +
          'Configure build tool to disable sourcemap generation for production builds. ' +
          'Source maps expose original source code, internal paths, and variable names.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'sourcemap_exposed',
          owaspWeb: 'A05',
          url: sourceMap.url,
          size: sourceMap.size,
          sourceCount: sourceMap.sourceCount,
          sources: sourceMap.sources?.slice(0, 20),
          analysisType: 'live',
        },
      };
    }

    // API endpoints discovered in JS
    for (const endpoint of jsBundleResult.endpoints) {
      if (endpoint.category === 'internal' || endpoint.category === 'websocket') {
        yield {
          ruleId: 'spear-25/js-internal-url',
          severity: endpoint.category === 'internal' ? 'high' : 'medium',
          message:
            `${endpoint.category === 'internal' ? 'Internal service' : 'WebSocket'} URL exposed in JavaScript: ${endpoint.url}`,
          cvss: endpoint.category === 'internal' ? 7.5 : 5.3,
          mitreTechniques: ['T1592'],
          remediation:
            'Do not embed internal service URLs or WebSocket endpoints in frontend code. ' +
            'Use relative paths or server-side configuration.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: `js_${endpoint.category}_url`,
            url: endpoint.url,
            scriptUrl: endpoint.scriptUrl,
            analysisType: 'live',
          },
        };
      }

      // Add discovered API endpoints to probe list
      if (endpoint.category === 'api') {
        try {
          const parsed = new URL(endpoint.url, context.liveAttack.targetUrl);
          // Only add if same origin
          const targetOrigin = new URL(context.liveAttack.targetUrl).origin;
          if (parsed.origin === targetOrigin) {
            const key = `GET:${parsed.pathname}`;
            if (!endpointsToProbeKeys.has(key)) {
              endpointsToProbeKeys.add(key);
              additionalEndpoints.push({ method: 'GET', path: parsed.pathname });
            }
          }
        } catch {
          // Invalid URL, skip
        }
      }
    }

    // ── Phase 3f: HTTP Security Header Analysis ─────────────────

    context.logger.info('Analyzing HTTP security headers');

    const headerResult = await analyzeHttpHeaders({
      baseUrl: context.liveAttack.targetUrl,
      timeout: context.liveAttack.timeout ?? 10000,
      logger: context.logger,
    });

    // Missing security headers
    for (const missing of headerResult.missingHeaders) {
      yield {
        ruleId: 'spear-25/missing-security-header',
        severity: missing.severity,
        message: `Missing security header: ${missing.header} — ${missing.impact}`,
        cvss: missing.severity === 'critical' ? 8.1 : missing.severity === 'high' ? 6.5 : 4.3,
        mitreTechniques: ['T1189'],
        confidence: 'high',
        remediation:
          `Add the ${missing.header} header to all responses. ` +
          `Recommended value: ${missing.recommended}`,
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'missing_security_header',
          owaspWeb: 'A05',
          header: missing.header,
          recommended: missing.recommended,
          analysisType: 'live',
        },
      };
    }

    // Insecure cookies
    for (const cookie of headerResult.insecureCookies) {
      yield {
        ruleId: 'spear-25/insecure-cookie',
        severity: 'medium',
        message:
          `Insecure cookie: "${cookie.name}" missing ${cookie.missingFlags.join(', ')} — ${cookie.impact}`,
        cvss: 5.3,
        mitreTechniques: ['T1539'],
        remediation:
          `Set ${cookie.missingFlags.join(', ')} flags on the "${cookie.name}" cookie. ` +
          'All session cookies should have HttpOnly, Secure, and SameSite=Strict or Lax.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'insecure_cookie',
          owaspWeb: 'A05',
          cookieName: cookie.name,
          missingFlags: cookie.missingFlags,
          raw: cookie.raw,
          analysisType: 'live',
        },
      };
    }

    // Information leakage
    for (const leak of headerResult.infoLeaks) {
      yield {
        ruleId: 'spear-25/header-info-leak',
        severity: 'low',
        message:
          `Information leakage via ${leak.header} header: "${leak.value}" — reveals ${leak.reveals}`,
        cvss: 3.7,
        mitreTechniques: ['T1592'],
        remediation:
          `Remove or suppress the ${leak.header} header in production. ` +
          'Revealing server software and versions aids attackers in finding known vulnerabilities.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'header_info_leak',
          owaspWeb: 'A05',
          header: leak.header,
          value: leak.value,
          analysisType: 'live',
        },
      };
    }

    // CORS issues
    for (const cors of headerResult.corsIssues) {
      const corsSeverity = cors.type === 'credentials_with_wildcard' ? 'critical' : 'medium';
      yield {
        ruleId: 'spear-25/cors-misconfiguration',
        severity: corsSeverity as Severity,
        message: `CORS misconfiguration: ${cors.description}`,
        cvss: corsSeverity === 'critical' ? 9.1 : 5.3,
        mitreTechniques: ['T1189'],
        confidence: 'confirmed',
        remediation:
          'Configure CORS to allow only specific trusted origins. ' +
          'Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'cors_misconfiguration',
          owaspWeb: 'A05',
          type: cors.type,
          evidence: cors.evidence,
          analysisType: 'live',
        },
      };
    }

    // Technology fingerprint (informational)
    if (headerResult.fingerprint.technologies.length > 0) {
      yield {
        ruleId: 'spear-25/tech-fingerprint',
        severity: 'info',
        message:
          `Technology fingerprint: ${headerResult.fingerprint.technologies.join(', ')}`,
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'tech_fingerprint',
          fingerprint: headerResult.fingerprint,
          analysisType: 'live',
        },
      };
    }

    // ── Phase 3g: Environment Variable Leak Findings ────────────

    for (const envLeak of jsBundleResult.envLeaks) {
      const severity: Severity = envLeak.isSensitive ? 'high' : 'medium';
      const finding: Finding = {
        ruleId: 'spear-25/build-env-leak',
        severity,
        message:
          `Build-time environment variable exposed: ${envLeak.variable}=${envLeak.maskedValue} ` +
          `(${envLeak.framework}) in ${envLeak.scriptUrl}` +
          (envLeak.isSensitive ? ' — SENSITIVE variable name detected' : ''),
        cvss: envLeak.isSensitive ? 7.5 : 4.3,
        mitreTechniques: ['T1552'],
        confidence: 'confirmed',
        remediation:
          `Review the ${envLeak.variable} environment variable. ` +
          'Ensure it does not contain sensitive values. ' +
          'Use server-side environment variables for secrets, not client-side prefixed ones.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'build_env_leak',
          framework: envLeak.framework,
          variable: envLeak.variable,
          isSensitive: envLeak.isSensitive,
          analysisType: 'live',
        },
      };

      if (yieldDeduped(finding, emittedFingerprints)) {
        yield finding;
      }
    }

    // ── Phase 3h: Sourcemap Deep Recovery Findings ──────────────

    for (const recovery of jsBundleResult.sourcemapRecoveries) {
      for (const secret of recovery.secrets) {
        const finding: Finding = {
          ruleId: 'spear-25/sourcemap-recovered-secret',
          severity: 'critical',
          message:
            `Secret recovered from sourcemap: ${secret.type} — ${secret.masked} ` +
            `in ${secret.sourceFile}:${secret.line} (via ${recovery.sourcemapUrl})`,
          cvss: 9.1,
          mitreTechniques: ['T1552'],
          confidence: 'high',
          remediation:
            'Remove source maps from production. The original source code is recoverable ' +
            'and contains embedded secrets. Rotate all exposed credentials immediately.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'sourcemap_recovered_secret',
            secretType: secret.type,
            masked: secret.masked,
            sourceFile: secret.sourceFile,
            line: secret.line,
            sourcemapUrl: recovery.sourcemapUrl,
            attackChain: ['sourcemap_access', 'source_recovery', 'secret_extraction'],
            analysisType: 'live',
          },
        };

        if (yieldDeduped(finding, emittedFingerprints)) {
          yield finding;
        }
      }

      // Env var references from sourcemap recovery
      for (const envRef of recovery.envReferences) {
        const finding: Finding = {
          ruleId: 'spear-25/sourcemap-env-reference',
          severity: 'medium',
          message:
            `Environment variable reference in recovered source: ${envRef.variable} ` +
            `in ${envRef.sourceFile}:${envRef.line}`,
          cvss: 4.3,
          mitreTechniques: ['T1592'],
          confidence: 'high',
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'sourcemap_env_reference',
            variable: envRef.variable,
            sourceFile: envRef.sourceFile,
            sourcemapUrl: recovery.sourcemapUrl,
            analysisType: 'live',
          },
        };

        if (yieldDeduped(finding, emittedFingerprints)) {
          yield finding;
        }
      }
    }

    // ── Phase 3i: Error Provocation ────────────────────────────

    context.logger.info('Starting error provocation');

    const errorResults = await provokeErrors({
      baseUrl: context.liveAttack.targetUrl,
      baseline,
      timeout: context.liveAttack.timeout ?? 5000,
      maxRequests: 15,
      logger: context.logger,
    });

    for (const errResult of errorResults) {
      for (const leak of errResult.leaks) {
        const severity: Severity = leak.type === 'db_connection' || leak.type === 'env_variable' ? 'critical' : 'high';
        const finding: Finding = {
          ruleId: 'spear-25/error-info-leak',
          severity,
          message:
            `Error provocation leaked ${leak.type}: "${leak.value}" ` +
            `(technique: ${errResult.technique}, status: ${errResult.status})`,
          cvss: severity === 'critical' ? 9.1 : 6.5,
          mitreTechniques: ['T1592'],
          confidence: 'confirmed',
          remediation:
            'Configure error handling to return generic error messages in production. ' +
            'Never expose stack traces, file paths, database connection strings, or internal IPs.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: `error_${leak.type}`,
            technique: errResult.technique,
            leakType: leak.type,
            url: errResult.url,
            status: errResult.status,
            evidence: leak.evidence.slice(0, 300),
            analysisType: 'live',
          },
        };

        if (yieldDeduped(finding, emittedFingerprints)) {
          yield finding;
        }
      }
    }

    // ── Phase 3j: Dependency CVE Findings ──────────────────────

    if (jsBundleResult.dependencyCves) {
      for (const cve of jsBundleResult.dependencyCves.cves) {
        const finding: Finding = {
          ruleId: 'spear-25/deployed-dependency-cve',
          severity: cve.severity,
          message:
            `${cve.name} ${cve.version} deployed — ${cve.cveId} (${cve.description}, ` +
            `CVSS ${cve.cvss}, fix: upgrade to ${cve.fixVersion})`,
          cvss: cve.cvss,
          mitreTechniques: ['T1190'],
          confidence: 'confirmed',
          remediation:
            `Upgrade ${cve.name} to version ${cve.fixVersion} or later to fix ${cve.cveId}.`,
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'deployed_dependency_cve',
            library: cve.name,
            version: cve.version,
            cveId: cve.cveId,
            fixVersion: cve.fixVersion,
            detectedIn: cve.detectedIn,
            analysisType: 'live',
          },
        };

        if (yieldDeduped(finding, emittedFingerprints)) {
          yield finding;
        }
      }
    }

    // ── Phase 3k: Git Exposure Scanner ─────────────────────────

    context.logger.info('Scanning for .git directory exposure');

    const gitResult = await scanGitExposure({
      baseUrl: context.liveAttack.targetUrl,
      timeout: context.liveAttack.timeout ?? 5000,
      logger: context.logger,
    });

    if (gitResult.exposed) {
      const finding: Finding = {
        ruleId: 'spear-25/git-exposed',
        severity: 'critical',
        message:
          `.git directory EXPOSED: ${gitResult.evidence}`,
        cvss: 9.8,
        mitreTechniques: ['T1213'],
        confidence: 'confirmed',
        remediation:
          'Block access to .git directory in your web server configuration. ' +
          'Add a deny rule for /.git/ in nginx/Apache. ' +
          'Full source code and commit history can be reconstructed from an exposed .git directory.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'git_exposed',
          confirmedPaths: gitResult.paths.filter((p) => p.contentValid).map((p) => p.path),
          gitConfig: gitResult.gitConfig,
          analysisType: 'live',
        },
      };

      if (yieldDeduped(finding, emittedFingerprints)) {
        yield finding;
      }
    }

    // Individual git path findings
    for (const pathResult of gitResult.paths) {
      if (pathResult.contentValid && pathResult.path === '/.git/config' && gitResult.gitConfig?.remoteUrl) {
        const finding: Finding = {
          ruleId: 'spear-25/git-config-leak',
          severity: 'critical',
          message:
            `Git config exposes remote URL: ${gitResult.gitConfig.remoteUrl}` +
            (gitResult.gitConfig.userEmail ? ` (committer: ${gitResult.gitConfig.userEmail})` : ''),
          cvss: 9.1,
          mitreTechniques: ['T1552'],
          confidence: 'confirmed',
          remediation:
            'Block access to /.git/config immediately. The remote URL may contain credentials ' +
            'and reveals the repository location.',
          metadata: {
            pluginId: 'endpoint-prober',
            category: 'git_config_leak',
            remoteUrl: gitResult.gitConfig.remoteUrl,
            userEmail: gitResult.gitConfig.userEmail,
            userName: gitResult.gitConfig.userName,
            analysisType: 'live',
          },
        };

        if (yieldDeduped(finding, emittedFingerprints)) {
          yield finding;
        }
      }
    }

    // ── Phase 3l: Path Bruteforce + Admin Panel Scanner ─────────

    context.logger.info('Starting path bruteforce', {
      wordlistSize: getWordlistSize(),
    });

    const bruteforceResults = await bruteforcePaths({
      baseUrl: context.liveAttack.targetUrl,
      baseline,
      timeout: context.liveAttack.timeout ?? 5000,
      concurrency: 10,
      logger: context.logger,
    });

    // Deep-analyze discovered paths
    const adminScanResult = analyzeDiscoveredPaths(bruteforceResults, context.logger);

    // Admin panels
    for (const panel of adminScanResult.adminPanels) {
      const finding: Finding = {
        ruleId: 'spear-25/admin-panel-exposed',
        severity: panel.severity,
        message:
          `Admin panel exposed: ${panel.technology} at ${panel.url}` +
          (panel.authenticated ? '' : ' — NO authentication required'),
        cvss: panel.authenticated ? 6.5 : 9.1,
        mitreTechniques: ['T1190'],
        confidence: 'confirmed',
        remediation:
          `Restrict access to admin panel (${panel.technology}). ` +
          'Use IP whitelisting, VPN-only access, or remove from production deployment.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'admin_panel_exposed',
          technology: panel.technology,
          authenticated: panel.authenticated,
          evidence: panel.evidence,
          analysisType: 'live',
        },
      };

      if (yieldDeduped(finding, emittedFingerprints)) {
        yield finding;
      }
    }

    // API documentation
    for (const doc of adminScanResult.apiDocs) {
      const finding: Finding = {
        ruleId: 'spear-25/api-docs-exposed',
        severity: doc.severity,
        message: `API documentation exposed: ${doc.type} at ${doc.url}`,
        cvss: 7.5,
        mitreTechniques: ['T1592'],
        confidence: 'confirmed',
        remediation:
          'Remove API documentation from production deployment or restrict access.',
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'api_docs_exposed',
          type: doc.type,
          evidence: doc.evidence,
          analysisType: 'live',
        },
      };

      if (yieldDeduped(finding, emittedFingerprints)) {
        yield finding;
      }
    }

    // Debug endpoints from deep analysis
    for (const debug of adminScanResult.debugEndpoints) {
      const finding: Finding = {
        ruleId: 'spear-25/debug-endpoint-exposed',
        severity: debug.severity,
        message:
          `Debug endpoint exposed: ${debug.type} at ${debug.url}` +
          (debug.leaksInfo ? ' — leaks sensitive information' : ''),
        cvss: debug.leaksInfo ? 9.1 : 6.5,
        mitreTechniques: ['T1592'],
        confidence: 'confirmed',
        remediation:
          `Remove ${debug.type} from production deployment. Debug endpoints leak internal state.`,
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'debug_endpoint_exposed',
          type: debug.type,
          leaksInfo: debug.leaksInfo,
          evidence: debug.evidence,
          analysisType: 'live',
        },
      };

      if (yieldDeduped(finding, emittedFingerprints)) {
        yield finding;
      }
    }

    // Database UIs
    for (const dbUI of adminScanResult.databaseUIs) {
      const finding: Finding = {
        ruleId: 'spear-25/database-ui-exposed',
        severity: 'critical',
        message:
          `Database management UI exposed: ${dbUI.technology} at ${dbUI.url}` +
          (dbUI.authenticated ? '' : ' — NO authentication'),
        cvss: 9.8,
        mitreTechniques: ['T1190'],
        confidence: 'confirmed',
        remediation:
          `Remove ${dbUI.technology} from production or restrict access to internal network only.`,
        metadata: {
          pluginId: 'endpoint-prober',
          category: 'database_ui_exposed',
          technology: dbUI.technology,
          authenticated: dbUI.authenticated,
          evidence: dbUI.evidence,
          analysisType: 'live',
        },
      };

      if (yieldDeduped(finding, emittedFingerprints)) {
        yield finding;
      }
    }

    // Remaining bruteforce hits not classified by deep analysis
    for (const bf of bruteforceResults) {
      // Skip paths already covered by deep analysis
      if (['admin', 'api_docs', 'debug', 'database'].includes(bf.category)) continue;

      // Config files and backup files are always interesting
      if (['config', 'backup', 'git', 'cicd'].includes(bf.category)) {
        const severity: Severity = bf.category === 'backup' || bf.category === 'config' ? 'high' : 'medium';
        const finding: Finding = {
          ruleId: `spear-25/sensitive-path-${bf.category}`,
          severity,
          message: `Sensitive file accessible: ${bf.description} at ${bf.path} (status ${bf.status})`,
          cvss: severity === 'high' ? 7.5 : 5.3,
          mitreTechniques: ['T1592'],
          confidence: 'confirmed',
          remediation:
            `Block access to ${bf.path} in production. Sensitive files should not be publicly accessible.`,
          metadata: {
            pluginId: 'endpoint-prober',
            category: `sensitive_path_${bf.category}`,
            path: bf.path,
            status: bf.status,
            bodySize: bf.bodySize,
            contentType: bf.contentType,
            analysisType: 'live',
          },
        };

        if (yieldDeduped(finding, emittedFingerprints)) {
          yield finding;
        }
      }
    }

    // ── Phase 4: Endpoint Probing with Baseline Filter ──────────

    const probeEngine = new ProbeEngine(context.liveAttack, context.logger, baseline);

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
        if (yieldDeduped(finding, emittedFingerprints)) {
          liveFindingsCount++;
          yield finding;
        }
      }
    }

    context.logger.info('Live probing complete', {
      endpointsProbed: probedCount,
      liveFindings: liveFindingsCount,
      totalDeduped: emittedFingerprints.size,
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
      confidence: 'confirmed',
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
      confidence: 'confirmed',
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
      confidence: 'confirmed',
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
      confidence: 'medium',
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

// ─── Dedup Helpers ──────────────────────────────────────────────

/**
 * Compute a fingerprint ID for deduplication.
 * fingerprintId = SHA256(ruleId + category + evidence).slice(0, 16)
 */
function computeFingerprintId(finding: Finding): string {
  const category = (finding.metadata as Record<string, unknown>)?.category as string ?? '';
  const evidence = (finding.metadata as Record<string, unknown>)?.evidence as string ?? finding.message;
  const input = `${finding.ruleId}:${category}:${evidence}`;
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 16);
}

/**
 * Check if a finding should be yielded (not a duplicate).
 * If it's new, adds the fingerprint to the set and sets fingerprintId on the finding.
 * Returns true if the finding should be yielded.
 */
function yieldDeduped(finding: Finding, emittedFingerprints: Set<string>): boolean {
  const fpId = computeFingerprintId(finding);
  if (emittedFingerprints.has(fpId)) {
    return false;
  }
  emittedFingerprints.add(fpId);
  finding.fingerprintId = fpId;
  return true;
}

// ─── Default Export ───────────────────────────────────────────

export default new EndpointProberPlugin();
