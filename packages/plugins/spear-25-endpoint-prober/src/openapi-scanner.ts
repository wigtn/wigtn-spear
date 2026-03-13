/**
 * SPEAR-25: OpenAPI/Swagger Scanner Module
 *
 * Auto-discovers and parses publicly exposed API documentation endpoints:
 *   - /openapi.json, /openapi.yaml
 *   - /swagger.json, /swagger.yaml
 *   - /docs (FastAPI Swagger UI)
 *   - /redoc (ReDoc)
 *   - /api-docs
 *   - /swagger-ui
 *   - /v1/openapi.json, /v2/openapi.json, /v3/openapi.json
 *
 * When an OpenAPI spec is found, the scanner:
 *   1. Parses all endpoint definitions
 *   2. Identifies endpoints without security definitions (auth gaps)
 *   3. Detects dangerous parameters (e.g., system_prompt_override)
 *   4. Extracts server info, auth schemes, and data models
 *
 * This automates what was previously done manually with curl against
 * /docs and /openapi.json.
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface OpenApiScanResult {
  /** Whether any API documentation endpoint was found */
  found: boolean;
  /** URLs that returned valid responses */
  exposedUrls: ExposedDocUrl[];
  /** Parsed OpenAPI specification (if any JSON spec was found) */
  spec?: ParsedOpenApiSpec;
  /** Endpoints extracted from the spec */
  endpoints: OpenApiEndpoint[];
  /** Endpoints with no security definitions */
  unauthenticatedEndpoints: OpenApiEndpoint[];
  /** Dangerous parameters found in request bodies */
  dangerousParams: DangerousParam[];
}

export interface ExposedDocUrl {
  url: string;
  status: number;
  contentType?: string;
  isSpec: boolean;
  latencyMs: number;
}

export interface ParsedOpenApiSpec {
  title?: string;
  version?: string;
  description?: string;
  servers?: string[];
  securitySchemes: Record<string, SecurityScheme>;
  globalSecurity: string[];
}

export interface SecurityScheme {
  type: string;
  scheme?: string;
  bearerFormat?: string;
  name?: string;
  in?: string;
}

export interface OpenApiEndpoint {
  method: string;
  path: string;
  operationId?: string;
  summary?: string;
  security: string[];
  parameters: ParamInfo[];
  requestBody?: RequestBodyInfo;
}

export interface ParamInfo {
  name: string;
  in: string;
  required: boolean;
  type?: string;
}

export interface RequestBodyInfo {
  required: boolean;
  properties: Record<string, PropertyInfo>;
}

export interface PropertyInfo {
  type?: string;
  nullable?: boolean;
  description?: string;
}

export interface DangerousParam {
  endpoint: string;
  method: string;
  paramName: string;
  location: string;
  reason: string;
}

export interface OpenApiScanConfig {
  /** Base URL to scan */
  baseUrl: string;
  /** Request timeout in ms (default: 8000) */
  timeout?: number;
  /** Logger instance */
  logger?: SpearLogger;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 8_000;
const PROBE_DELAY_MS = 100;

/** Common paths where API documentation is exposed. */
const DOC_PATHS: readonly string[] = [
  '/openapi.json',
  '/swagger.json',
  '/docs',
  '/redoc',
  '/api-docs',
  '/swagger-ui',
  '/swagger-ui/index.html',
  '/openapi.yaml',
  '/swagger.yaml',
  '/v1/openapi.json',
  '/v2/openapi.json',
  '/v3/openapi.json',
  '/api/openapi.json',
  '/api/swagger.json',
  '/api/docs',
  '/.well-known/openapi.json',
];

/** Parameter names that indicate potential security risks. */
const DANGEROUS_PARAM_PATTERNS: readonly {
  pattern: RegExp;
  reason: string;
}[] = [
  {
    pattern: /system[_-]?prompt/i,
    reason: 'Allows overriding system prompt — direct prompt injection vector',
  },
  {
    pattern: /(?:admin|root|sudo|superuser)[_-]?(?:mode|access|override)/i,
    reason: 'Privilege escalation parameter',
  },
  {
    pattern: /(?:callback|redirect|return)[_-]?url/i,
    reason: 'Open redirect / SSRF vector',
  },
  {
    pattern: /(?:webhook|notify)[_-]?url/i,
    reason: 'Server-side request to attacker-controlled URL',
  },
  {
    pattern: /(?:exec|eval|command|cmd|shell|script)/i,
    reason: 'Potential command injection parameter',
  },
  {
    pattern: /(?:sql|query|filter|where|order[_-]?by)/i,
    reason: 'Potential SQL injection / query manipulation parameter',
  },
  {
    pattern: /(?:file|path|dir|filename|template)/i,
    reason: 'Potential path traversal / file inclusion parameter',
  },
  {
    pattern: /(?:token|secret|key|password|credential)/i,
    reason: 'Sensitive credential parameter in request body',
  },
  {
    pattern: /(?:role|permission|scope|privilege)/i,
    reason: 'Authorization control parameter — potential privilege escalation',
  },
  {
    pattern: /(?:debug|verbose|trace|internal)/i,
    reason: 'Debug/internal parameter that may leak information',
  },
];

// ─── Scanner ──────────────────────────────────────────────────

/**
 * Scan a base URL for exposed API documentation.
 *
 * Probes common documentation paths, parses any discovered OpenAPI specs,
 * and analyzes them for security gaps.
 */
export async function scanOpenApi(
  config: OpenApiScanConfig,
): Promise<OpenApiScanResult> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const logger = config.logger;

  logger?.info('openapi-scanner: starting scan', { baseUrl });

  const exposedUrls: ExposedDocUrl[] = [];
  let rawSpec: Record<string, unknown> | null = null;

  // Probe all documentation paths
  for (const path of DOC_PATHS) {
    const url = baseUrl + path;
    const result = await probeDocUrl(url, timeout);

    if (result.status >= 200 && result.status < 400) {
      exposedUrls.push(result);

      logger?.info('openapi-scanner: documentation endpoint found', {
        url,
        status: result.status,
        isSpec: result.isSpec,
      });

      // Try to parse as OpenAPI spec
      if (result.isSpec && !rawSpec) {
        const specResult = await fetchAndParseSpec(url, timeout);
        if (specResult) {
          rawSpec = specResult;
          logger?.info('openapi-scanner: OpenAPI spec parsed successfully', {
            url,
          });
        }
      }
    }

    await sleep(PROBE_DELAY_MS);
  }

  if (exposedUrls.length === 0) {
    logger?.info('openapi-scanner: no documentation endpoints found');
    return {
      found: false,
      exposedUrls: [],
      endpoints: [],
      unauthenticatedEndpoints: [],
      dangerousParams: [],
    };
  }

  // Parse spec if found
  let spec: ParsedOpenApiSpec | undefined;
  let endpoints: OpenApiEndpoint[] = [];
  let unauthenticatedEndpoints: OpenApiEndpoint[] = [];
  let dangerousParams: DangerousParam[] = [];

  if (rawSpec) {
    spec = parseSpecMetadata(rawSpec);
    endpoints = extractEndpoints(rawSpec, spec);
    unauthenticatedEndpoints = endpoints.filter((ep) => ep.security.length === 0);
    dangerousParams = detectDangerousParams(endpoints, rawSpec);

    logger?.info('openapi-scanner: analysis complete', {
      totalEndpoints: endpoints.length,
      unauthenticated: unauthenticatedEndpoints.length,
      dangerousParams: dangerousParams.length,
    });
  }

  return {
    found: true,
    exposedUrls,
    spec,
    endpoints,
    unauthenticatedEndpoints,
    dangerousParams,
  };
}

// ─── URL Probe ────────────────────────────────────────────────

/**
 * Probe a single URL to check if it serves API documentation.
 */
async function probeDocUrl(
  url: string,
  timeout: number,
): Promise<ExposedDocUrl> {
  const start = performance.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'WIGTN-SPEAR/0.1.0 (Security Scanner)',
        Accept: 'application/json, text/html, */*',
      },
      signal: controller.signal,
      redirect: 'manual',
    });

    clearTimeout(timer);
    const latencyMs = Math.round(performance.now() - start);
    const contentType = response.headers.get('content-type') ?? undefined;

    // Check if this is likely a spec file (JSON/YAML)
    const isSpec =
      url.endsWith('.json') ||
      url.endsWith('.yaml') ||
      (contentType?.includes('application/json') ?? false);

    // Read body to avoid connection leaks
    try { await response.text(); } catch { /* ignore */ }

    return {
      url,
      status: response.status,
      contentType,
      isSpec,
      latencyMs,
    };
  } catch {
    return {
      url,
      status: 0,
      isSpec: false,
      latencyMs: Math.round(performance.now() - start),
    };
  }
}

// ─── Spec Parser ──────────────────────────────────────────────

/**
 * Fetch and parse an OpenAPI spec from a URL.
 */
async function fetchAndParseSpec(
  url: string,
  timeout: number,
): Promise<Record<string, unknown> | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'WIGTN-SPEAR/0.1.0 (Security Scanner)',
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (response.status !== 200) return null;

    const text = await response.text();
    if (text.length > 5_000_000) return null; // Skip specs > 5MB

    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Parse OpenAPI spec metadata (info, servers, securitySchemes).
 */
function parseSpecMetadata(spec: Record<string, unknown>): ParsedOpenApiSpec {
  const info = spec.info as Record<string, unknown> | undefined;
  const servers = (spec.servers as Array<{ url: string }>) ?? [];
  const components = spec.components as Record<string, unknown> | undefined;
  const securitySchemesRaw =
    (components?.securitySchemes as Record<string, Record<string, unknown>>) ?? {};
  const globalSecurity = (spec.security as Array<Record<string, unknown>>) ?? [];

  const securitySchemes: Record<string, SecurityScheme> = {};
  for (const [name, scheme] of Object.entries(securitySchemesRaw)) {
    securitySchemes[name] = {
      type: String(scheme.type ?? ''),
      scheme: scheme.scheme as string | undefined,
      bearerFormat: scheme.bearerFormat as string | undefined,
      name: scheme.name as string | undefined,
      in: scheme.in as string | undefined,
    };
  }

  return {
    title: info?.title as string | undefined,
    version: info?.version as string | undefined,
    description: info?.description as string | undefined,
    servers: servers.map((s) => s.url),
    securitySchemes,
    globalSecurity: globalSecurity.flatMap((s) => Object.keys(s)),
  };
}

/**
 * Extract all endpoints from an OpenAPI spec.
 */
function extractEndpoints(
  spec: Record<string, unknown>,
  metadata: ParsedOpenApiSpec,
): OpenApiEndpoint[] {
  const paths = spec.paths as Record<string, Record<string, unknown>> | undefined;
  if (!paths) return [];

  const endpoints: OpenApiEndpoint[] = [];

  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (method.startsWith('x-') || method === 'parameters') continue;

      const op = operation as Record<string, unknown>;

      // Determine security for this endpoint
      const endpointSecurity = op.security as Array<Record<string, unknown>> | undefined;
      let security: string[];

      if (endpointSecurity !== undefined) {
        // Endpoint has explicit security (could be empty array = no auth)
        security = endpointSecurity.flatMap((s) => Object.keys(s));
      } else {
        // Inherit global security
        security = metadata.globalSecurity;
      }

      // Extract parameters
      const params = (op.parameters as Array<Record<string, unknown>>) ?? [];
      const parameters: ParamInfo[] = params.map((p) => ({
        name: String(p.name ?? ''),
        in: String(p.in ?? ''),
        required: Boolean(p.required),
        type: (p.schema as Record<string, unknown>)?.type as string | undefined,
      }));

      // Extract request body properties
      let requestBody: RequestBodyInfo | undefined;
      const bodyDef = op.requestBody as Record<string, unknown> | undefined;
      if (bodyDef) {
        const content = bodyDef.content as Record<string, Record<string, unknown>> | undefined;
        const jsonSchema = content?.['application/json']?.schema as Record<string, unknown> | undefined;
        const properties = extractSchemaProperties(jsonSchema, spec);

        requestBody = {
          required: Boolean(bodyDef.required),
          properties,
        };
      }

      endpoints.push({
        method: method.toUpperCase(),
        path,
        operationId: op.operationId as string | undefined,
        summary: op.summary as string | undefined,
        security,
        parameters,
        requestBody,
      });
    }
  }

  return endpoints;
}

/**
 * Extract properties from a JSON Schema, resolving $ref references.
 */
function extractSchemaProperties(
  schema: Record<string, unknown> | undefined,
  rootSpec: Record<string, unknown>,
): Record<string, PropertyInfo> {
  if (!schema) return {};

  // Resolve $ref
  const resolved = resolveRef(schema, rootSpec);
  if (!resolved) return {};

  const properties = resolved.properties as Record<string, Record<string, unknown>> | undefined;
  if (!properties) return {};

  const result: Record<string, PropertyInfo> = {};
  for (const [name, prop] of Object.entries(properties)) {
    const resolvedProp = resolveRef(prop, rootSpec) ?? prop;
    result[name] = {
      type: resolvedProp.type as string | undefined,
      nullable: Boolean(resolvedProp.nullable),
      description: resolvedProp.description as string | undefined,
    };
  }

  return result;
}

/**
 * Resolve a $ref reference in an OpenAPI spec.
 */
function resolveRef(
  obj: Record<string, unknown>,
  rootSpec: Record<string, unknown>,
): Record<string, unknown> | null {
  const ref = obj.$ref as string | undefined;
  if (!ref) return obj;

  // Parse #/components/schemas/ModelName
  const parts = ref.replace('#/', '').split('/');
  let current: unknown = rootSpec;

  for (const part of parts) {
    if (current && typeof current === 'object') {
      current = (current as Record<string, unknown>)[part];
    } else {
      return null;
    }
  }

  return (current as Record<string, unknown>) ?? null;
}

// ─── Dangerous Parameter Detection ────────────────────────────

/**
 * Detect dangerous parameters across all endpoints.
 */
function detectDangerousParams(
  endpoints: OpenApiEndpoint[],
  _spec: Record<string, unknown>,
): DangerousParam[] {
  const results: DangerousParam[] = [];

  for (const ep of endpoints) {
    // Check query/path parameters
    for (const param of ep.parameters) {
      const danger = matchDangerousPattern(param.name);
      if (danger) {
        results.push({
          endpoint: ep.path,
          method: ep.method,
          paramName: param.name,
          location: param.in,
          reason: danger,
        });
      }
    }

    // Check request body properties
    if (ep.requestBody) {
      for (const [propName, _propInfo] of Object.entries(ep.requestBody.properties)) {
        const danger = matchDangerousPattern(propName);
        if (danger) {
          results.push({
            endpoint: ep.path,
            method: ep.method,
            paramName: propName,
            location: 'body',
            reason: danger,
          });
        }
      }
    }
  }

  return results;
}

/**
 * Match a parameter name against dangerous patterns.
 */
function matchDangerousPattern(name: string): string | null {
  for (const { pattern, reason } of DANGEROUS_PARAM_PATTERNS) {
    if (pattern.test(name)) {
      return reason;
    }
  }
  return null;
}

// ─── Utilities ────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
