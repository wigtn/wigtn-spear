/**
 * SPEAR-22: API Endpoint Extractor
 *
 * Extracts API endpoint intelligence from source code:
 *   - Next.js API routes (app/api/ ** /route.ts)
 *   - Express/Fastify route definitions (router.get, app.post, etc.)
 *   - Fetch/axios HTTP calls (external API dependencies)
 *   - WebSocket endpoints (ws://, wss://)
 *   - GraphQL endpoints
 *
 * All findings are severity 'info' -- this is an intelligence module.
 */

import type { Finding } from '@wigtn/shared';

// ─── Helper ─────────────────────────────────────────────────────

function findLineNumber(content: string, matchIndex: number): number {
  if (matchIndex < 0 || matchIndex >= content.length) return 1;
  let line = 1;
  for (let i = 0; i < matchIndex && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

function makeFinding(
  ruleIdSuffix: string,
  message: string,
  file: string,
  line: number,
  pluginId: string,
  type: string,
  value: string,
  extra?: Record<string, unknown>,
): Finding {
  return {
    ruleId: `spear-22/${ruleIdSuffix}`,
    severity: 'info',
    message,
    file,
    line,
    metadata: {
      plugin: pluginId,
      category: 'api_endpoints',
      type,
      value,
      ...extra,
    },
  };
}

// ─── Next.js API Route Detection ────────────────────────────────

/**
 * Detect Next.js API routes based on file path convention.
 *
 * Next.js App Router: app/api/ ** /route.ts(x)
 * Next.js Pages Router: pages/api/ ** /*.ts(x)
 */
function* extractNextjsRoutes(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const normalized = filePath.replace(/\\/g, '/');

  // App Router: app/api/**/route.ts(x)
  const appRouterMatch = normalized.match(/app\/api\/(.+?)\/route\.(?:ts|tsx|js|jsx)$/);
  if (appRouterMatch) {
    const routePath = `/api/${appRouterMatch[1]!}`;

    // Detect which HTTP methods are exported
    const methods: string[] = [];
    const methodPattern = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)/g;
    let methodMatch: RegExpExecArray | null;
    while ((methodMatch = methodPattern.exec(content)) !== null) {
      methods.push(methodMatch[1]!);
    }

    // Also detect named exports like: export { GET, POST }
    const namedExportPattern = /export\s*\{[^}]*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[^}]*\}/g;
    while ((methodMatch = namedExportPattern.exec(content)) !== null) {
      const fullMatch = methodMatch[0]!;
      for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
        if (fullMatch.includes(m) && !methods.includes(m)) {
          methods.push(m);
        }
      }
    }

    const methodStr = methods.length > 0 ? methods.join(', ') : 'UNKNOWN';
    yield makeFinding(
      'nextjs-api-route',
      `Next.js API Route: [${methodStr}] ${routePath}`,
      filePath,
      1,
      pluginId,
      'nextjs_api_route',
      routePath,
      { methods },
    );
  }

  // Pages Router: pages/api/**/*.ts(x)
  const pagesRouterMatch = normalized.match(/pages\/api\/(.+?)\.(?:ts|tsx|js|jsx)$/);
  if (pagesRouterMatch) {
    const routePath = `/api/${pagesRouterMatch[1]!}`;
    yield makeFinding(
      'nextjs-pages-api-route',
      `Next.js Pages API Route: ${routePath}`,
      filePath,
      1,
      pluginId,
      'nextjs_pages_api_route',
      routePath,
    );
  }
}

// ─── Express/Fastify Route Detection ────────────────────────────

/** Match router.get('/path', ...) or app.post('/path', ...) etc. */
const EXPRESS_ROUTE_PATTERNS: RegExp[] = [
  // app.get('/path', handler) or router.get('/path', handler)
  /(?:app|router|server|route)\.(get|post|put|patch|delete|head|options|all|use)\(\s*["'`](\/[^"'`]*)["'`]/gi,
  // fastify.get('/path', ...) or fastify.route({ method: 'GET', url: '/path' })
  /fastify\.(get|post|put|patch|delete|head|options|all)\(\s*["'`](\/[^"'`]*)["'`]/gi,
  // Express Router() with prefix: Router({ prefix: '/api' })
  /Router\(\s*\{[^}]*prefix:\s*["'`](\/[^"'`]*)["'`]/gi,
];

/** Fastify route config pattern */
const FASTIFY_ROUTE_CONFIG = /fastify\.route\(\s*\{[^}]*method:\s*["'`](\w+)["'`][^}]*url:\s*["'`](\/[^"'`]*)["'`]/gi;

function* extractExpressFastifyRoutes(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const pattern of EXPRESS_ROUTE_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const method = match[1]!.toUpperCase();
      const path = match[2]!;
      const key = `${method}:${path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'express-route',
        `Express/Fastify Route: [${method}] ${path}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'express_route',
        path,
        { method },
      );
    }
  }

  // Fastify route config objects
  FASTIFY_ROUTE_CONFIG.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = FASTIFY_ROUTE_CONFIG.exec(content)) !== null) {
    const method = match[1]!.toUpperCase();
    const path = match[2]!;
    const key = `${method}:${path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'fastify-route-config',
      `Fastify Route Config: [${method}] ${path}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'fastify_route',
      path,
      { method },
    );
  }
}

// ─── External API Calls (fetch/axios) ───────────────────────────

/** Match fetch('https://...') or axios.get('https://...') etc. */
const FETCH_PATTERNS: RegExp[] = [
  // fetch('https://api.example.com/...')
  /fetch\(\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g,
  // axios.get('https://...') / axios.post('https://...')
  /axios(?:\.\w+)?\(\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g,
  // axios({ url: 'https://...' })
  /axios\(\s*\{[^}]*url:\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g,
  // new URL('https://...')
  /new\s+URL\(\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g,
  // $fetch('https://...') (Nuxt)
  /\$fetch\(\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g,
  // got('https://...')
  /got(?:\.\w+)?\(\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g,
];

/** Match base URL constants: const API_URL = 'https://...' */
const BASE_URL_PATTERNS: RegExp[] = [
  /(?:BASE_URL|API_URL|ENDPOINT|BASE_API|SERVER_URL|BACKEND_URL)\s*[:=]\s*["'`](https?:\/\/[^"'`\s]+)["'`]/gi,
  /baseURL:\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g,
];

function* extractExternalApis(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const pattern of FETCH_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const url = match[1]!;
      // Skip localhost, 127.0.0.1 and template literals with variables
      if (url.includes('localhost') || url.includes('127.0.0.1') || url.includes('${')) continue;
      const key = `fetch:${url}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Extract the hostname
      let hostname = '';
      try {
        hostname = new URL(url).hostname;
      } catch {
        hostname = url;
      }

      yield makeFinding(
        'external-api-call',
        `External API Call: ${url}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'external_api_call',
        url,
        { hostname },
      );
    }
  }

  for (const pattern of BASE_URL_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const url = match[1]!;
      if (url.includes('localhost') || url.includes('127.0.0.1') || url.includes('${')) continue;
      const key = `base:${url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'api-base-url',
        `API Base URL: ${url}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'api_base_url',
        url,
      );
    }
  }
}

// ─── WebSocket Endpoints ────────────────────────────────────────

/** Match WebSocket URLs and constructors */
const WEBSOCKET_PATTERNS: RegExp[] = [
  // new WebSocket('wss://...')
  /new\s+WebSocket\(\s*["'`](wss?:\/\/[^"'`\s]+)["'`]/g,
  // io('wss://...') or io.connect('wss://...')
  /io(?:\.connect)?\(\s*["'`](wss?:\/\/[^"'`\s]+)["'`]/g,
  // WS_URL = 'wss://...'
  /(?:WS_URL|WEBSOCKET_URL|SOCKET_URL)\s*[:=]\s*["'`](wss?:\/\/[^"'`\s]+)["'`]/gi,
  // Generic wss:// URLs
  /["'`](wss?:\/\/[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?::\d+)?(?:\/[^"'`\s]*)?)["'`]/g,
];

function* extractWebsockets(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const pattern of WEBSOCKET_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const url = match[1]!;
      if (url.includes('localhost') || url.includes('127.0.0.1') || url.includes('${')) continue;
      const key = `ws:${url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'websocket-endpoint',
        `WebSocket Endpoint: ${url}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'websocket_endpoint',
        url,
      );
    }
  }
}

// ─── GraphQL Endpoints ──────────────────────────────────────────

/** Match GraphQL endpoint configurations and operations */
const GRAPHQL_PATTERNS: RegExp[] = [
  // GraphQL endpoint URL: graphqlEndpoint, GRAPHQL_URL, etc.
  /(?:graphql_?(?:endpoint|url|uri)|GRAPHQL_(?:ENDPOINT|URL|URI))\s*[:=]\s*["'`](\/[^"'`\s]+|https?:\/\/[^"'`\s]+)["'`]/gi,
  // Apollo Client: uri: '/graphql'
  /uri:\s*["'`](\/graphql[^"'`\s]*)["'`]/g,
  // new ApolloClient({ uri: '...' })
  /ApolloClient\(\s*\{[^}]*uri:\s*["'`]([^"'`\s]+)["'`]/g,
  // graphql(schema, query) -- schema definition
  /createSchema|buildSchema|makeExecutableSchema|typeDefs/g,
  // GraphQL queries/mutations
  /gql\s*`[\s\S]*?(?:query|mutation|subscription)\s+(\w+)/g,
];

function* extractGraphql(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  // GraphQL endpoint URLs
  for (let i = 0; i < 3; i++) {
    const pattern = GRAPHQL_PATTERNS[i]!;
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `gql-endpoint:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'graphql-endpoint',
        `GraphQL Endpoint: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'graphql_endpoint',
        value,
      );
    }
  }

  // Check if file defines a GraphQL schema
  const schemaPattern = GRAPHQL_PATTERNS[3]!;
  schemaPattern.lastIndex = 0;
  if (schemaPattern.test(content)) {
    const key = `gql-schema:${filePath}`;
    if (!seen.has(key)) {
      seen.add(key);
      yield makeFinding(
        'graphql-schema-definition',
        `GraphQL Schema Definition found`,
        filePath,
        1,
        pluginId,
        'graphql_schema',
        filePath,
      );
    }
  }

  // GraphQL operations (query/mutation/subscription names)
  const operationPattern = GRAPHQL_PATTERNS[4]!;
  operationPattern.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = operationPattern.exec(content)) !== null) {
    const name = match[1]!;
    const key = `gql-op:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'graphql-operation',
      `GraphQL Operation: ${name}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'graphql_operation',
      name,
    );
  }
}

// ─── Main Export ─────────────────────────────────────────────────

/**
 * Extract API endpoint intelligence from a source code file.
 *
 * Dispatches to endpoint-specific extractors based on file content and path.
 * Yields Finding objects with severity 'info' for each discovered endpoint.
 */
export function* extractEndpoints(
  content: string,
  relativePath: string,
  pluginId: string,
): Generator<Finding> {
  // Next.js API routes (detected by file path convention)
  yield* extractNextjsRoutes(content, relativePath, pluginId);

  // Express/Fastify route definitions
  yield* extractExpressFastifyRoutes(content, relativePath, pluginId);

  // External API calls (fetch, axios, got, etc.)
  yield* extractExternalApis(content, relativePath, pluginId);

  // WebSocket endpoints
  yield* extractWebsockets(content, relativePath, pluginId);

  // GraphQL endpoints
  yield* extractGraphql(content, relativePath, pluginId);
}
