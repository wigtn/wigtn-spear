/**
 * SPEAR-25: Endpoint Discovery Module
 *
 * Discovers API endpoints from source code by scanning for framework-specific
 * route definitions and auth middleware/decorator patterns.
 *
 * Supported frameworks:
 *   - Next.js App Router (app/api/.../route.ts)
 *   - Express / Fastify (router.get/post/... or app.get/post/...)
 *   - FastAPI / Python (decorator-based router.get/post/...)
 *
 * Auth detection:
 *   - Express: middleware like auth, authenticate, requireAuth, passport.authenticate
 *   - FastAPI: Depends(verify_auth), Depends(get_current_user), Security(...)
 *   - Next.js: getServerSession, auth(), withAuth
 *   - Generic: Authorization header check, JWT verification, cookie validation
 */

import { readFile, readdir, lstat } from 'node:fs/promises';
import { join, relative, resolve, extname } from 'node:path';

// ─── Types ────────────────────────────────────────────────────

export interface DiscoveredEndpoint {
  /** HTTP method: GET, POST, PUT, DELETE, PATCH, WS */
  method: string;
  /** API path: /api/users, /relay/calls/start */
  path: string;
  /** Source file where the endpoint was found */
  file: string;
  /** Line number in source file */
  line: number;
  /** Framework that defines this endpoint */
  framework: string;
  /** Whether auth middleware/decorator was detected */
  hasAuth: boolean;
  /** Auth type if detected: 'jwt', 'api_key', 'cookie', 'none' */
  authType?: string;
}

// ─── Constants ────────────────────────────────────────────────

/** File extensions to scan for endpoint definitions. */
const TARGET_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py',
]);

/** Directories to always skip during directory traversal. */
const SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.output',
  '__pycache__',
  '.venv',
  'venv',
  'vendor',
  'target',
  '.turbo',
  'coverage',
  '.nyc_output',
  '.tox',
  'egg-info',
]);

/** Maximum file size to process (2 MB). */
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

// ─── Auth Detection Patterns ──────────────────────────────────

/** Express/Node.js auth middleware patterns */
const EXPRESS_AUTH_PATTERNS: readonly RegExp[] = [
  /\bauth\b/i,
  /\bauthenticate\b/i,
  /\brequireAuth\b/i,
  /\bisAuthenticated\b/i,
  /\bpassport\.authenticate\b/,
  /\bverifyToken\b/i,
  /\bverifyJwt\b/i,
  /\bjwtMiddleware\b/i,
  /\brequireLogin\b/i,
  /\bensureAuthenticated\b/i,
  /\bcheckAuth\b/i,
  /\bauthMiddleware\b/i,
  /\bprotect\b/i,
  /\brequireRole\b/i,
  /\bauthorize\b/i,
];

/** FastAPI auth patterns */
const FASTAPI_AUTH_PATTERNS: readonly RegExp[] = [
  /Depends\s*\(\s*(?:verify_auth|get_current_user|require_auth|authenticate|check_auth|verify_token|get_user)/,
  /Security\s*\(/,
  /HTTPBearer\s*\(/,
  /OAuth2PasswordBearer\s*\(/,
  /APIKeyHeader\s*\(/,
  /Depends\s*\(\s*auth/i,
];

/** Next.js auth patterns */
const NEXTJS_AUTH_PATTERNS: readonly RegExp[] = [
  /\bgetServerSession\b/,
  /\bauth\s*\(\s*\)/,
  /\bwithAuth\b/,
  /\bgetSession\b/,
  /\buseSession\b/,
  /\bgetToken\b/,
  /\bnextAuth\b/i,
  /\bclerk\b/i,
  /\bcurrentUser\b/,
  /\bsession\s*=\s*await/,
];

/** Generic auth patterns (language-agnostic) */
const GENERIC_AUTH_PATTERNS: readonly RegExp[] = [
  /['"]Authorization['"]/i,
  /\.headers\s*\[\s*['"]authorization['"]\s*\]/i,
  /jwt\.verify\b/,
  /jwt\.decode\b/,
  /jsonwebtoken/,
  /\.cookies\b.*(?:session|token|auth)/i,
  /Bearer\s/,
  /api[_-]?key/i,
  /x-api-key/i,
];

// ─── Route Extraction Patterns ────────────────────────────────

/** Express/Fastify route patterns: router.get('/path', ...) or app.post('/path', ...) */
const EXPRESS_ROUTE_PATTERN =
  /(?:router|app|server|fastify)\s*\.\s*(get|post|put|delete|patch|options|head|all|ws)\s*\(\s*['"`]([^'"`]+)['"`]/gi;

/** FastAPI route decorator patterns: @router.get("/path") or @app.post("/path") */
const FASTAPI_ROUTE_PATTERN =
  /^\s*@(?:router|app)\s*\.\s*(get|post|put|delete|patch|options|head|websocket)\s*\(\s*['"]([^'"]+)['"]/gim;

/** Next.js App Router: export async function GET/POST/PUT/DELETE/PATCH */
const NEXTJS_HANDLER_PATTERN =
  /export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(/gi;

// ─── Main Discovery Function ─────────────────────────────────

/**
 * Discover API endpoints from source code in the given directory.
 *
 * Walks the directory tree, scans each relevant source file for
 * framework-specific route definitions, and returns discovered endpoints
 * with auth detection results.
 */
export async function discoverEndpoints(
  rootDir: string,
  exclude?: string[],
): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];
  const resolvedRoot = resolve(rootDir);

  for await (const { absolutePath, relativePath } of walkSourceFiles(resolvedRoot, exclude)) {
    try {
      const content = await readFileContent(absolutePath);
      if (content === null) continue;

      if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) continue;

      // Try each framework scanner
      const discovered = [
        ...discoverNextJsEndpoints(content, relativePath, resolvedRoot),
        ...discoverExpressEndpoints(content, relativePath),
        ...discoverFastAPIEndpoints(content, relativePath),
      ];

      endpoints.push(...discovered);
    } catch {
      // Non-fatal: skip file
    }
  }

  return endpoints;
}

// ─── Framework-Specific Scanners ──────────────────────────────

/**
 * Discover Next.js App Router endpoints.
 *
 * Next.js App Router uses directory-based routing:
 *   app/api/users/route.ts -> /api/users
 *
 * Route handlers are exported functions named GET, POST, PUT, DELETE, PATCH.
 */
function discoverNextJsEndpoints(
  content: string,
  relativePath: string,
  rootDir: string,
): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];

  // Only process route.ts/route.js files inside an app/ or src/app/ directory
  const normalizedPath = relativePath.replace(/\\/g, '/');
  const isRouteFile = /(?:^|\/)app\/.*\/route\.[jt]sx?$/.test(normalizedPath);
  if (!isRouteFile) return endpoints;

  // Extract the API path from the file path
  // e.g., app/api/users/route.ts -> /api/users
  // e.g., src/app/api/relay/calls/start/route.ts -> /api/relay/calls/start
  const appMatch = normalizedPath.match(/app\/(.+)\/route\.[jt]sx?$/);
  if (!appMatch) return endpoints;

  const routePath = '/' + appMatch[1]!;

  const lines = content.split('\n');
  const hasFileAuth = detectAuthInContent(content, 'nextjs');

  // Reset regex lastIndex for each file
  NEXTJS_HANDLER_PATTERN.lastIndex = 0;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!;
    NEXTJS_HANDLER_PATTERN.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = NEXTJS_HANDLER_PATTERN.exec(line)) !== null) {
      const method = match[1]!.toUpperCase();

      endpoints.push({
        method,
        path: routePath,
        file: relativePath,
        line: lineIndex + 1,
        framework: 'nextjs',
        hasAuth: hasFileAuth.detected,
        authType: hasFileAuth.type,
      });
    }
  }

  return endpoints;
}

/**
 * Discover Express/Fastify endpoints.
 *
 * Matches patterns like:
 *   router.get('/api/users', authMiddleware, handler)
 *   app.post('/api/orders', handler)
 */
function discoverExpressEndpoints(
  content: string,
  relativePath: string,
): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  const lines = content.split('\n');

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!;
    EXPRESS_ROUTE_PATTERN.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = EXPRESS_ROUTE_PATTERN.exec(line)) !== null) {
      const method = match[1]!.toUpperCase();
      const path = match[2]!;

      // Check if auth middleware is present on the same line (inline middleware)
      const lineHasAuth = detectAuthInLine(line, 'express');

      // Also check the broader file context for auth applied at router level
      const fileAuth = detectAuthInContent(content, 'express');

      const hasAuth = lineHasAuth.detected || fileAuth.detected;
      const authType = lineHasAuth.type ?? fileAuth.type;

      endpoints.push({
        method: method === 'ALL' ? 'ALL' : method,
        path,
        file: relativePath,
        line: lineIndex + 1,
        framework: 'express',
        hasAuth,
        authType,
      });
    }
  }

  return endpoints;
}

/**
 * Discover FastAPI endpoints.
 *
 * Matches decorator patterns like:
 *   @router.get("/api/users")
 *   @app.post("/relay/calls/start")
 *   @router.websocket("/ws")
 */
function discoverFastAPIEndpoints(
  content: string,
  relativePath: string,
): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  const lines = content.split('\n');

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!;
    FASTAPI_ROUTE_PATTERN.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = FASTAPI_ROUTE_PATTERN.exec(line)) !== null) {
      const rawMethod = match[1]!;
      const method = rawMethod.toUpperCase() === 'WEBSOCKET' ? 'WS' : rawMethod.toUpperCase();
      const path = match[2]!;

      // Look at the function signature (next few lines) for Depends(auth)
      const contextLines = lines.slice(lineIndex, Math.min(lineIndex + 10, lines.length)).join('\n');
      const lineAuth = detectAuthInContent(contextLines, 'fastapi');

      // Also check the broader file for router-level auth
      const fileAuth = detectAuthInContent(content, 'fastapi');

      const hasAuth = lineAuth.detected || fileAuth.detected;
      const authType = lineAuth.type ?? fileAuth.type;

      endpoints.push({
        method,
        path,
        file: relativePath,
        line: lineIndex + 1,
        framework: 'fastapi',
        hasAuth,
        authType,
      });
    }
  }

  return endpoints;
}

// ─── Auth Detection Helpers ───────────────────────────────────

interface AuthDetectionResult {
  detected: boolean;
  type?: string;
}

/**
 * Detect authentication patterns in file content.
 */
function detectAuthInContent(
  content: string,
  framework: 'express' | 'fastapi' | 'nextjs',
): AuthDetectionResult {
  const patterns = getAuthPatterns(framework);

  for (const pattern of patterns) {
    if (pattern.test(content)) {
      return { detected: true, type: classifyAuthType(content) };
    }
  }

  // Also check generic patterns
  for (const pattern of GENERIC_AUTH_PATTERNS) {
    if (pattern.test(content)) {
      return { detected: true, type: classifyAuthType(content) };
    }
  }

  return { detected: false, type: 'none' };
}

/**
 * Detect authentication patterns in a single line (for inline middleware).
 */
function detectAuthInLine(
  line: string,
  framework: 'express' | 'fastapi' | 'nextjs',
): AuthDetectionResult {
  const patterns = getAuthPatterns(framework);

  for (const pattern of patterns) {
    if (pattern.test(line)) {
      return { detected: true, type: classifyAuthType(line) };
    }
  }

  return { detected: false };
}

/**
 * Get framework-specific auth patterns.
 */
function getAuthPatterns(
  framework: 'express' | 'fastapi' | 'nextjs',
): readonly RegExp[] {
  switch (framework) {
    case 'express':
      return EXPRESS_AUTH_PATTERNS;
    case 'fastapi':
      return FASTAPI_AUTH_PATTERNS;
    case 'nextjs':
      return NEXTJS_AUTH_PATTERNS;
  }
}

/**
 * Classify the auth type from content patterns.
 */
function classifyAuthType(content: string): string {
  if (/jwt|jsonwebtoken|jose/i.test(content)) return 'jwt';
  if (/api[_-]?key|x-api-key/i.test(content)) return 'api_key';
  if (/cookie|session/i.test(content)) return 'cookie';
  if (/OAuth2|oauth/i.test(content)) return 'oauth';
  if (/Bearer/i.test(content)) return 'jwt';
  return 'unknown';
}

// ─── Directory Walker ─────────────────────────────────────────

interface SourceFileEntry {
  absolutePath: string;
  relativePath: string;
}

/**
 * Walk the directory tree and yield source code files.
 *
 * Uses an explicit stack (iterative DFS) to avoid stack overflow.
 * Does NOT follow symlinks to prevent traversal attacks.
 */
async function* walkSourceFiles(
  rootDir: string,
  exclude?: string[],
): AsyncGenerator<SourceFileEntry> {
  const stack: string[] = [rootDir];

  while (stack.length > 0) {
    const currentDir = stack.pop()!;

    let entries: string[];
    try {
      entries = await readdir(currentDir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const relativePath = relative(rootDir, fullPath);

      // Check exclude patterns
      if (exclude && exclude.length > 0) {
        const matchesExclude = exclude.some(
          (pattern) => relativePath.includes(pattern) || entry === pattern,
        );
        if (matchesExclude) continue;
      }

      let entryStat;
      try {
        entryStat = await lstat(fullPath);
      } catch {
        continue;
      }

      // Do not follow symlinks
      if (entryStat.isSymbolicLink()) continue;

      if (entryStat.isDirectory()) {
        if (SKIP_DIRS.has(entry)) continue;
        stack.push(fullPath);
      } else if (entryStat.isFile()) {
        const ext = extname(entry).toLowerCase();
        if (TARGET_EXTENSIONS.has(ext)) {
          yield { absolutePath: fullPath, relativePath };
        }
      }
    }
  }
}

// ─── Utilities ────────────────────────────────────────────────

/**
 * Read file content as UTF-8 string.
 * Returns null on any error (permissions, encoding, etc.).
 */
async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf-8');
  } catch {
    return null;
  }
}
